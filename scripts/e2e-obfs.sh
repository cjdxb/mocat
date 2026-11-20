#!/bin/bash
# 伪装端到端测试（需要 root、nft、socat、tcpdump、python3、curl，以及 fakehttp/fakesip 与 mocat-node 同目录）。
# 拓扑：client ns —(10.200.1.0/24)— 节点(本机) —(10.200.2.0/24)— router ns —(10.200.3.0/24)— target ns
# 伪装报文 TTL=1：在 router 处过期，不会到达目标；在节点出口 mc_vt 上抓包检查顺序。
# 用法: sudo scripts/e2e-obfs.sh <mocat-controller> <mocat-node>
set -uo pipefail
CTRL_BIN="${1:?controller}"; NODE_BIN="${2:?node}"
HERE="$(cd "$(dirname "$0")" && pwd)"
W=/var/tmp/mocat-e2e-obfs
PASS=0; FAIL=0
ok()   { echo "  [通过] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [失败] $*"; FAIL=$((FAIL+1)); }
step() { echo; echo "== $*"; }
TGT=10.200.3.2

cleanup() {
  if [ -n "${NODE_PID:-}" ]; then kill "$NODE_PID" 2>/dev/null; wait "$NODE_PID" 2>/dev/null; fi
  [ -n "${CTRL_PID:-}" ] && kill "$CTRL_PID" 2>/dev/null
  pkill -f "$W/" 2>/dev/null
  for ns in mc_client mc_router mc_target; do ip netns pids $ns 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $ns 2>/dev/null; done
  ip link del mc_vc 2>/dev/null; ip link del mc_vt 2>/dev/null
  nft delete table inet mocat 2>/dev/null
}
trap cleanup EXIT
cleanup; rm -rf "$W"; mkdir -p "$W"

step "准备网络（client → 节点 → router → target）"
ip netns add mc_client; ip netns add mc_router; ip netns add mc_target
ip link add mc_vc type veth peer name eth0 netns mc_client
ip link add mc_vt type veth peer name eth0 netns mc_router
ip -n mc_router link add eth1 type veth peer name eth0 netns mc_target
ip addr add 10.200.1.1/24 dev mc_vc; ip link set mc_vc up
ip addr add 10.200.2.1/24 dev mc_vt; ip link set mc_vt up
ip route add 10.200.3.0/24 via 10.200.2.2
sysctl -qw net.ipv4.ip_forward=1
ip -n mc_client addr add 10.200.1.2/24 dev eth0; ip -n mc_client link set eth0 up; ip -n mc_client link set lo up
ip -n mc_client route add default via 10.200.1.1
ip -n mc_router addr add 10.200.2.2/24 dev eth0; ip -n mc_router link set eth0 up
ip -n mc_router addr add 10.200.3.1/24 dev eth1; ip -n mc_router link set eth1 up
ip -n mc_router route add 10.200.1.0/24 via 10.200.2.1
ip netns exec mc_router sysctl -qw net.ipv4.ip_forward=1
ip -n mc_target addr add $TGT/24 dev eth0; ip -n mc_target link set eth0 up; ip -n mc_target link set lo up
ip -n mc_target route add default via 10.200.3.1
mkdir -p "$W/www"; echo hello-mocat > "$W/www/index.html"
ip netns exec mc_target python3 -m http.server 8000 --bind $TGT --directory "$W/www" > "$W/http.log" 2>&1 &
cat > "$W/udpecho.py" <<EOF
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("$TGT", 5353))
log = open("$W/udp.log", "a")
while True:
    d, a = s.recvfrom(4096); log.write(repr(d) + "\n"); log.flush(); s.sendto(b"echo:" + d, a)
EOF
ip netns exec mc_target python3 "$W/udpecho.py" &
sleep 1
ip netns exec mc_client curl -s --max-time 3 http://$TGT:8000/index.html >/dev/null && ok "client 可直连目标（路由正常）" || bad "路由不通"

step "启动控制端与节点"
echo '{"listen":"127.0.0.1:18443","data_dir":"'$W'/ctrl"}' > "$W/ctrl.json"
"$CTRL_BIN" run -c "$W/ctrl.json" > "$W/ctrl.log" 2>&1 & CTRL_PID=$!
sleep 2
PW=$(python3 -c "import json
for l in open('$W/ctrl.log'):
    try: d=json.loads(l)
    except: continue
    if d.get('password'): print(d['password'])")
C="curl -sk -b $W/cookie -c $W/cookie -H X-Mocat:1 -H Content-Type:application/json"
B=https://127.0.0.1:18443
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
$C -X POST $B/api/login -d '{"username":"admin","password":"'$PW'"}' >/dev/null
NJ=$($C -X POST $B/api/nodes -d '{"name":"node1","host":"127.0.0.1","port":19443}')
NODE_ID=$(echo "$NJ" | jget 'd["node"]["id"]'); TOKEN=$(echo "$NJ" | jget 'd["install"]["token"]')
"$NODE_BIN" init -c "$W/node.json" -token "$TOKEN" -listen 127.0.0.1:19443 -state-dir "$W/node" >/dev/null
"$NODE_BIN" run -c "$W/node.json" > "$W/node.log" 2>&1 & NODE_PID=$!
sleep 1

HTTP_O='{"type":"fakehttp","template_id":"","params":{"host":"www.speedtest.net","ttl":1,"repeat":2}}'
SIP_O='{"type":"fakesip","template_id":"","params":{"uri":"sip:10086@sip.example.com","ttl":1,"repeat":2}}'
NONE_O='{"type":"none"}'
add_rule() { # name proto port tport backend obfs
  local r; r=$($C -X POST $B/api/rules -d '{"node_id":"'$NODE_ID'","name":"'$1'","enabled":true,"protocol":"'$2'","listen_port":'$3',"target_host":"'$TGT'","target_port":'$4',"backend":"'$5'","obfs":'$6'}')
  echo "$r" | grep -q '"error"' && bad "新建规则 $1 失败: $r"
}
add_rule tcp-socat       tcp 18001 8000 socat "$NONE_O"
add_rule udp-socat       udp 15001 5353 socat "$NONE_O"
add_rule tcp-nft-http    tcp 18002 8000 nft   "$HTTP_O"
add_rule tcp-socat-http  tcp 18003 8000 socat "$HTTP_O"
add_rule udp-nft-sip     udp 15002 5353 nft   "$SIP_O"
add_rule udp-socat-sip   udp 15003 5353 socat "$SIP_O"

wait_synced() {
  for i in $(seq 1 40); do
    [ "$($C $B/api/nodes/$NODE_ID | jget 'd["node"]["runtime"]["online"] and d["node"]["synced"]')" = True ] && return 0; sleep 1
  done; return 1
}
wait_synced && ok "节点在线且已同步" || bad "节点未同步"
sleep 1
STATES=$($C "$B/api/rules?node_id=$NODE_ID" | jget "'\n'.join(r['name']+': '+r['state']+' '+r.get('reason','') for r in d)")
echo "$STATES" | sed 's/^/    /'
echo "$STATES" | grep -qv ': running' && bad "存在未运行的规则" || ok "6 条规则全部运行中"
[ "$(pgrep -xc fakehttp)" = 1 ] && ok "两条参数相同的 FakeHTTP 规则共用 1 个进程" || bad "fakehttp 进程数 $(pgrep -xc fakehttp)"
[ "$(pgrep -xc fakesip)" = 1 ] && ok "两条参数相同的 FakeSIP 规则共用 1 个进程" || bad "fakesip 进程数 $(pgrep -xc fakesip)"

# 抓包 + 发流量 + 分析
cap_start() {
  rm -f "$W/tcpdump.err"
  tcpdump -i mc_vt -nn -U -w "$W/$1.pcap" "$2" 2>"$W/tcpdump.err" & TP=$!
  for i in $(seq 1 50); do grep -q listening "$W/tcpdump.err" 2>/dev/null && break; sleep 0.1; done
}
cap_stop()  { sleep 1; kill $TP; wait $TP 2>/dev/null; }
tcp_req() { local port=$1 n=${2:-3} good=0; for i in $(seq 1 $n); do
  [ "$(ip netns exec mc_client curl -s --max-time 4 http://10.200.1.1:$port/index.html)" = hello-mocat ] && good=$((good+1)); done; echo $good; }
udp_req() { ip netns exec mc_client python3 -c "
import socket; good=0
for i in range(${2:-3}):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    try:
        s.sendto(b'ping%d'%i, ('10.200.1.1', $1)); good += s.recvfrom(100)[0]==b'echo:ping%d'%i
    except Exception: pass
print(good)"; }
check() { # name proto port expect marker
  python3 "$HERE/pcapcheck.py" "$W/$1.pcap" $TGT $2 $3 $4 1 "${5:-}"
}

for spec in "tcp-socat 18001 plain" "tcp-nft-http 18002 fake speedtest" "tcp-socat-http 18003 fake speedtest"; do
  set -- $spec
  step "TCP $1"
  cap_start "$1" "tcp and host $TGT"; N=$(tcp_req $2 3); cap_stop
  [ "$N" = 3 ] && ok "3/3 请求成功，数据正确" || bad "成功 $N/3"
  R=$(check $1 tcp 8000 $3 ${4:-}); echo "    $R"
  echo "$R" | grep -q '"problems": \[\]' && echo "$R" | grep -q '"flows": 3'     && ok "抓包：$([ $3 = fake ] && echo '每条连接的伪造 HTTP 请求都在第一个业务报文之前' || echo '无伪装报文')" || bad "抓包检查未通过"
done
for spec in "udp-socat 15001 plain" "udp-nft-sip 15002 fake sip:" "udp-socat-sip 15003 fake sip:"; do
  set -- $spec
  step "UDP $1"
  cap_start "$1" "udp and host $TGT"; N=$(udp_req $2 3); cap_stop
  [ "$N" = 3 ] && ok "3/3 个新流收到正确回包" || bad "成功 $N/3"
  R=$(check $1 udp 5353 $3 ${4:-}); echo "    $R"
  echo "$R" | grep -q '"problems": \[\]' && echo "$R" | grep -q '"flows": 3'     && ok "抓包：$([ $3 = fake ] && echo '每个新流的伪造 SIP 报文都在第一个业务报文之前' || echo '无伪装报文')" || bad "抓包检查未通过"
done
grep -q 'sip:' "$W/udp.log" && bad "目标收到了伪装报文（TTL 未生效）" || ok "目标未收到任何伪装报文（TTL 过期）"
grep -q ' 400 ' "$W/http.log" && bad "目标收到了错误请求" || ok "目标 HTTP 服务未收到被污染的请求"

step "杀掉伪装进程：fail-closed，不得漏出未伪装数据"
pkill -9 -x fakehttp; pkill -9 -x fakesip
cap_start kill-tcp "tcp and host $TGT"
for i in 1 2 3; do ip netns exec mc_client curl -s --max-time 1 http://10.200.1.1:18002/ >/dev/null; ip netns exec mc_client curl -s --max-time 1 http://10.200.1.1:18003/ >/dev/null; done
cap_stop
R=$(check kill-tcp tcp 8000 fake speedtest); echo "    $R"
echo "$R" | grep -q '"problems": \[\]' && ok "伪装进程重启期间没有未伪装的 TCP 业务数据发出" || bad "存在未伪装的数据"
pkill -9 -x fakesip
cap_start kill-udp "udp and host $TGT"; udp_req 15002 2 >/dev/null; udp_req 15003 2 >/dev/null; cap_stop
R=$(check kill-udp udp 5353 fake sip:); echo "    $R"
echo "$R" | grep -q '"problems": \[\]' && ok "伪装进程重启期间没有未伪装的 UDP 业务报文发出" || bad "存在未伪装的数据"
[ "$(tcp_req 18001 2)" = 2 ] && ok "无伪装的规则不受影响" || bad "无伪装规则受影响"
sleep 6
[ "$(pgrep -xc fakehttp)" = 1 ] && [ "$(pgrep -xc fakesip)" = 1 ] && ok "伪装进程已自动重启" || bad "伪装进程未重启"
[ "$(tcp_req 18002 2)" = 2 ] && [ "$(tcp_req 18003 2)" = 2 ] && [ "$(udp_req 15002 2)" = 2 ] && ok "伪装进程重启后转发恢复" || bad "转发未恢复"

step "socat 进程异常退出后自动重启"
pkill -9 -f 'TCP4-LISTEN:18001'; sleep 3
[ "$(tcp_req 18001 2)" = 2 ] && ok "socat 自动重启后恢复转发" || bad "socat 未恢复"

step "流量统计（socat 后端）"
sleep 11
S=$($C "$B/api/rules?node_id=$NODE_ID" | jget "[ (r['stats']['up_bytes'], r['stats']['down_bytes']) for r in d if r['name']=='tcp-socat'][0]")
echo "    tcp-socat (up, down) = $S"
echo "$S" | python3 -c "import sys; u,d=eval(sys.stdin.read()); sys.exit(0 if u>0 and d>0 else 1)" && ok "socat 后端也有流量统计" || bad "socat 统计为 0"

step "停止节点后无残留"
kill $NODE_PID; wait $NODE_PID 2>/dev/null; NODE_PID=
nft list table inet mocat >/dev/null 2>&1 && bad "nft 表残留" || ok "nft 表已删除"
pgrep -x fakehttp >/dev/null || pgrep -x fakesip >/dev/null || pgrep -x socat >/dev/null && bad "子进程残留" || ok "fakehttp / fakesip / socat 无残留"

echo; echo "== 伪装进程日志（节选）"
python3 - "$W/node.log" <<'P' | tail -25
import json, sys
for l in open(sys.argv[1]):
    try: d = json.loads(l)
    except Exception: continue
    if d.get("proc", "").startswith(("fakehttp", "fakesip")): print("   ", d["proc"], d["msg"][:160])
P
echo; echo "结果：通过 $PASS，失败 $FAIL"
[ $FAIL -eq 0 ]
