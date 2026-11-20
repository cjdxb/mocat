#!/bin/bash
# 端到端测试（需要 root、nft、python3、curl）：
#   用 network namespace 模拟 客户端 → 节点（本机）→ 目标，真实运行控制端与节点。
# 用法: sudo scripts/e2e.sh <mocat-controller 路径> <mocat-node 路径>
set -uo pipefail
CTRL_BIN="${1:?controller}"; NODE_BIN="${2:?node}"
W=/var/tmp/mocat-e2e
PASS=0; FAIL=0
ok()   { echo "  [通过] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [失败] $*"; FAIL=$((FAIL+1)); }
step() { echo; echo "== $*"; }

cleanup() {
  if [ -n "${NODE_PID:-}" ]; then kill "$NODE_PID" 2>/dev/null; wait "$NODE_PID" 2>/dev/null; fi
  [ -n "${CTRL_PID:-}" ] && kill "$CTRL_PID" 2>/dev/null
  [ -n "${HTTP_PID:-}" ] && kill "$HTTP_PID" 2>/dev/null
  [ -n "${UDP_PID:-}" ] && kill "$UDP_PID" 2>/dev/null
  ip netns del mc_client 2>/dev/null; ip netns del mc_target 2>/dev/null
  ip link del mc_vc 2>/dev/null; ip link del mc_vt 2>/dev/null
  nft delete table inet mocat 2>/dev/null
}
trap cleanup EXIT
cleanup; rm -rf "$W"; mkdir -p "$W"

step "准备网络命名空间"
ip netns add mc_client; ip netns add mc_target
ip link add mc_vc type veth peer name eth0 netns mc_client
ip link add mc_vt type veth peer name eth0 netns mc_target
ip addr add 10.200.1.1/24 dev mc_vc; ip link set mc_vc up
ip addr add 10.200.2.1/24 dev mc_vt; ip link set mc_vt up
ip -n mc_client addr add 10.200.1.2/24 dev eth0; ip -n mc_client link set eth0 up; ip -n mc_client link set lo up
ip -n mc_target addr add 10.200.2.2/24 dev eth0; ip -n mc_target link set eth0 up; ip -n mc_target link set lo up
ip -n mc_client route add default via 10.200.1.1
ip -n mc_target route add default via 10.200.2.1
mkdir -p "$W/www"; head -c 1048576 /dev/urandom > "$W/www/blob"; echo hello-mocat > "$W/www/index.html"
ip netns exec mc_target python3 -m http.server 8000 --bind 10.200.2.2 --directory "$W/www" >/dev/null 2>&1 & HTTP_PID=$!
cat > "$W/udpecho.py" <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.200.2.2", 5353))
while True:
    d, a = s.recvfrom(2048); s.sendto(b"echo:" + d, a)
EOF
ip netns exec mc_target python3 "$W/udpecho.py" & UDP_PID=$!
sleep 1

step "启动控制端"
echo '{"listen":"127.0.0.1:18443","data_dir":"'$W'/ctrl"}' > "$W/ctrl.json"
"$CTRL_BIN" run -c "$W/ctrl.json" > "$W/ctrl.log" 2>&1 & CTRL_PID=$!
sleep 2
PW=$(python3 -c "import json,sys
for l in open('$W/ctrl.log'):
    try: d=json.loads(l)
    except: continue
    if d.get('password'): print(d['password'])")
[ -n "$PW" ] && ok "首次启动生成管理员初始密码" || { bad "未找到初始密码"; cat "$W/ctrl.log"; exit 1; }

C="curl -sk -b $W/cookie -c $W/cookie -H X-Mocat:1 -H Content-Type:application/json"
B=https://127.0.0.1:18443
jget() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

$C -X POST $B/api/login -d '{"username":"admin","password":"'$PW'"}' >/dev/null
NODE_JSON=$($C -X POST $B/api/nodes -d '{"name":"node1","host":"127.0.0.1","port":19443,"data_host":"10.200.1.1"}')
NODE_ID=$(echo "$NODE_JSON" | jget 'd["node"]["id"]')
TOKEN=$(echo "$NODE_JSON" | jget 'd["install"]["token"]')
[ -n "$NODE_ID" ] && [ ${#TOKEN} -ge 32 ] && ok "Web API 新建节点并生成 Token" || bad "新建节点失败: $NODE_JSON"

step "启动节点"
# 单独目录运行，确保找不到 fakehttp/fakesip（用于测试“伪装不可用即阻断”）
mkdir -p "$W/bin"; cp "$NODE_BIN" "$W/bin/mocat-node"; NODE_BIN="$W/bin/mocat-node"
"$NODE_BIN" init -c "$W/node.json" -token "$TOKEN" -listen 127.0.0.1:19443 -state-dir "$W/node" >/dev/null
start_node() { "$NODE_BIN" run -c "$W/node.json" >> "$W/node.log" 2>&1 & NODE_PID=$!; sleep 2; }
start_node
CODE=$(curl -sk -o /dev/null -w '%{http_code}' -H "Authorization: Bearer wrong-token-xxxxxxxx" https://127.0.0.1:19443/api/v1/status)
[ "$CODE" = 401 ] && ok "错误 Token 访问节点被拒绝 (401)" || bad "错误 Token 返回 $CODE"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:19443/api/v1/config)
[ "$CODE" = 401 ] && ok "无 Token 不能读取节点配置" || bad "无 Token 返回 $CODE"

wait_online() {
  for i in $(seq 1 30); do
    st=$($C $B/api/nodes/$NODE_ID | jget 'd["node"]["runtime"]["online"] and d["node"]["synced"]')
    [ "$st" = True ] && return 0; sleep 1
  done; return 1
}
wait_online && ok "控制端连上节点，节点在线且已同步" || bad "节点未上线"

step "nft 后端 TCP / UDP 转发"
$C -X POST $B/api/rules -d '{"node_id":"'$NODE_ID'","name":"tcp-nft","enabled":true,"protocol":"tcp","listen_port":18080,"target_host":"10.200.2.2","target_port":8000,"backend":"nft","obfs":{"type":"none"}}' >/dev/null
$C -X POST $B/api/rules -d '{"node_id":"'$NODE_ID'","name":"udp-nft","enabled":true,"protocol":"udp","listen_port":15353,"target_host":"10.200.2.2","target_port":5353,"backend":"nft","obfs":{"type":"none"}}' >/dev/null
wait_online
rule_state() { $C "$B/api/rules?node_id=$NODE_ID" | jget "[r['state']+'|'+r.get('reason','') for r in d if r['name']=='$1'][0]"; }
echo "    tcp-nft: $(rule_state tcp-nft) / udp-nft: $(rule_state udp-nft)"
OUT=$(ip netns exec mc_client curl -s --max-time 5 http://10.200.1.1:18080/index.html)
[ "$OUT" = hello-mocat ] && ok "TCP 经节点 DNAT 转发到目标" || bad "TCP 转发失败: $OUT"
ip netns exec mc_client curl -s --max-time 10 -o "$W/blob.dl" http://10.200.1.1:18080/blob
cmp -s "$W/blob.dl" "$W/www/blob" && ok "1MB 数据完整转发" || bad "大文件转发不一致"
UOUT=$(ip netns exec mc_client python3 -c "
import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(3)
s.sendto(b'ping', ('10.200.1.1', 15353)); print(s.recvfrom(100)[0].decode())")
[ "$UOUT" = echo:ping ] && ok "UDP 经节点 DNAT 转发" || bad "UDP 转发失败: $UOUT"

step "流量统计"
sleep 12
STATS=$($C "$B/api/rules?node_id=$NODE_ID" | jget "[(r['stats']['up_bytes'], r['stats']['down_bytes']) for r in d if r['name']=='tcp-nft'][0]")
DOWN=$(echo "$STATS" | python3 -c "import sys; print(eval(sys.stdin.read())[1])")
echo "    tcp-nft (up, down) = $STATS"
[ "$DOWN" -gt 1048576 ] && [ "$DOWN" -lt 1300000 ] && ok "下行字节数与实际传输量基本一致（1MB 文件）" || bad "下行统计异常: $DOWN"

step "伪装失败即阻断（fail-closed）"
# 本测试环境没有 fakehttp：规则应失败且不转发
$C -X POST $B/api/rules -d '{"node_id":"'$NODE_ID'","name":"tcp-obfs","enabled":true,"protocol":"tcp","listen_port":18081,"target_host":"10.200.2.2","target_port":8000,"backend":"nft","obfs":{"type":"fakehttp"}}' >/dev/null
wait_online
ST=$(rule_state tcp-obfs); echo "    tcp-obfs: $ST"
[[ "$ST" == failed* ]] && ok "伪装程序不可用时规则状态为失败" || bad "规则状态: $ST"
OUT=$(ip netns exec mc_client curl -s --max-time 3 http://10.200.1.1:18081/index.html)
[ -z "$OUT" ] && ok "伪装不可用的规则不转发任何流量" || bad "伪装不可用却转发了: $OUT"
OUT=$(ip netns exec mc_client curl -s --max-time 5 http://10.200.1.1:18080/index.html)
[ "$OUT" = hello-mocat ] && ok "其他规则不受影响" || bad "其他规则受影响"

step "规则停用 / 删除只影响相关规则"
RID=$($C "$B/api/rules?node_id=$NODE_ID" | jget "[r['id'] for r in d if r['name']=='udp-nft'][0]")
$C -X PUT $B/api/rules/$RID -d '{"node_id":"'$NODE_ID'","name":"udp-nft","enabled":false,"protocol":"udp","listen_port":15353,"target_host":"10.200.2.2","target_port":5353,"backend":"nft","obfs":{"type":"none"}}' >/dev/null
wait_online
[ "$(rule_state udp-nft)" = "disabled|" ] && ok "规则停用" || bad "停用状态: $(rule_state udp-nft)"
nft list table inet mocat | grep -q 'dport 15353' && bad "停用后 DNAT 规则仍在" || ok "停用后 nft 中已无该规则"
OUT=$(ip netns exec mc_client curl -s --max-time 5 http://10.200.1.1:18080/index.html)
[ "$OUT" = hello-mocat ] && ok "停用其他规则后 TCP 规则仍正常" || bad "TCP 规则受影响"

step "控制端停止后节点继续转发"
kill $CTRL_PID; wait $CTRL_PID 2>/dev/null; CTRL_PID=
OUT=$(ip netns exec mc_client curl -s --max-time 5 http://10.200.1.1:18080/index.html)
[ "$OUT" = hello-mocat ] && ok "控制端停止后转发不中断" || bad "控制端停止后转发中断"

step "节点重启后按缓存配置恢复（控制端仍停止）"
kill $NODE_PID; wait $NODE_PID 2>/dev/null; NODE_PID=
nft list table inet mocat >/dev/null 2>&1 && bad "节点退出后 nft 表残留" || ok "节点退出后 nft 表已清理"
pgrep -f "$W/node.json" >/dev/null && bad "节点子进程残留" || ok "无残留进程"
start_node
OUT=$(ip netns exec mc_client curl -s --max-time 5 http://10.200.1.1:18080/index.html)
[ "$OUT" = hello-mocat ] && ok "节点重启后按缓存恢复转发" || bad "缓存恢复失败: $OUT"

step "配置版本：旧版本被拒绝"
CODE=$(curl -sk -o /dev/null -w '%{http_code}' -X PUT -H "Authorization: Bearer $TOKEN" -d '{"version":1,"rules":[]}' https://127.0.0.1:19443/api/v1/config)
[ "$CODE" = 409 ] && ok "旧版本配置返回 409，不覆盖" || bad "旧版本配置返回 $CODE"

step "节点停止后无残留"
kill $NODE_PID; wait $NODE_PID 2>/dev/null; NODE_PID=
nft list table inet mocat >/dev/null 2>&1 && bad "nft 表残留" || ok "nft 表已删除"
OUT=$(ip netns exec mc_client curl -s --max-time 3 http://10.200.1.1:18080/index.html)
[ -z "$OUT" ] && ok "节点停止后不再转发" || bad "节点停止后仍在转发"

echo; echo "结果：通过 $PASS，失败 $FAIL"
[ $FAIL -eq 0 ]
