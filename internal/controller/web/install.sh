#!/bin/bash
# mocat 节点一键安装脚本（由控制端提供）。
# 用法: install.sh --controller https://ctrl:8443 --pin 'sha256//...' --token TOKEN [--listen 0.0.0.0:9443]
set -euo pipefail

CONTROLLER="" PIN="" TOKEN="" LISTEN="0.0.0.0:9443" PREFIX="/opt/mocat"
while [ $# -gt 0 ]; do
  case "$1" in
    --controller) CONTROLLER="$2"; shift 2 ;;
    --pin) PIN="$2"; shift 2 ;;
    --token) TOKEN="$2"; shift 2 ;;
    --listen) LISTEN="$2"; shift 2 ;;
    --prefix) PREFIX="$2"; shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = "0" ] || { echo "请以 root 运行" >&2; exit 1; }
[ -n "$CONTROLLER" ] && [ -n "$TOKEN" ] || { echo "缺少 --controller 或 --token" >&2; exit 2; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "不支持的架构: $(uname -m)（仅支持 amd64 / arm64）" >&2; exit 1 ;;
esac

CURL=(curl -fsSL)
if [ -n "$PIN" ]; then CURL+=(--insecure --pinnedpubkey "$PIN"); fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "下载 mocat-node ($ARCH) ..."
"${CURL[@]}" -o "$TMP/pkg.tar.gz" "$CONTROLLER/dl/mocat-node-linux-$ARCH.tar.gz"
mkdir -p "$PREFIX"
tar -xzf "$TMP/pkg.tar.gz" -C "$PREFIX" --strip-components=1
chmod 755 "$PREFIX/mocat-node" "$PREFIX/fakehttp" "$PREFIX/fakesip" 2>/dev/null || true

# 依赖：nft、socat（conntrack 可选）
need=()
command -v nft >/dev/null 2>&1 || need+=(nftables)
command -v socat >/dev/null 2>&1 || need+=(socat)
command -v conntrack >/dev/null 2>&1 || need+=(conntrack)
if [ ${#need[@]} -gt 0 ]; then
  echo "安装依赖: ${need[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq "${need[@]}" || true
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${need[@]/conntrack/conntrack-tools}" || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${need[@]/conntrack/conntrack-tools}" || true
  elif command -v apk >/dev/null 2>&1; then
    apk add "${need[@]/conntrack/conntrack-tools}" || true
  else
    echo "请手动安装: ${need[*]}" >&2
  fi
fi

if [ -f /etc/mocat/node.json ]; then
  echo "检测到已有配置，更新 token 与监听地址"
fi
"$PREFIX/mocat-node" init -token "$TOKEN" -listen "$LISTEN"
install -m 644 "$PREFIX/mocat-node.service" /etc/systemd/system/mocat-node.service
sed -i "s#/opt/mocat#$PREFIX#g" /etc/systemd/system/mocat-node.service
systemctl daemon-reload
systemctl enable mocat-node >/dev/null 2>&1
systemctl restart mocat-node
"$PREFIX/mocat-node" check || true
echo "mocat 节点已安装并启动：systemctl status mocat-node"
