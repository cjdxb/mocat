#!/bin/bash
# 构建 amd64 / arm64 发行包（N-02、C-01）。
#   dist/mocat-node-linux-<arch>.tar.gz        mocat-node + fakehttp + fakesip + service + 许可证
#   dist/mocat-controller-linux-<arch>.tar.gz  mocat-controller + service
#
# fakehttp / fakesip 默认取 third_party/bin/<arch>/（由 scripts/build-fake.sh 生成）；
# 设置 BUILD_FAKE=1 时自动调用 build-fake.sh。
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo 0.1.0)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
LDFLAGS="-s -w -X mocat/internal/version.Version=$VERSION -X mocat/internal/version.Commit=$COMMIT -X mocat/internal/version.Date=$DATE"

rm -rf dist && mkdir -p dist
for ARCH in amd64 arm64; do
  echo "== $ARCH"
  FAKE="third_party/bin/$ARCH"
  if [ "${BUILD_FAKE:-0}" = "1" ]; then scripts/build-fake.sh "$ARCH" "$FAKE"; fi

  N="dist/mocat-node-linux-$ARCH"
  mkdir -p "$N"
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags "$LDFLAGS" -o "$N/mocat-node" ./cmd/mocat-node
  cp deploy/mocat-node.service "$N/"
  cp THIRD_PARTY.md "$N/"
  if [ -x "$FAKE/fakehttp" ] && [ -x "$FAKE/fakesip" ]; then
    cp "$FAKE/fakehttp" "$FAKE/fakesip" "$N/"
    cp "$FAKE"/LICENSE.* "$N/" 2>/dev/null || true
  else
    echo "警告: 未找到 $FAKE/fakehttp 或 fakesip，节点包中将不含伪装程序（可先运行 BUILD_FAKE=1）" >&2
  fi
  tar -C dist -czf "$N.tar.gz" "$(basename "$N")"

  C="dist/mocat-controller-linux-$ARCH"
  mkdir -p "$C"
  CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -trimpath -ldflags "$LDFLAGS" -o "$C/mocat-controller" ./cmd/mocat-controller
  cp deploy/mocat-controller.service "$C/"
  tar -C dist -czf "$C.tar.gz" "$(basename "$C")"
done
ls -la dist/*.tar.gz
echo "提示: 把 dist/mocat-node-linux-*.tar.gz 复制到控制端数据目录的 packages/ 下即可启用一键安装。"
