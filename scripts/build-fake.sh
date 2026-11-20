#!/bin/sh
# 在 Docker（Alpine/musl）中从源码静态编译 fakehttp / fakesip（N-02、附录 A）。
# 依赖库 libmnl / libnfnetlink / libnetfilter_queue 也从固定版本源码静态编译。
#
# 用法: scripts/build-fake.sh <amd64|arm64> <输出目录>
# 需要 docker；跨架构编译需要 binfmt/qemu（docker run --privileged --rm tonistiigi/binfmt --install arm64）。
set -eu

ARCH="${1:?arch}"
OUT="$(cd "$(dirname "${2:?outdir}")" && pwd)/$(basename "$2")"
mkdir -p "$OUT"

# 固定版本（升级时同步更新 THIRD_PARTY.md）
FAKEHTTP_VER=0.9.18
FAKESIP_VER=0.9.1
LIBMNL_VER=1.0.5
LIBNFNETLINK_VER=1.0.2
LIBNFQ_VER=1.0.5

docker run --rm --platform "linux/$ARCH" -v "$OUT:/out" alpine:3.20 sh -euxc "
apk add --no-cache build-base linux-headers pkgconf bzip2 curl
cd /tmp
curl -fsSL https://www.netfilter.org/pub/libmnl/libmnl-$LIBMNL_VER.tar.bz2 | tar xj
curl -fsSL https://www.netfilter.org/pub/libnfnetlink/libnfnetlink-$LIBNFNETLINK_VER.tar.bz2 | tar xj
curl -fsSL https://www.netfilter.org/pub/libnetfilter_queue/libnetfilter_queue-$LIBNFQ_VER.tar.bz2 | tar xj
for d in libmnl-$LIBMNL_VER libnfnetlink-$LIBNFNETLINK_VER libnetfilter_queue-$LIBNFQ_VER; do
  (cd \$d && ./configure --prefix=/usr/local --enable-static --disable-shared && make -j\$(nproc) && make install)
done
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
curl -fsSL https://github.com/MikeWang000000/FakeHTTP/archive/refs/tags/$FAKEHTTP_VER.tar.gz | tar xz
curl -fsSL https://github.com/MikeWang000000/FakeSIP/archive/refs/tags/$FAKESIP_VER.tar.gz | tar xz
(cd FakeHTTP-$FAKEHTTP_VER && make STATIC=1 CFLAGS='-I/usr/local/include' LDFLAGS='-L/usr/local/lib' && cp build/fakehttp /out/ 2>/dev/null || cp fakehttp /out/)
(cd FakeSIP-$FAKESIP_VER && make STATIC=1 CFLAGS='-I/usr/local/include' LDFLAGS='-L/usr/local/lib' && cp build/fakesip /out/ 2>/dev/null || cp fakesip /out/)
cp FakeHTTP-$FAKEHTTP_VER/LICENSE /out/LICENSE.fakehttp
cp FakeSIP-$FAKESIP_VER/LICENSE /out/LICENSE.fakesip
strip /out/fakehttp /out/fakesip
file /out/fakehttp /out/fakesip 2>/dev/null || true
"
echo "已输出到 $OUT"
