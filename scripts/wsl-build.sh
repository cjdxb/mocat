#!/bin/bash
# 开发辅助：把源码同步到 WSL 的 Linux 文件系统后编译（避免在 /mnt 上做 IO 密集操作）。
set -e
SRC="$(cd "$(dirname "$0")/.." && pwd)"
DST="$HOME/mocat-build"
export PATH="$HOME/go-sdk/bin:$PATH"
mkdir -p "$DST"
rsync -a --delete --exclude dist --exclude bin --exclude .git "$SRC/" "$DST/"
cd "$DST"
"$@"
