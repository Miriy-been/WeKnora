#!/bin/bash
# 本地编译 + 组包：产物与 .github/workflows/release-lite.yml 等价
#   WeKnora (linux amd64, EDITION=standard, sqlite_fts5 tag) + web/ + config/ + migrations/
#
# 用法：bash build-local.sh [版本号]
#   产物：WeKnora_<版本>_linux_amd64.tar.gz
#   部署：cp WeKnora_<版本>_linux_amd64.tar.gz ../wek/weknora-lite-linux-amd64.tar.gz
#         （外层文件名保留历史名，wek/.gitattributes 例外行引用它）
#
# 依赖：Docker Desktop（golang:1.26-bookworm 容器内编译，锁定 glibc 2.36，
#       与 docreader bookworm 基座兼容；勿用 Windows go / WSL24.04 直接编译，
#       glibc 2.38+ 产物在容器里会 GLIBC not found）
#
# 注意：migrations/versioned（PG 主库迁移线）为本地组包新增——workflow 旧版
#       只打包了 sqlite 线，PG 模式启动会找不到迁移文件，勿用旧包。
set -e
cd "$(dirname "$0")"

VERSION="${1:-vlocal-$(date +%Y%m%d)}"
ARCHIVE="WeKnora_${VERSION}_linux_amd64"

echo ">>> [1/3] 容器内编译（golang:1.26-bookworm）..."
# Docker 探测：WSL 内无 docker daemon 时回退 docker.exe（Docker Desktop interop），
# 此时挂载路径须转 Windows 格式（wslpath -w）
if docker info >/dev/null 2>&1; then
    DOCKER="docker"
    SRCPATH="$PWD"
else
    DOCKER="docker.exe"
    SRCPATH="$(wslpath -w "$PWD")"
    "$DOCKER" info >/dev/null 2>&1 || { echo "ERROR: docker 与 docker.exe 均不可用"; exit 1; }
fi
"$DOCKER" run --rm -i -v "$SRCPATH:/src" -w /src -v weknora-gomod:/go/pkg/mod \
    -e CGO_ENABLED=1 \
    -e CGO_CFLAGS="-Wno-deprecated-declarations" \
    -e GOPROXY="https://goproxy.cn,direct" \
    golang:1.26-bookworm bash -s <<'INNER'
set -e
git config --global --add safe.directory /src
# 本地网络对 debian 官方源/镜像源时好时坏：直连失败自动切宿主代理
# （Docker Desktop 下 host.docker.internal 指向宿主，代理端口 7890）
if ! apt-get update -qq; then
    echo ">>> apt 直连失败，走宿主代理 127.0.0.1:7890 重试..."
    printf 'Acquire::http::Proxy "http://host.docker.internal:7890";\nAcquire::https::Proxy "http://host.docker.internal:7890";\n' \
        > /etc/apt/apt.conf.d/99local-proxy
    apt-get update -qq
fi
apt-get install -y -qq libsqlite3-dev > /dev/null
cd /src
go build -tags "sqlite_fts5" -ldflags="-w -s" -o WeKnora ./cmd/server
echo BUILD_OK
INNER

echo ">>> [2/3] 组包 $ARCHIVE ..."
if [ ! -f web/index.html ]; then
    echo "    web/ 不存在，从 wek/weknora-lite-linux-amd64.tar.gz 提取（前端未改动，无需重新构建）..."
    mkdir -p /tmp/weknora-web
    tar xzf ../wek/weknora-lite-linux-amd64.tar.gz -C /tmp/weknora-web --strip-components=1
    mv /tmp/weknora-web/web ./web
    rm -rf /tmp/weknora-web
fi

rm -rf "$ARCHIVE"
mkdir -p "$ARCHIVE/web" "$ARCHIVE/migrations"
cp WeKnora "$ARCHIVE/"
cp -r web/. "$ARCHIVE/web/"
cp -r config "$ARCHIVE/config"
cp -r migrations/sqlite "$ARCHIVE/migrations/sqlite"
cp -r migrations/versioned "$ARCHIVE/migrations/versioned"
cp .env.lite.example "$ARCHIVE/"
cp docs/LITE.md "$ARCHIVE/README.md" 2>/dev/null || true

echo ">>> [3/3] 打 tar.gz..."
tar czf "${ARCHIVE}.tar.gz" "$ARCHIVE"
rm -rf "$ARCHIVE"

echo ">>> 完成: $PWD/${ARCHIVE}.tar.gz"
echo "    部署替换: cp ${ARCHIVE}.tar.gz ../wek/weknora-lite-linux-amd64.tar.gz"
echo "    校验大小: du -h ${ARCHIVE}.tar.gz  （应约 90MB 级，非 KB 级指针）"
