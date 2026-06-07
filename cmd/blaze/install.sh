#!/usr/bin/env bash
# blaze VPS kurulum scripti
#
# Kullanim:
#   curl -fsSL https://raw.githubusercontent.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest/claude/quirky-goodall-8vvFd/cmd/blaze/install.sh | bash
#
# veya manuel:
#   wget <url>
#   chmod +x install.sh
#   sudo ./install.sh
#
# Yaptiklari:
#   1. Go 1.22+ yoksa kurar
#   2. Repo'yu /opt/blaze altina klonlar
#   3. Static linux/amd64 binary build eder, /usr/local/bin/blaze'e koyar
#   4. ulimit + sysctl ayarlarini kalici yapar (yuksek RPS icin sart)
#   5. 'blaze fp' calistirip Safari fingerprint'i dogrular

set -euo pipefail

REPO_URL="https://github.com/JSInvasor/Gohttp-clientfingerprintemulateandfastest.git"
BRANCH="claude/quirky-goodall-8vvFd"
INSTALL_DIR="/opt/blaze"
BIN_PATH="/usr/local/bin/blaze"
GO_MIN_VERSION="1.22"

red()    { printf "\033[31m%s\033[0m\n" "$*"; }
green()  { printf "\033[32m%s\033[0m\n" "$*"; }
yellow() { printf "\033[33m%s\033[0m\n" "$*"; }
cyan()   { printf "\033[36m%s\033[0m\n" "$*"; }

# Root kontrol — sysctl + /usr/local/bin yazimi icin sart
if [[ $EUID -ne 0 ]]; then
    red "bu script sudo/root ile calismali. sudo ile tekrar dene:"
    echo "  sudo bash install.sh"
    exit 1
fi

cyan "==> distro tespit"
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    DISTRO="$ID"
else
    red "/etc/os-release yok, distro tespit edilemedi"
    exit 1
fi
echo "distro: $DISTRO"

cyan "==> bagimliliklar kuruluyor"
case "$DISTRO" in
    ubuntu|debian)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq git curl ca-certificates build-essential
        ;;
    fedora|rhel|centos|rocky|almalinux)
        dnf install -y -q git curl ca-certificates gcc make
        ;;
    arch)
        pacman -Sy --noconfirm git curl ca-certificates base-devel
        ;;
    alpine)
        apk add --no-cache git curl ca-certificates build-base
        ;;
    *)
        yellow "bilinmeyen distro ($DISTRO) — git/curl/build-essential elle kurulu olmali"
        ;;
esac

cyan "==> Go kurulum"
NEED_GO_INSTALL=1
if command -v go >/dev/null 2>&1; then
    CUR_GO=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' || echo "0.0")
    if [[ "$(printf '%s\n' "$GO_MIN_VERSION" "$CUR_GO" | sort -V | head -n1)" == "$GO_MIN_VERSION" ]]; then
        green "go $CUR_GO bulundu, kurulum atlandi"
        NEED_GO_INSTALL=0
    fi
fi

if [[ $NEED_GO_INSTALL -eq 1 ]]; then
    GO_VERSION="1.23.4"
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64) GO_ARCH=amd64 ;;
        aarch64|arm64) GO_ARCH=arm64 ;;
        *) red "desteklenmeyen mimari: $ARCH"; exit 1 ;;
    esac
    GO_TARBALL="go${GO_VERSION}.linux-${GO_ARCH}.tar.gz"

    echo "indiriliyor: $GO_TARBALL"
    curl -fsSL "https://go.dev/dl/${GO_TARBALL}" -o "/tmp/${GO_TARBALL}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TARBALL}"
    rm -f "/tmp/${GO_TARBALL}"

    # PATH'i hem login hem non-login shell'ler icin profile.d'ye koy
    cat > /etc/profile.d/go.sh <<'EOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
EOF
    chmod 644 /etc/profile.d/go.sh
    export PATH=$PATH:/usr/local/go/bin
    green "go $GO_VERSION kuruldu"
fi

cyan "==> repo klonlaniyor: $REPO_URL ($BRANCH)"
if [[ -d "$INSTALL_DIR/.git" ]]; then
    yellow "$INSTALL_DIR var, fetch + reset ile guncelleniyor"
    cd "$INSTALL_DIR"
    git fetch --depth 1 origin "$BRANCH"
    git checkout "$BRANCH"
    git reset --hard "origin/$BRANCH"
else
    rm -rf "$INSTALL_DIR"
    git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

cyan "==> blaze build (static, stripped)"
export PATH=$PATH:/usr/local/go/bin
export GOPATH=${GOPATH:-/root/go}
CGO_ENABLED=0 GOOS=linux GOARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    go build -ldflags="-s -w" -trimpath -o "$BIN_PATH" ./cmd/blaze
chmod +x "$BIN_PATH"
green "binary: $BIN_PATH"

cyan "==> OS tuning (ulimit + sysctl)"

# ulimit kalici — /etc/security/limits.d altina ozel dosya, asagidakileri
# ezse de upstream limits.conf'a dokunmasin
cat > /etc/security/limits.d/99-blaze.conf <<'EOF'
# blaze loadtest icin yuksek file descriptor limiti
# default 1024 → 10k+ RPS'i hemen oldurur (her TCP conn 1 fd)
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
green "limits.d/99-blaze.conf yazildi (nofile=1048576)"

# systemd kullanan distrolarda system+user manager'in da limitini yukselt;
# yoksa systemd-launched servisler hala 1024'te kalir
if [[ -d /etc/systemd ]]; then
    mkdir -p /etc/systemd/system.conf.d /etc/systemd/user.conf.d
    cat > /etc/systemd/system.conf.d/99-blaze.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=1048576
EOF
    cp /etc/systemd/system.conf.d/99-blaze.conf /etc/systemd/user.conf.d/99-blaze.conf
fi

# sysctl — yuksek RPS icin kritik 5 ayar
cat > /etc/sysctl.d/99-blaze.conf <<'EOF'
# === blaze loadtest tuning ===

# Ephemeral port range — default 32768-60999 = ~28k port. TIME_WAIT ile
# birlikte yuksek concurrency'de hizla biter. Tum non-privileged range'i ac.
net.ipv4.ip_local_port_range = 1024 65535

# TIME_WAIT socket'leri yeni outbound baglantilar icin tekrar kullan.
# Yuksek RPS'te bu ayar olmadan ephemeral port'lar 60s boyunca TIME_WAIT'te
# kilitli kalir ve "cannot assign requested address" hatasi alirsin.
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15

# Socket buffer maxlari — gofire WithSocketBuffers(2MB) bu tavanin altinda
# olmali, yoksa istek silently 256KB'a kirpilir.
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.rmem_default = 262144
net.core.wmem_default = 262144

# TCP per-socket buffer (min default max)
net.ipv4.tcp_rmem = 4096 262144 16777216
net.ipv4.tcp_wmem = 4096 262144 16777216

# Backlog — yuksek concurrency'de SYN queue dolup paketler dusebilir
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_max_syn_backlog = 32768

# FIN-WAIT-2 cleanup
net.ipv4.tcp_max_tw_buckets = 1440000
EOF

# Conntrack ayri dosya — modul yuklu degilse hata vermesin
if lsmod 2>/dev/null | grep -q nf_conntrack; then
    cat > /etc/sysctl.d/99-blaze-conntrack.conf <<'EOF'
# NAT/firewall arkasinda RPS bottleneck'i — default 65k tablo dolar ve
# yeni baglantilar drop edilir. Tabloyu agresif buyut.
net.netfilter.nf_conntrack_max = 1048576
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
EOF
fi

sysctl --system >/dev/null
green "sysctl ayarlari aktif"

cyan "==> fingerprint dogrulamasi"
if "$BIN_PATH" fp 2>&1 | head -10; then
    green "blaze hazir"
else
    yellow "fingerprint testi network'e cikamadi — VPS DNS/network'unu kontrol et"
fi

cat <<EOF

$(green "kurulum tamam.")

binary:    $BIN_PATH
kaynak:    $INSTALL_DIR
guncelle:  cd $INSTALL_DIR && git pull && go build -ldflags="-s -w" -o $BIN_PATH ./cmd/blaze

ornek kullanim:
  blaze fp                                            # fingerprint kontrol
  blaze https://hedef.com 60 64 32                    # 60sn, 64 thread × 32 stream
  blaze https://hedef.com 60 100 50 GET proxyler.txt  # proxy listesi ile
  blaze https://hedef.com 60 40 40 POST --body=16k    # 16KB body POST

$(yellow "not:") ulimit ayarinin yansimasi icin yeni shell ac (logout/login veya 'su - $USER').
       mevcut shell'in limitini kontrol: ulimit -n
EOF
