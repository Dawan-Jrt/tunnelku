#!/bin/bash
# tunnelku installer - Xray (VLESS/VMess/Trojan) + nginx + TLS + menu
# Pemakaian: bash <(curl -Ls https://raw.githubusercontent.com/USERNAME/REPO/main/install.sh) [domain]
set -u

[ "$(id -u)" -eq 0 ] || { echo "Jalankan sebagai root."; exit 1; }
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ;;
  *) echo "Hanya mendukung Debian / Ubuntu."; exit 1 ;;
esac

write_files() {
  mkdir -p /usr/local/lib/tunnelku
  cat > /usr/local/lib/tunnelku/common.sh <<'__TUNNELKU_COMMON__'
#!/bin/bash
# tunnelku - fungsi bersama (dipakai installer & menu)
NAME="tunnelku"
ETC="/etc/$NAME"
DB="$ETC/users.json"
BASE="$ETC/xray-base.json"
DOMAIN_FILE="$ETC/domain"
CERT_DIR="$ETC/cert"
XCONF="/usr/local/etc/xray/config.json"
NGX_CONF="/etc/nginx/conf.d/$NAME.conf"
ACME="/root/.acme.sh/acme.sh"
LOCK="$ETC/.lock"
INFO="$ETC/ipinfo.json"
LOG="/var/log/$NAME-install.log"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; C='\033[0;36m'; N='\033[0m'
msg()  { echo -e "${C}[*]${N} $*"; }
ok()   { echo -e "${G}[OK]${N} $*"; }
warn() { echo -e "${Y}[!]${N} $*"; }
die()  { echo -e "${R}[X]${N} $*" >&2; exit 1; }

# jalankan perintah, simpan outputnya ke log (bukan dibuang)
run_log() { "$@" >>"$LOG" 2>&1; }

# jalankan fungsi dengan kunci agar cron & menu tidak menulis users.json bersamaan
locked() { mkdir -p "$ETC"; ( flock -w 30 9 || { echo "Gagal mendapat kunci database." >&2; exit 1; }; "$@" ) 9>"$LOCK"; }

# baca satu field dari cache info IP/kota/ISP (JSON, tidak pernah di-source)
info_get() { local v; v=$(jq -r --arg k "$1" '.[$k] // empty' "$INFO" 2>/dev/null); echo "${v:--}"; }

# ambil IP, kota, ISP lewat HTTPS (ipinfo.io), simpan sebagai cache
fetch_ipinfo() {
  local j
  j=$(curl -fsS --max-time 8 https://ipinfo.io/json 2>/dev/null) || return 1
  echo "$j" | jq -e 'has("ip")' >/dev/null 2>&1 || return 1
  mkdir -p "$ETC"
  echo "$j" | jq '{ip:.ip, city:(.city // "-"), isp:((.org // "-") | sub("^AS[0-9]+ ";""))}' > "$INFO"
}

get_ip() { curl -4 -fsS --max-time 8 https://ipv4.icanhazip.com 2>/dev/null | tr -d '[:space:]'; }
fmt_date() { date -d "@$1" '+%Y-%m-%d %H:%M'; }
valid_domain() { [[ $1 =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]]; }

check_dns() {
  local d=$1 ip dns
  ip=$(get_ip)
  dns=$(getent ahostsv4 "$d" | awk '{print $1; exit}')
  if [ -z "$dns" ]; then warn "Domain $d belum ter-resolve."; return 1; fi
  if [ "$dns" != "$ip" ]; then warn "Domain mengarah ke $dns, sedangkan IP VPS ini $ip."; return 1; fi
  return 0
}

# ---------- konfigurasi dasar Xray ----------
write_base() {
  mkdir -p "$ETC"
  cat > "$BASE" <<'JSON'
{
  "log": { "loglevel": "warning", "access": "none", "error": "/var/log/xray/error.log" },
  "inbounds": [
    { "tag": "vless-ws", "listen": "127.0.0.1", "port": 10001, "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vless" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] } },
    { "tag": "vmess-ws", "listen": "127.0.0.1", "port": 10002, "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/vmess" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] } },
    { "tag": "trojan-ws", "listen": "127.0.0.1", "port": 10003, "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "ws", "wsSettings": { "path": "/trojan" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] } },
    { "tag": "vless-grpc", "listen": "127.0.0.1", "port": 10011, "protocol": "vless",
      "settings": { "clients": [], "decryption": "none" },
      "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "vless-grpc" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] } },
    { "tag": "vmess-grpc", "listen": "127.0.0.1", "port": 10012, "protocol": "vmess",
      "settings": { "clients": [] },
      "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "vmess-grpc" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] } },
    { "tag": "trojan-grpc", "listen": "127.0.0.1", "port": 10013, "protocol": "trojan",
      "settings": { "clients": [] },
      "streamSettings": { "network": "grpc", "grpcSettings": { "serviceName": "trojan-grpc" } },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] } }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "ip": ["geoip:private"], "outboundTag": "block" },
      { "type": "field", "protocol": ["bittorrent"], "outboundTag": "block" }
    ]
  }
}
JSON
}

# ---------- nginx ----------
write_nginx() {
  mkdir -p "$ETC"
  local v6_80="" v6_443="" h2="http2" h2on="" ngv
  # nginx >= 1.25.1: "listen ... http2" deprecated, pakai direktif "http2 on;"
  ngv=$(nginx -v 2>&1 | sed -n 's|.*/\([0-9][0-9.]*\).*|\1|p')
  if [ -n "$ngv" ] && [ "$(printf '%s\n1.25.1\n' "$ngv" | sort -V | head -1)" = "1.25.1" ]; then
    h2=""; h2on="http2 on;"
  fi
  if [ -f /proc/net/if_inet6 ]; then
    v6_80="listen [::]:80 default_server;"
    v6_443="listen [::]:443 ssl $h2 default_server;"
  fi

  : > "$ETC/locations.conf"
  local p port
  for p in vless:10001 vmess:10002 trojan:10003; do
    port=${p#*:}
    cat >> "$ETC/locations.conf" <<LOC
location /${p%%:*} {
    proxy_pass http://127.0.0.1:$port;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$host;
    proxy_read_timeout 86400s;
    proxy_send_timeout 86400s;
}
LOC
  done

  : > "$ETC/grpc.conf"
  for p in vless-grpc:10011 vmess-grpc:10012 trojan-grpc:10013; do
    port=${p#*:}
    cat >> "$ETC/grpc.conf" <<LOC
location ^~ /${p%%:*} {
    if (\$request_method != "POST") { return 404; }
    client_body_buffer_size 1m;
    client_max_body_size 0;
    client_body_timeout 1h;
    grpc_read_timeout 1h;
    grpc_send_timeout 1h;
    grpc_pass grpc://127.0.0.1:$port;
}
LOC
  done

  rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
  cat > "$NGX_CONF" <<CONF
server {
    listen 80 default_server;
    $v6_80
    server_name _;
    include $ETC/locations.conf;
    location / { default_type text/plain; return 404 "not found\n"; }
}
server {
    listen 443 ssl $h2 default_server;
    $v6_443
    $h2on
    server_name _;
    ssl_certificate $CERT_DIR/fullchain.pem;
    ssl_certificate_key $CERT_DIR/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    include $ETC/locations.conf;
    include $ETC/grpc.conf;
    location / { default_type text/plain; return 404 "not found\n"; }
}
CONF
  nginx -t >/dev/null 2>&1 || { nginx -t; return 1; }
  systemctl enable nginx >/dev/null 2>&1
  systemctl restart nginx
}

# ---------- sertifikat TLS (Let's Encrypt via acme.sh) ----------
issue_cert() {
  local d=$1 other rc
  if [ ! -x "$ACME" ]; then
    msg "Memasang acme.sh..."
    curl -fsSL https://get.acme.sh 2>>"$LOG" | sh >>"$LOG" 2>&1
    [ -x "$ACME" ] || { warn "Gagal memasang acme.sh"; return 1; }
  fi
  "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1
  other=$(ss -ltnpH 'sport = :80' 2>/dev/null | grep -v '"nginx"' || true)
  if [ -n "$other" ]; then
    warn "Port 80 dipakai program lain:"; echo "$other"; return 1
  fi
  mkdir -p "$CERT_DIR"
  msg "Meminta sertifikat untuk $d..."
  "$ACME" --issue -d "$d" --standalone --keylength ec-256 \
        --pre-hook "systemctl stop nginx" --post-hook "systemctl start nginx"
  rc=$?
  # rc 2 = sertifikat masih valid, acme.sh melewati penerbitan ulang (aman)
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 2 ]; then
    systemctl start nginx 2>/dev/null || true
    warn "Gagal menerbitkan sertifikat. Pastikan domain mengarah ke IP VPS (Cloudflare: mode DNS only)."
    return 1
  fi
  "$ACME" --install-cert -d "$d" --ecc \
    --fullchain-file "$CERT_DIR/fullchain.pem" --key-file "$CERT_DIR/key.pem" \
    --reloadcmd "systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true" || return 1
  chmod 600 "$CERT_DIR/key.pem"
  return 0
}

# ---------- database akun & sinkron ke Xray ----------
db_init() { mkdir -p "$ETC"; [ -s "$DB" ] || echo '[]' > "$DB"; chmod 600 "$DB"; }

rebuild() {
  # nama sementara harus berakhiran .json, kalau tidak Xray gagal mengenali formatnya
  local tmp="${XCONF%.json}.new.json" out
  jq --slurpfile u "$DB" '
    def cl(p): [ $u[0][] | select(.proto==p)
        | if   p=="trojan" then {password:.id, email:.user}
          elif p=="vmess"  then {id:.id, email:.user, alterId:0}
          else                  {id:.id, email:.user} end ];
    .inbounds |= map(
      if   (.tag|startswith("vless"))  then .settings.clients = cl("vless")
      elif (.tag|startswith("vmess"))  then .settings.clients = cl("vmess")
      elif (.tag|startswith("trojan")) then .settings.clients = cl("trojan")
      else . end)' "$BASE" > "$tmp" || { rm -f "$tmp"; warn "Gagal menyusun config (jq)."; return 1; }
  if ! out=$(xray run -test -format json -config "$tmp" 2>&1); then
    rm -f "$tmp"; warn "Config Xray tidak valid, perubahan dibatalkan."
    echo "$out" | grep -v '\[Warning\]' | tail -n 10 >&2
    return 1
  fi
  mv "$tmp" "$XCONF"; chmod 644 "$XCONF"
  fix_xray_log
  systemctl restart xray
}

# tes konfigurasi dijalankan sebagai root dan bisa membuat error.log milik root;
# kembalikan kepemilikannya ke user layanan Xray agar layanan bisa menulis log
fix_xray_log() {
  local xu
  xu=$(systemctl show -p User --value xray 2>/dev/null)
  mkdir -p /var/log/xray
  [ -n "$xu" ] && chown -R "$xu": /var/log/xray 2>/dev/null
  return 0
}

user_exists() { jq -e --arg p "$1" --arg u "$2" 'any(.[]; .proto==$p and .user==$u)' "$DB" >/dev/null; }

_add_user() { # proto user detik -> mencetak id
  local proto=$1 user=$2 secs=$3 id exp
  id=${4:-$(cat /proc/sys/kernel/random/uuid)}
  exp=$(( $(date +%s) + secs ))
  jq --arg p "$proto" --arg u "$user" --arg i "$id" --argjson e "$exp" \
     '. += [{proto:$p, user:$u, id:$i, exp:$e}]' "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
  rebuild >&2
  echo "$id $exp"
}

_del_user() { # proto user
  jq --arg p "$1" --arg u "$2" 'map(select((.proto==$p and .user==$u) | not))' "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
  rebuild
}

_renew_user() { # proto user detik
  jq --arg p "$1" --arg u "$2" --argjson s "$3" --argjson n "$(date +%s)" \
     'map(if .proto==$p and .user==$u then .exp = ((if .exp>$n then .exp else $n end) + $s) else . end)' \
     "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
  rebuild
}

_expire_cleanup() {
  local now n
  now=$(date +%s)
  n=$(jq --argjson n "$now" '[.[] | select(.exp<=$n)] | length' "$DB")
  if [ "${n:-0}" -gt 0 ]; then
    jq --argjson n "$now" 'map(select(.exp>$n))' "$DB" > "$DB.tmp" && mv "$DB.tmp" "$DB"
    rebuild
  fi
}

# ---------- tampilan akun & link ----------
add_user()       { locked _add_user "$@"; }
del_user()       { locked _del_user "$@"; }
renew_user()     { locked _renew_user "$@"; }
expire_cleanup() { locked _expire_cleanup "$@"; }

vmess_link() { # domain id ps port net path tls type
  jq -nc --arg add "$1" --arg id "$2" --arg ps "$3" --arg port "$4" --arg net "$5" \
         --arg path "$6" --arg tls "$7" --arg type "$8" \
    '{v:"2",ps:$ps,add:$add,port:$port,id:$id,aid:"0",scy:"auto",net:$net,type:$type,host:$add,path:$path,tls:$tls,sni:$add}' \
    | base64 -w0 | sed 's|^|vmess://|'
  echo
}

show_account() { # proto user id exp
  local proto=$1 user=$2 id=$3 exp=$4 d up=${1^^} L ltls lnon lgrpc
  L="————————————————————————————————————"
  d=$(cat "$DOMAIN_FILE" 2>/dev/null)
  case "$proto" in
    vless)
      ltls="vless://$id@$d:443?encryption=none&security=tls&sni=$d&type=ws&host=$d&path=%2Fvless#$user"
      lnon="vless://$id@$d:80?encryption=none&security=none&type=ws&host=$d&path=%2Fvless#$user-ntls"
      lgrpc="vless://$id@$d:443?encryption=none&security=tls&sni=$d&type=grpc&serviceName=vless-grpc&mode=gun#$user-grpc" ;;
    vmess)
      ltls=$(vmess_link "$d" "$id" "$user" 443 ws /vmess tls none)
      lnon=$(vmess_link "$d" "$id" "$user-ntls" 80 ws /vmess "" none)
      lgrpc=$(vmess_link "$d" "$id" "$user-grpc" 443 grpc vmess-grpc tls gun) ;;
    trojan)
      ltls="trojan://$id@$d:443?security=tls&sni=$d&type=ws&host=$d&path=%2Ftrojan#$user"
      lnon=""
      lgrpc="trojan://$id@$d:443?security=tls&sni=$d&type=grpc&serviceName=trojan-grpc&mode=gun#$user-grpc" ;;
  esac
  echo "$L"; printf '%*s%s\n' 15 '' "$up"; echo "$L"
  printf '%-15s: %s\n' "Remarks" "$user" "CITY" "$(info_get city)" "ISP" "$(info_get isp)" "Domain" "$d"
  printf '%-15s: %s\n' "Port TLS" "443"
  [ "$proto" != trojan ] && printf '%-15s: %s\n' "Port none TLS" "80"
  if [ "$proto" = trojan ]; then printf '%-15s: %s\n' "Password" "$id"; else printf '%-15s: %s\n' "id" "$id"; fi
  [ "$proto" = vmess ] && printf '%-15s: %s\n' "alterId" "0" "Security" "auto"
  printf '%-15s: %s\n' "network" "ws / grpc" "path ws" "/$proto" "serviceName" "$proto-grpc" "Expired On" "$(fmt_date "$exp")"
  echo "$L"; printf '%*s%s\n' 12 '' "$up WS TLS"; echo "$L"; echo "$ltls"
  if [ -n "$lnon" ]; then
    echo "$L"; printf '%*s%s\n' 11 '' "$up WS NO TLS"; echo "$L"; echo "$lnon"
  fi
  echo "$L"; printf '%*s%s\n' 13 '' "$up GRPC"; echo "$L"; echo "$lgrpc"
  echo "$L"
}
__TUNNELKU_COMMON__
  cat > /usr/local/bin/tunnelku <<'__TUNNELKU_MENU__'
#!/bin/bash
# tunnelku - menu pengelola (tampilan box)
LIB="/usr/local/lib/tunnelku/common.sh"
[ -f "$LIB" ] || { echo "File $LIB tidak ditemukan."; exit 1; }
# shellcheck disable=SC1090
. "$LIB"

[ "$(id -u)" -eq 0 ] || die "Jalankan sebagai root."

case "${1:-}" in
  --expire)  expire_cleanup; exit 0 ;;
  --rebuild) rebuild; exit $? ;;
  -h|--help) echo "Pemakaian: $NAME [--expire|--rebuild]"; exit 0 ;;
esac

VERSION="v1.1.0"
CYAN='\033[0;36m'; YELLOW='\033[0;33m'; GREEN='\033[0;32m'; RED='\033[0;31m'
PURPLE='\033[0;35m'; WHITE='\033[1;37m'; NC='\033[0m'
HR=$(printf '─%.0s' $(seq 1 55))
BRAND_FILE="$ETC/brand.json"
REBOOT_CRON="/etc/cron.d/$NAME-reboot"

# ---------- elemen tampilan ----------
pause() { echo; read -rp " Tekan Enter untuk kembali..." _; }
top()   { echo -e "${CYAN}┌${HR}${NC}"; }
mid()   { echo -e "${CYAN}├${HR}${NC}"; }
bot()   { echo -e "${CYAN}└${HR}${NC}"; }
sep()   { echo -e "${CYAN}${HR}${NC}"; }
line()  { echo -e "${CYAN}│${NC} $*"; }
title() { local t=$1 pad; pad=$(( (55 - ${#t}) / 2 )); [ "$pad" -lt 1 ] && pad=1
          echo -e "${CYAN}│${NC}$(printf '%*s' "$pad" '')${YELLOW}${t}${NC}"; }
row()   { printf "${CYAN}│${NC} %-8s: ${3:-$WHITE}%s${NC}\n" "$1" "$2"; }
svc()   { systemctl is-active --quiet "$1" && echo "${GREEN}ON${NC}" || echo "${RED}OFF${NC}"; }
iface() { ip -4 route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}'; }
brand_get() { local v; v=$(jq -r --arg k "$1" '.[$k] // empty' "$BRAND_FILE" 2>/dev/null); echo "${v:-$2}"; }

header_main() {
  clear
  local os ram swap ifc vn rxd txd rxm txm r1 t1 r2 t2 mbit nv nl nt cert dom up
  os=$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")
  ram=$(free -m | awk '/Mem:/{print $2}'); swap=$(free -m | awk '/Swap:/{print $2}')
  dom=$(cat "$DOMAIN_FILE" 2>/dev/null); up=$(uptime -p | sed 's/^up //')
  cert=$(openssl x509 -enddate -noout -in "$CERT_DIR/fullchain.pem" 2>/dev/null | cut -d= -f2)
  ifc=$(iface)
  vn=$(vnstat -i "$ifc" --oneline 2>/dev/null)
  IFS=';' read -r _ _ _ rxd txd _ _ _ rxm txm _ <<<"$vn"
  mbit="-"
  if [ -n "$ifc" ] && [ -r "/sys/class/net/$ifc/statistics/rx_bytes" ]; then
    r1=$(<"/sys/class/net/$ifc/statistics/rx_bytes"); t1=$(<"/sys/class/net/$ifc/statistics/tx_bytes")
    sleep 0.4
    r2=$(<"/sys/class/net/$ifc/statistics/rx_bytes"); t2=$(<"/sys/class/net/$ifc/statistics/tx_bytes")
    mbit=$(awk -v a="$r1" -v b="$t1" -v c="$r2" -v d="$t2" 'BEGIN{printf "%.2f", ((c-a)+(d-b))*8/0.4/1000000}')
  fi
  read -r nv nl nt < <(jq -r '[ (map(select(.proto=="vmess"))|length), (map(select(.proto=="vless"))|length), (map(select(.proto=="trojan"))|length) ] | @tsv' "$DB" 2>/dev/null)

  top; title "$(brand_get name 'TUNNELKU VPN')"; mid
  row OS "$os"; row RAM "${ram:--}MB"; row SWAP "${swap:--}MB"
  row CITY "$(info_get city)"; row ISP "$(info_get isp)"; row IP "$(info_get ip)"
  row DOMAIN "${dom:--}" "$YELLOW"; row UPTIME "$up"; row SSL "${cert:--}"
  printf "${CYAN}│${NC} ${PURPLE}%-8s${NC}: ${GREEN}RX:${NC} %s ${CYAN}|${NC} ${RED}TX:${NC} %s\n" TODAY "${rxd:--}" "${txd:--}"
  printf "${CYAN}│${NC} ${PURPLE}%-8s${NC}: ${GREEN}RX:${NC} %s ${CYAN}|${NC} ${RED}TX:${NC} %s\n" MONTH "${rxm:--}" "${txm:--}"
  row SPEED "$mbit Mbit/s"
  mid
  printf "${CYAN}│${NC} %-8s: XRAY: %b ${CYAN}|${NC} NGINX: %b ${CYAN}|${NC} CRON: %b\n" STATUS "$(svc xray)" "$(svc nginx)" "$(svc cron)"
  bot
  top; title "LIST ACCOUNTS"; mid
  printf "${CYAN}│${NC} %-14s: ${WHITE}%-4s${NC} ACCOUNT\n" VMESS "${nv:-0}" VLESS "${nl:-0}" TROJAN "${nt:-0}"
  bot
}

header_sub() { clear; top; title "$(brand_get name 'TUNNELKU VPN') - ${1:-SUB MENU}"; bot; }

# ---------- pemilihan akun ----------
pick_proto() {
  echo " 1) VLESS   2) VMess   3) Trojan"
  read -rp " Pilih protokol [1-3]: " p
  case "$p" in 1) PROTO=vless ;; 2) PROTO=vmess ;; 3) PROTO=trojan ;; *) PROTO="" ;; esac
  [ -n "$PROTO" ]
}

pick_account() { # [proto] -> SEL_PROTO SEL_USER SEL_ID SEL_EXP
  mapfile -t ROWS < <(jq -r --arg p "${1:-}" '.[] | select($p=="" or .proto==$p) | [.proto,.user,.id,(.exp|tostring)] | @tsv' "$DB")
  if [ ${#ROWS[@]} -eq 0 ]; then warn "Belum ada akun."; return 1; fi
  local i=1 row p u id e n
  printf " %3s  %-7s %-20s %s\n" NO PROTO USERNAME EXPIRED
  for row in "${ROWS[@]}"; do
    IFS=$'\t' read -r p u id e <<<"$row"
    printf " %3d  %-7s %-20s %s\n" "$i" "$p" "$u" "$(fmt_date "$e")"
    i=$((i+1))
  done
  read -rp " Nomor akun (kosong = batal): " n
  [[ $n =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le ${#ROWS[@]} ] || return 1
  IFS=$'\t' read -r SEL_PROTO SEL_USER SEL_ID SEL_EXP <<<"${ROWS[$((n-1))]}"
}

# ---------- aksi akun ----------
do_create() { # proto
  local P=$1 u days uid="" id exp
  read -rp " Username (huruf/angka/_ , 3-20): " u
  [[ $u =~ ^[A-Za-z0-9_]{3,20}$ ]] || { warn "Username tidak valid."; pause; return; }
  user_exists "$P" "$u" && { warn "Username sudah ada di $P."; pause; return; }
  if [ "$P" != trojan ]; then
    read -rp " UUID (Enter = acak): " uid
    if [ -n "$uid" ] && ! [[ $uid =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
      warn "Format UUID tidak valid."; pause; return
    fi
  fi
  read -rp " Expired (hari) [30]: " days; days=${days:-30}
  [[ $days =~ ^[0-9]+$ ]] && [ "$days" -ge 1 ] || { warn "Masa aktif tidak valid."; pause; return; }
  read -r id exp < <(add_user "$P" "$u" $((days*86400)) "$uid")
  [ -n "${id:-}" ] || { warn "Gagal membuat akun."; pause; return; }
  clear; show_account "$P" "$u" "$id" "$exp"; pause
}

do_trial() {
  header_sub "TRIAL ACCOUNT"
  pick_proto || { warn "Pilihan tidak valid."; pause; return; }
  local m u id exp
  read -rp " Durasi trial (menit) [60]: " m; m=${m:-60}
  [[ $m =~ ^[0-9]+$ ]] && [ "$m" -ge 1 ] || { warn "Durasi tidak valid."; pause; return; }
  u="trial$(tr -dc 'a-z0-9' </dev/urandom | head -c 5)"
  read -r id exp < <(add_user "$PROTO" "$u" $((m*60)))
  [ -n "${id:-}" ] || { warn "Gagal membuat akun."; pause; return; }
  clear; show_account "$PROTO" "$u" "$id" "$exp"
  echo " (akun trial dihapus otomatis maksimal 5 menit setelah kedaluwarsa)"; pause
}

do_renew() { # proto
  local days
  pick_account "$1" || { pause; return; }
  read -rp " Tambah masa aktif (hari): " days
  [[ $days =~ ^[0-9]+$ ]] && [ "$days" -ge 1 ] || { warn "Jumlah hari tidak valid."; pause; return; }
  renew_user "$SEL_PROTO" "$SEL_USER" $((days*86400)) && ok "Akun $SEL_USER diperpanjang $days hari."
  pause
}

do_del() { # proto
  local y
  pick_account "$1" || { pause; return; }
  read -rp " Hapus $SEL_PROTO/$SEL_USER? [y/N]: " y
  [[ $y =~ ^[yY]$ ]] || return
  del_user "$SEL_PROTO" "$SEL_USER" && ok "Akun dihapus."
  pause
}

do_check() { # proto
  pick_account "$1" || { pause; return; }
  clear; show_account "$SEL_PROTO" "$SEL_USER" "$SEL_ID" "$SEL_EXP"; pause
}

do_list() { # proto
  local n; n=$(jq --arg p "$1" '[.[] | select(.proto==$p)] | length' "$DB")
  if [ "${n:-0}" -eq 0 ]; then warn "Belum ada akun."; pause; return; fi
  printf " %-20s %s\n" USERNAME EXPIRED
  jq -r --arg p "$1" '.[] | select(.proto==$p) | [.user,(.exp|tostring)] | @tsv' "$DB" | while IFS=$'\t' read -r u e; do
    printf " %-20s %s\n" "$u" "$(fmt_date "$e")"
  done
  pause
}

proto_menu() { # proto
  local P=$1 N opt
  N=${P^}
  while true; do
    header_sub "${P^^} ACCOUNT"
    line "[1] Create Account $N"
    line "[2] Renew Account $N"
    line "[3] Delete Account $N"
    line "[4] Check Config User"
    line "[5] List Account $N"
    line "[x] Back"
    sep
    read -rp " Select Menu : " opt
    case "$opt" in
      1) do_create "$P" ;; 2) do_renew "$P" ;; 3) do_del "$P" ;;
      4) do_check "$P" ;;  5) do_list "$P" ;;  x|X|0) return ;;
    esac
  done
}

# ---------- domain ----------
change_domain_menu() {
  local d
  header_sub "CHANGE DOMAIN"
  echo -e "${YELLOW}WARNING: Mengganti domain akan menerbitkan sertifikat SSL baru!${NC}"
  sep
  read -rp " Masukkan Domain Baru (kosong = batal): " d
  [ -z "$d" ] && return
  valid_domain "$d" || { warn "Format domain tidak valid."; pause; return; }
  check_dns "$d" || { read -rp " DNS belum cocok. Lanjut tetap? [y/N]: " y; [[ $y =~ ^[yY]$ ]] || return; }
  warn "Nginx berhenti sebentar saat sertifikat diminta."
  if issue_cert "$d"; then
    echo "$d" > "$DOMAIN_FILE"
    write_nginx && ok "Domain diganti ke $d. Link lama perlu diambil ulang (Check Config User)."
  fi
  pause
}

# ---------- features ----------
do_bandwidth() {
  local ifc; ifc=$(iface)
  command -v vnstat >/dev/null || { warn "vnstat belum terpasang (apt install vnstat)."; pause; return; }
  trap ':' INT; vnstat -l -i "$ifc"; trap - INT
}

do_speedtest() {
  trap ':' INT
  if command -v speedtest >/dev/null && speedtest --version 2>&1 | grep -qi ookla; then
    speedtest --accept-license --accept-gdpr
  elif command -v speedtest-cli >/dev/null; then
    speedtest-cli --simple
  elif command -v speedtest >/dev/null; then
    speedtest --simple
  else
    warn "Speedtest belum terpasang. Pasang dengan: apt install speedtest-cli"
  fi
  trap - INT; pause
}

do_restart_all() { systemctl restart xray nginx vnstat 2>/dev/null; ok "Xray, Nginx & Vnstat di-restart."; sleep 2; }

do_clearcache() { sync; echo 3 > /proc/sys/vm/drop_caches && ok "Cache RAM dibersihkan."; sleep 1; }

do_autoreboot() {
  local h y
  if [ -f "$REBOOT_CRON" ]; then
    read -rp " Auto reboot sedang aktif. Matikan? [y/N]: " y
    [[ $y =~ ^[yY]$ ]] && rm -f "$REBOOT_CRON" && ok "Auto reboot dimatikan."
  else
    read -rp " Jam reboot harian (0-23) [0]: " h; h=${h:-0}
    [[ $h =~ ^[0-9]+$ ]] && [ "$h" -le 23 ] || { warn "Jam tidak valid."; pause; return; }
    echo "0 $h * * * root /sbin/reboot" > "$REBOOT_CRON"; chmod 644 "$REBOOT_CRON"
    ok "Auto reboot tiap jam $h:00 (zona waktu server: $(date +%Z))."
  fi
  sleep 2
}

do_sysinfo() {
  header_sub "INFORMATION SYSTEM"
  top
  row OS "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
  row KERNEL "$(uname -r)"
  row CPU "$(awk -F: '/model name/{print $2; exit}' /proc/cpuinfo | sed 's/^ //') ($(nproc) core)"
  row RAM "$(free -m | awk '/Mem:/{print $3"/"$2" MB"}')"
  row DISK "$(df -h / | awk 'NR==2{print $3"/"$2" ("$5")"}')"
  row LOAD "$(cut -d' ' -f1-3 /proc/loadavg)"
  row UPTIME "$(uptime -p | sed 's/^up //')"
  row IP "$(get_ip)"
  bot; pause
}

do_ipinfo() { fetch_ipinfo && ok "Info IP/kota/ISP diperbarui." || warn "Gagal mengambil info IP."; sleep 2; }

do_brand() {
  local n o t
  read -rp " Nama brand [$(brand_get name 'TUNNELKU VPN')]: " n
  read -rp " Owner [$(brand_get owner '-')]: " o
  read -rp " Telegram [$(brand_get telegram '-')]: " t
  # hanya karakter aman agar tampilan tidak bisa disusupi kode escape
  n=$(printf '%s' "${n:-$(brand_get name 'TUNNELKU VPN')}" | tr -dc '[:alnum:] _@.:|/+&()#-' | cut -c1-40)
  o=$(printf '%s' "${o:-$(brand_get owner '-')}"           | tr -dc '[:alnum:] _@.:|/+&()#-' | cut -c1-40)
  t=$(printf '%s' "${t:-$(brand_get telegram '-')}"        | tr -dc '[:alnum:] _@.:|/+&()#-' | cut -c1-40)
  mkdir -p "$ETC"
  jq -n --arg n "$n" --arg o "$o" --arg t "$t" '{name:$n,owner:$o,telegram:$t}' > "$BRAND_FILE" && ok "Brand disimpan."
  sleep 2
}

features_menu() {
  local opt
  while true; do
    header_sub "FEATURES"
    line "[1] Check Bandwidth (Vnstat)"
    line "[2] Speedtest"
    line "[3] Restart All Services"
    line "[4] Clear Cache RAM"
    line "[5] Auto Reboot (on/off)"
    line "[6] Information System"
    line "[7] Update Info IP / Kota / ISP"
    line "[8] Ubah Brand / Owner / Telegram"
    line "[x] Back"
    sep
    read -rp " Select Menu : " opt
    case "$opt" in
      1) do_bandwidth ;; 2) do_speedtest ;; 3) do_restart_all ;; 4) do_clearcache ;;
      5) do_autoreboot ;; 6) do_sysinfo ;; 7) do_ipinfo ;; 8) do_brand ;;
      x|X|0) return ;;
    esac
  done
}

check_services() {
  header_sub "SERVICES STATUS"
  top; title "SERVICES STATUS"; mid
  printf "${CYAN}│${NC} %-14s: %b\n" "Xray Core" "$(svc xray)" "Nginx" "$(svc nginx)" "Cron" "$(svc cron)" "Vnstat Mon" "$(svc vnstat)"
  bot; pause
}

# ---------- backup / restore ----------
do_backup() {
  local f="/root/$NAME-backup-$(date +%F-%H%M).tar.gz"
  tar czf "$f" -C / "etc/$NAME" && chmod 600 "$f" && ok "Backup: $f"
  pause
}

do_restore() {
  local f y
  read -rp " Path file backup (.tar.gz): " f
  [ -f "$f" ] || { warn "File tidak ditemukan."; pause; return; }
  # tolak backup yang berisi path di luar etc/tunnelku atau memakai ".."
  if ! tar tzf "$f" >/dev/null 2>&1; then warn "File bukan tar.gz yang valid."; pause; return; fi
  if tar tzf "$f" | grep -vE "^(\./)?etc/$NAME(/|$)" | grep -q . || tar tzf "$f" | grep -q '\.\.'; then
    warn "Backup ditolak: berisi path di luar etc/$NAME."; pause; return
  fi
  read -rp " Ini menimpa data akun & sertifikat saat ini. Lanjut? [y/N]: " y
  [[ $y =~ ^[yY]$ ]] || return
  locked tar xzf "$f" -C / && write_nginx && rebuild && ok "Restore selesai."
  pause
}

backup_menu() {
  local opt
  while true; do
    header_sub "BACKUP / RESTORE"
    line "[1] Backup Data"
    line "[2] Restore Data"
    line "[x] Back"
    sep
    read -rp " Select Menu : " opt
    case "$opt" in 1) do_backup ;; 2) do_restore ;; x|X|0) return ;; esac
  done
}

# ---------- uninstall ----------
do_uninstall() {
  clear
  echo -e "${RED}PERINGATAN: Ini akan menghapus Xray, akun, sertifikat, dan menu ini.${NC}"
  read -rp " Ketik HAPUS untuk uninstall semuanya: " y
  [ "$y" = "HAPUS" ] || return
  local d; d=$(cat "$DOMAIN_FILE" 2>/dev/null)
  systemctl stop xray 2>/dev/null
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove >/dev/null 2>&1
  [ -n "$d" ] && [ -x "$ACME" ] && "$ACME" --remove -d "$d" --ecc >/dev/null 2>&1
  rm -f "$NGX_CONF" "/etc/cron.d/$NAME" "$REBOOT_CRON"
  systemctl reload nginx 2>/dev/null
  rm -rf "$ETC" "/usr/local/lib/$NAME" "/usr/local/bin/$NAME"
  ok "Uninstall selesai. (nginx dan vnstat tetap terpasang)"
  exit 0
}

# ---------- menu utama ----------
while true; do
  header_main
  line "[1] VMESS ACCOUNT        [5] CHANGE DOMAIN VPS"
  line "[2] VLESS ACCOUNT        [6] FEATURES"
  line "[3] TROJAN ACCOUNT       [7] CHECK SERVICES"
  line "[4] TRIAL ACCOUNT        [8] BACKUP / RESTORE"
  line "[9] UNINSTALL SCRIPT     [x] EXIT"
  sep
  top
  printf "${CYAN}│${NC}  %-10s:  %s\n" Version "$VERSION" Owner "$(brand_get owner '-')" Telegram "$(brand_get telegram '-')"
  bot
  read -rp " Select Menu : " opt
  case "$opt" in
    1) proto_menu vmess ;; 2) proto_menu vless ;; 3) proto_menu trojan ;;
    4) do_trial ;; 5) change_domain_menu ;; 6) features_menu ;;
    7) check_services ;; 8) backup_menu ;; 9) do_uninstall ;;
    x|X|0|q) clear; exit 0 ;;
  esac
done
__TUNNELKU_MENU__
  chmod 644 /usr/local/lib/tunnelku/common.sh
  chmod 755 /usr/local/bin/tunnelku
}

write_files
# shellcheck disable=SC1091
. /usr/local/lib/tunnelku/common.sh

DOMAIN="${1:-}"
while ! valid_domain "$DOMAIN"; do
  read -rp "Masukkan domain (sudah diarahkan ke IP VPS ini): " DOMAIN </dev/tty
done
if ! check_dns "$DOMAIN"; then
  read -rp "DNS belum cocok. Lanjut tetap? [y/N]: " yn </dev/tty
  [[ $yn =~ ^[yY]$ ]] || exit 1
fi

: > "$LOG"; chmod 600 "$LOG"
msg "Memasang paket... (log: $LOG)"
run_log apt-get update -y
export DEBIAN_FRONTEND=noninteractive
run_log apt-get install -y curl jq nginx socat cron openssl tar ca-certificates unzip iproute2 util-linux vnstat \
  || { tail -n 15 "$LOG"; die "Gagal memasang paket dasar. Log lengkap: $LOG"; }

msg "Memasang Xray..."
XI=$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh 2>>"$LOG") \
  || die "Gagal mengunduh installer Xray. Log: $LOG"
run_log bash -c "$XI" @ install
command -v xray >/dev/null || { tail -n 15 "$LOG"; die "Xray gagal terpasang. Log: $LOG"; }

systemctl enable --now vnstat >/dev/null 2>&1 || true
fetch_ipinfo || true
db_init
write_base
echo "$DOMAIN" > "$DOMAIN_FILE"

issue_cert "$DOMAIN" || die "Sertifikat gagal. Perbaiki DNS lalu jalankan ulang installer."
write_nginx || die "Konfigurasi nginx gagal."
rebuild || die "Konfigurasi Xray gagal."
systemctl enable --now xray >/dev/null 2>&1

echo "*/5 * * * * root /usr/local/bin/tunnelku --expire >/dev/null 2>&1" > /etc/cron.d/tunnelku
chmod 644 /etc/cron.d/tunnelku

echo
ok "Instalasi selesai."
echo "  Domain : $DOMAIN"
echo "  Menu   : ketik  tunnelku"
echo
