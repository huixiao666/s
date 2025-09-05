Go Buddy:
#!/bin/bash
# =========================================================
# Hysteria2 企业级自动化部署脚本 (v3.1)
# 特性：
# - 非交互式 / 幂等 (含 UFW 规则)
# - 官方混淆规范 (obfs.salamander.password)
# - QUIC 优化可选
# - Certbot 续期时自动修复 ACL 并重启服务
# - systemd 等待 network-online.target
# - 每次运行同步 UFW / Fail2Ban 端口
# - 支持 yq (可选) 以更稳健解析 YAML
# - 自动生成客户端 JSON / URI 订阅（并收紧权限）
# - 卸载 (--uninstall)
# - 增量更新 (--update-only)
# - dry-run 模式 (--dry-run)
# =========================================================
set -euo pipefail

# ----------------- 全局变量 -----------------
LOG_DIR="/var/log/hysteria_ops"
CONFIG_FILE="/etc/hysteria/config.yaml"
HYSTERIA_SERVICE_FILE="/etc/systemd/system/hysteria-server.service"
RENEWAL_HOOK_FILE="/etc/letsencrypt/renewal-hooks/deploy/hysteria-reload.sh"
SYSCTL_CONF_FILE="/etc/sysctl.d/99-hysteria-optimizations.conf"
LOGROTATE_CONF_FILE="/etc/logrotate.d/hysteria_ops"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.d/hysteria.local"
FAIL2BAN_FILTER_CONF="/etc/fail2ban/filter.d/hysteria.conf"
CLIENT_JSON_FILE="/etc/hysteria/client_sub.json"
CLIENT_URI_FILE="/etc/hysteria/client_sub.txt"

# 默认配置
SERVER_BANDWIDTH_UP="1gbps"
SERVER_BANDWIDTH_DOWN="1gbps"
IGNORE_CLIENT_BANDWIDTH=false
ENABLE_QUIC_TUNING=false
PORT_COUNT=10
PORT_MIN=40000
PORT_MAX=50000

# 控制开关
USE_YQ=false
DRY_RUN=false
UPDATE_ONLY=false
UNINSTALL=false

# 将这些全局声明，但在 main 中赋值
DOMAIN=""
EMAIL=""
H_PASS=""
O_PASS=""
declare -a PORTS

PKG_MANAGER=""  # 自动填充 apt/dnf/yum

# ----------------- 输出函数 -----------------
print_info()  { echo -e "\033[0;32m[信息]\033[0m $1"; }
print_warn()  { echo -e "\033[0;33m[警告]\033[0m $1"; }
print_error() { echo -e "\033[0;31m[错误]\033[0m $1"; exit 1; }
print_dry()   { echo -e "\033[0;36m[DRY-RUN]\033[0m $1"; }

# ----------------- run wrapper (支持 dry-run, 移除了 eval) -----------------
run_cmd() {
  if is_true "$DRY_RUN"; then
    print_dry "$*"
  else
    "$@"
  fi
}

# ----------------- 布尔帮助 -----------------
is_true() { [[ "$1" == "true" ]]; }

# ----------------- 使用说明 -----------------
usage() {
  cat <<'USAGE'
用法: sudo bash hysteria_v3.1.sh --domain <域名> [可选]

必选:
  --domain <域名>
  --email  <邮箱>         (首次申请证书需要)

可选:
  --port-count <N>            随机端口数量 (默认 10)
  --enable-quic <true|false>
  --force-bandwidth <true|false>
  --bandwidth-up <value>      eg: 500mbps
  --bandwidth-down <value>    eg: 500mbps
  --use-yq <true|false>       若安装 yq 则使用它解析 YAML
  --dry-run                   仅打印将执行的步骤，不做改动
  --update-only               只更新 config.yaml (使用现有密码/端口)，并重启服务
  --uninstall                 卸载并清理 Hysteria 相关配置
  --help
USAGE
}

# ----------------- 包管理器检测 -----------------
detect_pkg_manager() {
  if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
  elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
  elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
  else
    print_error "找不到受支持的包管理器 (apt-get/dnf/yum)。请在 Debian/Ubuntu/CentOS/RHEL 上运行。"
  fi
  print_info "检测到包管理器: $PKG_MANAGER"
}

# ----------------- 配置解析（yq 或内置） -----------------
parse_ports_from_config() {
    if is_true "$USE_YQ" && command -v yq &>/dev/null; then
        yq e '.listen[] | sub("^:?";"") | sub(":$";"") | sub("^:";"")' "$CONFIG_FILE" 2>/dev/null || true
    else
        grep -oP '^\s*-\s*:\s*\K[0-9]+' "$CONFIG_FILE" || true
    fi
}

parse_password_from_config() {
    local type="$1"
    if is_true "$USE_YQ" && command -v yq &>/dev/null; then
        if [[ "$type" == "auth" ]]; then
            yq e '.auth.password' "$CONFIG_FILE" 2>/dev/null || true
        else
            yq e '.obfs.salamander.password // .obfs.password' "$CONFIG_FILE" 2>/dev/null || true
        fi
    else
        if [[ "$type" == "auth" ]]; then
            awk '/^auth:/{f=1;next} f && /password:/ {gsub(/.*password[ ]*:[ ]*/,""); gsub(/"/,""); print; exit}' "$CONFIG_FILE" || true
        else
            awk '
              /^obfs:/{f=1; next}
              f && /salamander:/{in_salam=1; next}
              in_salam && /password:/{gsub(/.*password[ ]*:[ ]*/,""); gsub(/"/,""); print; exit}
              f && /password:/ && !in_salam { gsub(/.

*password[ ]*:[ ]*/,""); gsub(/"/,""); print; exit }
              f && NF==0 { f=0; in_salam=0 }
            ' "$CONFIG_FILE" || true
        fi
    fi
}

# ----------------- 域名解析检查 -----------------
check_domain_resolution() {
    local IP4 IP6 RES4 RES6
    IP4=$(curl -4s --max-time 5 ifconfig.me || echo "")
    IP6=$(curl -6s --max-time 5 ifconfig.me || echo "")
    RES4=$(dig +short A "$DOMAIN" | tr '\n' ' ' | xargs echo)
    RES6=$(dig +short AAAA "$DOMAIN" | tr '\n' ' ' | xargs echo)

    if [[ -z "$RES4" && -z "$RES6" ]]; then
        print_error "域名 $DOMAIN 未检测到任何 A 或 AAAA 记录"
    fi
    if [[ -n "$RES4" && -n "$IP4" ]]; then
        if ! echo "$RES4" | grep -qw "$IP4"; then
            print_warn "域名 $DOMAIN 的 A 记录 ($RES4) 未包含当前公网 IPv4 ($IP4)"
        fi
    fi
    if [[ -n "$RES6" && -n "$IP6" ]]; then
        if ! echo "$RES6" | grep -qw "$IP6"; then
            print_warn "域名 $DOMAIN 的 AAAA 记录 ($RES6) 未包含当前公网 IPv6 ($IP6)"
        fi
    fi
    print_info "域名解析检查通过 (若提示警告请确认 DNS 记录)"
}

# ----------------- 用户与证书权限 -----------------
create_hysteria_user() {
    if ! id -u hysteria &>/dev/null; then
        print_info "创建 hysteria 系统用户..."
        run_cmd useradd --system --shell /usr/sbin/nologin --home-dir /etc/hysteria hysteria
    else
        print_info "hysteria 用户已存在"
    fi
}

adjust_cert_permissions() {
    local domain_to_adjust="$1"
    if [[ -d "/etc/letsencrypt/live/$domain_to_adjust" ]]; then
        print_info "授予 hysteria 用户读取证书 ($domain_to_adjust) 权限..."
        run_cmd setfacl -R -m u:hysteria:rx "/etc/letsencrypt/live/$domain_to_adjust"
        run_cmd setfacl -R -m u:hysteria:rx "/etc/letsencrypt/archive/$domain_to_adjust"
    fi
}

# ----------------- 生成 Hysteria 配置 -----------------
generate_hysteria_config() {
    local D="$1"; local HP="$2"; local OP="$3"; shift 3
    local P=("$@")
    run_cmd mkdir -p "$(dirname "$CONFIG_FILE")"

    if is_true "$DRY_RUN"; then
        print_dry "将写入 Hysteria 配置到 $CONFIG_FILE (内容片段: listen: ${P[*]})"
        return
    fi
    
    cat > "$CONFIG_FILE" <<EOL
listen:
$(for port in "${P[@]}"; do echo "  - :$port"; done)
tls:
  cert: /etc/letsencrypt/live/$D/fullchain.pem
  key: /etc/letsencrypt/live/$D/privkey.pem
auth:
  type: password
  password: "$HP"
obfs:
  type: salamander
  salamander:
    password: "$OP"
ignoreClientBandwidth: $IGNORE_CLIENT_BANDWIDTH
EOL

    if is_true "$IGNORE_CLIENT_BANDWIDTH"; then
      cat >> "$CONFIG_FILE" <<EOL
bandwidth:
  up: $SERVER_BANDWIDTH_UP
  down: $SERVER_BANDWIDTH_DOWN
EOL
    fi

    if is_true "$ENABLE_QUIC_TUNING"; then
      cat >> "$CONFIG_FILE" <<'EOL'
transport:
  type: quic
  quic:
    initialStreamReceiveWindow: 8388608
    maxStreamReceiveWindow: 8388608
    initialConnectionReceiveWindow: 20971520
    maxConnectionReceiveWindow: 20971520
    maxIdleTimeout: 30s
    maxIncomingStreams: 1024
    disablePathMTUDiscovery: false
EOL
    fi

    # 权限加固：归 hysteria 用户，600 权限 (移除 || true)
    run_cmd chown hysteria:hysteria "$CONFIG_FILE"
    run_cmd chmod 600 "$CONFIG_FILE"
    print_info "Hysteria 配置已写入并设置权限为 hysteria:600"
}

# ----------------- 生成客户端订阅 -----------------
generate_client_subscriptions() {
    run_cmd mkdir -p "$(dirname "$CLIENT_JSON_FILE")"
    if is_true "$DRY_RUN"; then
        print_dry "将生成客户端订阅文件: $CLIENT_JSON_FILE 和 $CLIENT_URI_FILE"
        return
    fi

    # JSON
    {
      echo "{"
      echo '  "servers": ['
      local first=true
      for p in "${PORTS[@]}"; do
        if $first; then first=false; else echo "    ,"; fi
        echo "    {"
        echo "      \"addr\": \"$DOMAIN\","
        echo "      \"port\": $p,"
        echo "      \"auth\": \"$H_PASS\","
        echo "      \"obfs\": { \"type\": \"salamander\", \"password\": \"$O_PASS\" },"
        if is_true "$ENABLE_QUIC_TUNING"; then
          echo "      \"transport\": { \"type\": \"quic\" },"
        else
          echo "      \"transport\": null,"
        fi
        echo "      \"ignore_client_bandwidth\": $IGNORE_CLIENT_BANDWIDTH"
        echo "    }"
      done
      echo "  ]"
      echo "}"

} > "$CLIENT_JSON_FILE"

    # URI
    : > "$CLIENT_URI_FILE"
    for p in "${PORTS[@]}"; do
        local uri="hysteria://$H_PASS@$DOMAIN:$p?obfs=salamander&obfs-password=$O_PASS"
        if is_true "$ENABLE_QUIC_TUNING"; then
            uri="${uri}&transport=quic"
        fi
        echo "$uri" >> "$CLIENT_URI_FILE"
    done

    # 权限收紧 (移除 || true)
    run_cmd chown hysteria:hysteria "$CLIENT_JSON_FILE"
    run_cmd chmod 600 "$CLIENT_JSON_FILE"
    run_cmd chown hysteria:hysteria "$CLIENT_URI_FILE"
    run_cmd chmod 600 "$CLIENT_URI_FILE"
    print_info "客户端订阅已生成: $CLIENT_JSON_FILE, $CLIENT_URI_FILE (权限已收紧)"
}

# ----------------- UFW 同步 (增强幂等性) -----------------
sync_ufw_ports() {
    local COMMENT="Hysteria2-Managed" # 统一注释标识
    if ! command -v ufw &>/dev/null; then
        print_warn "ufw 未安装，跳过 UFW 配置"
        return
    fi

    # 确保基本规则存在
    run_cmd sed -i 's/IPV6=no/IPV6=yes/' /etc/ufw/ufw.conf
    if ! is_true "$DRY_RUN" && ! ufw status | grep -qw active; then
        print_info "UFW 未激活，设置默认规则..."
        ufw default deny incoming
        ufw default allow outgoing
        ufw logging on
        ufw allow 22/tcp
        ufw allow 80/tcp
        ufw allow 443/tcp
    fi

    # 清理旧的、由本脚本管理的规则 (健壮的幂等性)
    print_info "正在清理旧的 UFW 规则..."
    if ! is_true "$DRY_RUN" && ufw status numbered | grep -q "$COMMENT"; then
        # 逆序删除，避免规则编号变化导致错误
        ufw status numbered | tac | grep "$COMMENT" | awk -F'[][]' '{print $2}' | while read -r num; do
            # 必须用 yes 来确认删除
            yes | run_cmd ufw delete "$num"
        done
    else
        print_info "未发现需要清理的旧规则。"
    fi
    
    # 添加当前端口规则
    print_info "正在添加当前的 UFW 规则..."
    for p in "${PORTS[@]}"; do
        if ufw allow proto udp from any to any port "$p" comment "$COMMENT" 2>/dev/null; then
            :
        else
            # fallback for older ufw versions
            ufw allow "$p"/udp
        fi
    done

    run_cmd ufw --force enable
    print_info "UFW 端口同步完成"
}


# ----------------- Fail2Ban 同步 -----------------
sync_fail2ban() {
    if is_true "$DRY_RUN"; then
        print_dry "将写入 Fail2Ban 配置: $FAIL2BAN_JAIL_LOCAL"
        return
    fi
    
    cat > "$FAIL2BAN_JAIL_LOCAL" <<EOL
[hysteria]
enabled = true
backend = systemd
journalmatch = _SYSTEMD_UNIT=hysteria-server.service
port = $(IFS=,; echo "${PORTS[*]}")
protocol = udp
filter = hysteria
maxretry = 5
bantime = 12h
findtime = 5m
EOL

    cat > "$FAIL2BAN_FILTER_CONF" <<'EOL'
[Definition]
failregex = ^.*auth failed: incorrect password for <HOST>.*$
ignoreregex =
EOL

    run_cmd systemctl enable --now fail2ban
    run_cmd systemctl restart fail2ban
    print_info "Fail2Ban 同步完成"
}

# ----------------- 卸载逻辑 -----------------
uninstall_all() {
    print_info "执行卸载流程..."
    run_cmd systemctl stop hysteria-server.service
    run_cmd systemctl disable hysteria-server.service
    run_cmd rm -f "$HYSTERIA_SERVICE_FILE"
    run_cmd rm -rf /etc/hysteria # 删除整个配置目录
    run_cmd rm -f "$RENEWAL_HOOK_FILE"
    run_cmd rm -f "$SYSCTL_CONF_FILE"
    run_cmd rm -f "$LOGROTATE_CONF_FILE"
    run_cmd rm -f "$FAIL2BAN_JAIL_LOCAL" "$FAIL2BAN_FILTER_CONF"
    
    # 清理 UFW 端口（使用与同步时相同的逻辑）
    if command -v ufw &>/dev/null; then
        sync_ufw_ports # 传入空的 PORTS 数组即可实现清理
    fi
    
    if id -u hysteria &>/dev/null; then
        run_cmd userdel hysteria
    fi
    print_info "卸载完成。"
}

# ----------------- 命令行解析 -----------------
while [[ $# -gt 0 ]]; do
    case $1 in
        --domain) DOMAIN="$2"; shift 2 ;;
        --email) EMAIL="$2"; shift 2 ;;
        --port-count) PORT_COUNT="$2"; shift 2 ;;
        --enable-quic) ENABLE_QUIC_TUNING="$2"; shift 2 ;;
        --force-bandwidth) IGNORE_CLIENT_BANDWIDTH="$2"; shift 2 ;;
        --bandwidth-up) SERVER_BANDWIDTH_UP="$2"; shift 2 ;;
        --bandwidth-down) SERVER_BANDWIDTH_DOWN="$2"; shift 2 ;;
        --use-yq) USE_YQ="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --update-only) UPDATE_ONLY=true; shift ;;
        --uninstall) UNINSTALL=true; shift ;;
        --help) usage; exit 0 ;;

*) echo "未知参数: $1"; usage; exit 1 ;;
    esac
done

# ----------------- 参数校验与自动检测 -----------------
main() {
    if [[ "$EUID" -ne 0 ]]; then print_error "请以 root 或 sudo 权限运行脚本"; fi

    mkdir -p "$LOG_DIR"
    LOG_FILE="$LOG_DIR/$(date +'%Y%m%d_%H%M%S')_v3.1_ops.log"
    if ! is_true "$DRY_RUN"; then
      exec > >(tee -a "$LOG_FILE") 2>&1
      trap 'print_error "脚本执行失败，请查看日志: $LOG_FILE"' ERR
    else
      print_info "Dry-run 模式已启用：脚本只会打印将执行的操作，不会更改系统"
    fi

    detect_pkg_manager

    if is_true "$UNINSTALL"; then
        if [[ -f "$CONFIG_FILE" ]]; then
            mapfile -t PORTS < <(parse_ports_from_config)
        fi
        PORTS=() # 确保卸载时 PORTS 为空，以便 sync_ufw_ports 清理所有规则
        uninstall_all
        return 0
    fi

    if [[ -z "$DOMAIN" && -f "$CONFIG_FILE" ]]; then
        DOMAIN=$(grep -oP 'cert:\s*/etc/letsencrypt/live/\K[^/]+' "$CONFIG_FILE" 2>/dev/null || true)
        if [[ -n "$DOMAIN" ]]; then print_info "从现有配置检测到域名: $DOMAIN"; fi
    fi
    [[ -z "$DOMAIN" ]] && print_error "必须提供 --domain 参数（或确保已有 $CONFIG_FILE 中包含域名）"
    [[ ! "$PORT_COUNT" =~ ^[0-9]+$ ]] && print_error "--port-count 必须为数字"
    for flag in ENABLE_QUIC_TUNING IGNORE_CLIENT_BANDWIDTH USE_YQ; do
        val="${!flag}"
        if [[ "$val" != "true" && "$val" != "false" ]]; then
            print_error "--${flag,,} 值必须为 true 或 false"
        fi
    done
    
    print_info "开始 Hysteria2 部署 v3.1..."

    # 安装依赖
    print_info "准备安装/检查基础依赖 (pkg manager: $PKG_MANAGER)"
    local -a deps_common=(ufw curl socat certbot gzip openssl uuid-runtime net-tools fail2ban logrotate acl)
    local -a deps_debian=("${deps_common[@]}" dnsutils)
    local -a deps_rhel=("${deps_common[@]}" bind-utils)
    
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        run_cmd "$PKG_MANAGER" update -y
        run_cmd "$PKG_MANAGER" install -y "${deps_debian[@]}"
    else
        # dnf / yum
        run_cmd "$PKG_MANAGER" install -y "${deps_rhel[@]}"
    fi
    if is_true "$USE_YQ"; then 
        run_cmd "$PKG_MANAGER" install -y yq || print_warn "无法通过包管理器安装 yq，请手动安装"
    fi

    # 安装/更新 Hysteria
    run_cmd bash <(curl -fsSL https://get.hy2.sh/)
    
    # 读取旧配置或生成新
    if [[ -f "$CONFIG_FILE" ]]; then
        print_info "检测到现有配置，尝试读取端口与密码..."
        mapfile -t PORTS < <(parse_ports_from_config)
        H_PASS=$(parse_password_from_config "auth")
        O_PASS=$(parse_password_from_config "obfs")
        if [[ ${#PORTS[@]} -gt 0 && -n "$H_PASS" && -n "$O_PASS" ]]; then
            print_info "读取到 ${#PORTS[@]} 个端口与密码"
        else
            print_warn "未能完整解析现有配置，将生成新的端口/密码"
            PORTS=()
        fi
    fi

    if [[ ${#PORTS[@]} -eq 0 ]]; then
        if is_true "$UPDATE_ONLY"; then
            print_error "未找到现有端口/密码配置，无法执行 --update-only"
        fi
        print_info "生成 ${PORT_COUNT} 个随机端口并创建随机密码..."
        PORTS=()
        while [ ${#PORTS[@]} -lt "$PORT_COUNT" ]; do
            P=$(( RANDOM % (PORT_MAX - PORT_MIN + 1) + PORT_MIN ))
            if ! ss -tuln | grep -q ":$P\b" && ! [[ " ${PORTS[*]} " =~ " $P " ]]; then
                PORTS+=("$P")
            fi
        done
        H_PASS=$(uuidgen)
        O_PASS=$(openssl rand -hex 16)
        print_info "已生成端口与随机密码"
    fi

    if is_true "$UPDATE_ONLY"; then
        print_info "--update-only: 使用现有密码/端口更新配置..."
        generate_hysteria_config "$DOMAIN" "$H_PASS" "$O_PASS" "${PORTS[@]}"
        run_cmd systemctl daemon-reload
        run_cmd systemctl restart hysteria-server.service
        generate_client_subscriptions
        print_info "更新完成 (update-only)"
        return 0
    fi

    check_domain_resolution
    create_hysteria_user
    if [[ -d "/etc/letsencrypt/live/$DOMAIN" ]]; then adjust_cert_permissions "$DOMAIN"; fi

    # sysctl 优化
    run_cmd mkdir -p "$(dirname "$SYSCTL_CONF_FILE")"
    if ! is_true "$DRY_RUN"; then
        tee "$SYSCTL_CONF_FILE" >/dev/null <<'EOF'
# Hysteria 2 Optimizations
net.core.default_qdisc=fq; net.ipv4.tcp_congestion_control=bbr; net.core.rmem_max=26214400; net.core.wmem_max=26214400; net.ipv4.tcp_rmem=4096 87380 13107200; net.ipv4.

tcp_wmem=4096 65536 13107200; net.core.netdev_max_backlog=16384; net.ipv4.udp_mem=65536 131072 262144; net.ipv4.udp_rmem_min=8192; net.ipv4.udp_wmem_min=8192;
EOF
        sed -i 's/;/\n/g' "$SYSCTL_CONF_FILE" # 格式化为多行
        sysctl -p "$SYSCTL_CONF_FILE" >/dev/null || print_warn "sysctl 应用可能失败"
    fi

    sync_ufw_ports
    sync_fail2ban

    # 证书申请
    if ! certbot certificates -d "$DOMAIN" 2>/dev/null | grep -q "VALID"; then
        print_info "开始申请证书..."
        [[ -z "$EMAIL" ]] && print_error "首次申请证书必须提供 --email"
        run_cmd certbot certonly --standalone --preferred-challenges http -d "$DOMAIN" --non-interactive --agree-tos -m "$EMAIL" --keep-until-expiring
    else
        print_info "检测到有效证书，跳过申请"
    fi
    adjust_cert_permissions "$DOMAIN"

    generate_hysteria_config "$DOMAIN" "$H_PASS" "$O_PASS" "${PORTS[@]}"

    # systemd 服务部署
    run_cmd mkdir -p "$(dirname "$HYSTERIA_SERVICE_FILE")"
    if ! is_true "$DRY_RUN"; then
        tee "$HYSTERIA_SERVICE_FILE" >/dev/null <<'EOL'
[Unit]
Description=Hysteria 2 Server
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=hysteria
Group=hysteria
ExecStart=/usr/local/bin/hysteria server --config %h/config.yaml
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
ProtectSystem=full
PrivateTmp=true
NoNewPrivileges=yes
ProtectHome=true
PrivateDevices=true
ProtectHostname=true
LockPersonality=true
[Install]
WantedBy=multi-user.target
EOL
        # 修正 ExecStart 路径为相对路径 %h/config.yaml 并确保 home dir 正确
        sed -i "s|%h/config.yaml|$CONFIG_FILE|" "$HYSTERIA_SERVICE_FILE"
        systemctl daemon-reload
        systemctl restart hysteria-server.service || print_warn "重启 hysteria-server.service 失败"
        systemctl enable hysteria-server.service
    fi

    # 续期钩子
    run_cmd mkdir -p "$(dirname "$RENEWAL_HOOK_FILE")"
    if ! is_true "$DRY_RUN"; then
        tee "$RENEWAL_HOOK_FILE" >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail
for domain in $RENEWED_DOMAINS; do
  setfacl -R -m u:hysteria:rx "/etc/letsencrypt/live/$domain" &>/dev/null || true
  setfacl -R -m u:hysteria:rx "/etc/letsencrypt/archive/$domain" &>/dev/null || true
done
systemctl restart hysteria-server.service &>/dev/null || true
EOF
        chmod +x "$RENEWAL_HOOK_FILE"
    fi

    # 日志轮转
    if ! is_true "$DRY_RUN"; then
        tee "$LOGROTATE_CONF_FILE" >/dev/null <<'EOL'
/var/log/hysteria_ops/*.log { daily; rotate 14; compress; delaycompress; missingok; notifempty; create 0640 root adm; }
EOL
    fi

    generate_client_subscriptions

    # 输出信息
    local SERVER_IPV4 SERVER_IPV6
    SERVER_IPV4=$(curl -4s --max-time 5 ifconfig.me || echo "N/A")
    SERVER_IPV6=$(curl -6s --max-time 5 ifconfig.me || echo "N/A")

    echo "=========================================================="
    echo "✅ Hysteria2 部署完成 (v3.1)"
    echo "域名:           $DOMAIN"
    echo "IPv4:           $SERVER_IPV4"
    echo "IPv6:           $SERVER_IPV6"
    echo "UDP 端口:       ${PORTS[*]}"
    echo "连接密码 (Auth): $H_PASS"
    echo "混淆密码 (Obfs): $O_PASS"
    echo "客户端 JSON:    $CLIENT_JSON_FILE"
    echo "客户端 URI:     $CLIENT_URI_FILE"
    if ! is_true "$DRY_RUN"; then echo "日志文件:       $LOG_FILE"; fi
    echo "=========================================================="
}

main "$@"
