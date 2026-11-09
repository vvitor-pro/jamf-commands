#!/bin/bash
# Diagnóstico de leitura para macOS / Jamf Pro. Bash 3.2 e utilitários nativos.
# Versão 2.2.0 — não executa políticas, inventário, reparos ou reinscrição.
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C LANG=C
umask 077
VERSION=2.2.0

usage() {
    cat <<'HELP'
Uso: sudo /bin/bash ./jamf-diagnostico.sh [opções]

Verifica computador, usuário conectado, Jamf, MDM, rede, Wi-Fi, DNS, Zscaler/VPN
e certificados. Gera relatorio.html, relatorio.txt e evidências em uma pasta privada.

  --output-base PASTA  Pasta existente para salvar a coleta (/private/tmp).
  --jamf-url URL       Destino HTTPS alternativo para os testes de rede.
  --deep              Inclui eventos MDM, Jamf e APNs dos últimos 15 minutos.
  --no-logs           Omite coleta e análise de logs.
  --no-color          Desativa cores no Terminal.
  --help, -h          Mostra esta ajuda.

Não altera configurações, perfis, certificados ou serviços. Não envia arquivos.
Com o Zscaler instalado, consulta https://ip.zscaler.com para confirmar a saída.
Retornos: 0=sem falha confirmada; 1=falha encontrada; 2=erro de uso; 130=interrompido.
HELP
}
die() { printf 'Erro: %s\n' "$*" >&2; exit 2; }
init_colors() {
    RESET='' BLUE='' GREEN='' YELLOW='' RED='' BOLD=''
    if [ -t 1 ] && [ "$NO_COLOR_FLAG" = 0 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != dumb ]; then
        RESET=$'\033[0m' BLUE=$'\033[36m' GREEN=$'\033[32m'
        YELLOW=$'\033[33m' RED=$'\033[31m' BOLD=$'\033[1m'
    fi
}
progress() { printf '%s  [%s/8]%s %s\n' "$BLUE" "$1" "$RESET" "$2"; }

# Consultas isoladas: saída e retorno preservados, sem travar a coleta.
capture() {
    local key="$1" seconds="$2" pid guard rc marker
    shift 2
    marker="$EVID/$key.timeout"
    /bin/rm -f "$marker"
    "$@" </dev/null >"$EVID/$key.txt" 2>&1 &
    pid=$!; ACTIVE_PID=$pid
    (
        sleeper=''
        trap 'if [ -n "$sleeper" ]; then kill "$sleeper" 2>/dev/null; fi; exit 0' TERM INT
        /bin/sleep "$seconds" & sleeper=$!
        wait "$sleeper"
        if kill -0 "$pid" 2>/dev/null; then
            : >"$marker"
            kill -TERM "$pid" 2>/dev/null
            /bin/sleep 2 & sleeper=$!
            wait "$sleeper"
            kill -KILL "$pid" 2>/dev/null
        fi
    ) &
    guard=$!; ACTIVE_GUARD=$guard
    wait "$pid" 2>/dev/null; rc=$?
    kill -TERM "$guard" 2>/dev/null
    wait "$guard" 2>/dev/null
    ACTIVE_PID='' ACTIVE_GUARD=''
    [ ! -f "$marker" ] || rc=124
    printf '%s\n' "$rc" >"$EVID/$key.rc"
    return 0
}
interrupted() {
    [ -z "${ACTIVE_PID:-}" ] || kill -TERM "$ACTIVE_PID" 2>/dev/null
    [ -z "${ACTIVE_GUARD:-}" ] || kill -TERM "$ACTIVE_GUARD" 2>/dev/null
    printf '\nColeta interrompida. Arquivos parciais: %s\n' "$OUT" >&2
    exit 130
}
rc_of() {
    if [ -r "$EVID/$1.rc" ]; then /bin/cat "$EVID/$1.rc"; else printf '125\n'; fi
}
# Em locale C, printf conta bytes: o preenchimento ignora os bytes de continuação UTF-8.
padded() {
    local plain="${2//[$'\x80'-$'\xbf']/}" n
    n=$(($1 - ${#plain}))
    [ "$n" -gt 0 ] || n=1
    printf '%s%*s' "$2" "$n" ''
}
kv_line() { printf '  %s%s\n' "$(padded 26 "$1:")" "${2:-Não disponível}"; }
join_parts() {
    local part out=''
    for part in "$@"; do [ -z "$part" ] || out="${out:+$out · }$part"; done
    printf '%s' "$out"
}
init_findings() {
    FAILS=0 WARNINGS=0 OKS=0 SECTION_N=0 AREA='' START_HINT='' REPORT_SUBJECT='' AGENT_CONN_FAILED=0
    AREA_NAMES=() AREA_FAIL=() AREA_WARN=() AREA_OK=() AREA_INFO=() FACT_LABELS=() FACT_VALUES=()
}
# A área curta identifica a origem de cada achado no resumo e no painel por área.
section() {
    SECTION_N=$((SECTION_N + 1)) AREA="${2:-$1}"
    AREA_NAMES[SECTION_N]="$AREA"
    AREA_FAIL[SECTION_N]=0; AREA_WARN[SECTION_N]=0; AREA_OK[SECTION_N]=0; AREA_INFO[SECTION_N]=0
    printf '\n## %s\n\n' "$1" >>"$BODY"
}
detail() { kv_line "$@" >>"$BODY"; }
note() { printf '%s\n' "$*" >>"$BODY"; }
# Dados principais exibidos na visão geral do Terminal, do texto e do HTML.
fact() {
    FACT_LABELS[${#FACT_LABELS[@]}]="$1"
    FACT_VALUES[${#FACT_VALUES[@]}]="$(printf '%s' "${2:-Não disponível}" | /usr/bin/tr '\t\n' '  ')"
}
finding() {
    local level="$1"
    shift
    printf '[%s] %s\n' "$level" "$*" >>"$BODY"
    printf '[%s] %s: %s\n' "$level" "${AREA:-Geral}" "$*" >>"$ISSUES"
    case "$level" in
        FALHA) FAILS=$((FAILS + 1)); AREA_FAIL[SECTION_N]=$((AREA_FAIL[SECTION_N] + 1)) ;;
        ATENCAO) WARNINGS=$((WARNINGS + 1)); AREA_WARN[SECTION_N]=$((AREA_WARN[SECTION_N] + 1)) ;;
        OK) OKS=$((OKS + 1)); AREA_OK[SECTION_N]=$((AREA_OK[SECTION_N] + 1)) ;;
        INFO) AREA_INFO[SECTION_N]=$((AREA_INFO[SECTION_N] + 1)) ;;
    esac
}
# Linha curta de uma evidência (first|last) para citar a resposta no próprio achado.
excerpt() {
    /usr/bin/awk -v mode="$2" '
        /^[a-z_]+=/ || !NF {next}
        {gsub(/[[:cntrl:]]/, ""); sub(/^[ \t]+/, ""); sub(/^curl: \([0-9]+\) /, ""); line = $0; if (mode == "first") exit}
        END {if (length(line) > 160) {line = substr(line, 1, 157); sub(/[\200-\377]+$/, "", line); line = line "..."}; print line}' "$EVID/$1.txt" 2>/dev/null
}
# Nome comum (CN) de um titular/emissor RFC2253; sem CN, devolve o nome completo.
cert_cn() { local v="${1#*CN=}"; printf '%s' "${v%%,*}"; }
evidence() {
    printf '\n>>> %s\n' "$2" >>"$BODY"
    if [ -s "$EVID/$1.txt" ]; then
        # Blocos indentados evitam que conteúdo de logs vire marcação do relatório.
        /usr/bin/tr -d '\000-\010\013-\037\177' <"$EVID/$1.txt" | /usr/bin/sed 's/^/    /' >>"$BODY"
        printf '\n' >>"$BODY"
    else printf '    Nenhum dado retornado.\n' >>"$BODY"; fi
    printf '<<<\n' >>"$BODY"
}
parse_url() {
    local authority port
    URL_HOST='' URL_PORT=443
    case "$1" in https://*) ;; *) return 1 ;; esac
    case "$1" in *'@'*|*'?'*|*'#'*|*[[:space:]]*|*\\*|*[[:cntrl:]]*) return 1 ;; esac
    authority="${1#https://}"; authority="${authority%%/*}"
    if [[ "$authority" =~ ^([A-Za-z0-9][A-Za-z0-9.-]*)(:([0-9]{1,5}))?$ ]]; then
        URL_HOST="${BASH_REMATCH[1]}"; port="${BASH_REMATCH[3]}"
    else return 1; fi
    if [ -n "$port" ]; then
        port=$((10#$port))
        [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || return 1
        URL_PORT="$port"
    fi
    return 0
}
hardware_value() {
    /usr/bin/awk -v key="$1" '{line=$0;sub(/^[ \t]+/, "", line)}
        index(line,key ":")==1 {sub(/^[^:]+:[ \t]*/, "", line);print line;exit}' "$EVID/hardware.txt"
}
plist_value() { /usr/libexec/PlistBuddy -c "Print :$2" "$1" 2>/dev/null; }

collect_machine() {
    progress 1 'Computador, usuário e armazenamento'
    capture system 10 /usr/bin/sw_vers
    capture hardware 30 /usr/sbin/system_profiler SPHardwareDataType
    capture architecture 5 /usr/bin/uname -m
    capture computer_name 5 /usr/sbin/scutil --get ComputerName
    capture uptime 5 /usr/bin/uptime
    capture disk 10 /bin/df -h /System/Volumes/Data
    [ "$(rc_of disk)" = 0 ] || capture disk 10 /bin/df -h /
    capture disk_info 15 /usr/sbin/diskutil info /
    capture battery 10 /usr/bin/pmset -g batt
    capture power 20 /usr/sbin/system_profiler SPPowerDataType -detailLevel mini
    capture filevault 15 /usr/bin/fdesetup status
    capture time_auto 10 /usr/sbin/systemsetup -getusingnetworktime
    capture time_server 10 /usr/sbin/systemsetup -getnetworktimeserver
    CONSOLE_USER="$(/usr/bin/stat -f '%Su' /dev/console 2>/dev/null)"
    USER_HOME='' CONSOLE_UID=''
    case "$CONSOLE_USER" in
        ''|root|loginwindow|_mbsetupuser) CONSOLE_USER='' ;;
        *)
            CONSOLE_UID="$(/usr/bin/id -u "$CONSOLE_USER" 2>/dev/null)"
            capture user 10 /usr/bin/dscl . -read "/Users/$CONSOLE_USER" RealName UniqueID PrimaryGroupID NFSHomeDirectory UserShell
            USER_HOME="$(/usr/bin/dscl . -read "/Users/$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | /usr/bin/sed -n 's/^NFSHomeDirectory: //p')"
            capture user_admin 10 /usr/bin/dsmemberutil checkmembership -U "$CONSOLE_USER" -G admin
            capture secure_token 15 /usr/sbin/sysadminctl -secureTokenStatus "$CONSOLE_USER"
            ;;
    esac
}
collect_management() {
    local candidate file label n=0
    progress 2 'Agente Jamf, serviços e inscrição MDM'
    capture enrollment 20 /usr/bin/profiles status -type enrollment
    capture bootstrap 20 /usr/bin/profiles status -type bootstraptoken
    capture profiles 20 /usr/bin/profiles list -all -type configuration
    capture launch_disabled 10 /bin/launchctl print-disabled system
    capture apsd 10 /bin/launchctl print system/com.apple.apsd
    capture processes 10 /bin/ps -axo pid,ppid,user,etime,comm
    JAMF=''
    for candidate in /usr/local/jamf/bin/jamf /usr/local/bin/jamf; do
        if [ -x "$candidate" ]; then JAMF="$candidate"; break; fi
    done
    if [ -n "$JAMF" ]; then
        capture jamf_version 15 "$JAMF" -version
        capture jamf_connection 35 "$JAMF" checkJSSConnection -retry 1
        capture jamf_signature 15 /usr/bin/codesign --verify --verbose=2 "$JAMF"
    fi
    : >"$EVID/services.tsv"
    for file in /Library/LaunchDaemons/*jamf*.plist /Library/LaunchDaemons/*Jamf*.plist; do
        [ -f "$file" ] || continue
        label="$(plist_value "$file" Label)"
        [ -n "$label" ] || continue
        n=$((n + 1))
        capture "service_$n" 10 /bin/launchctl print "system/$label"
        printf '%s\t%s\t%s\n' "$n" "$label" "$file" >>"$EVID/services.tsv"
    done
    capture jamf_url 10 /usr/bin/defaults read /Library/Preferences/com.jamfsoftware.jamf jss_url
    TARGET_URL=''
    [ "$(rc_of jamf_url)" != 0 ] || TARGET_URL="$(/bin/cat "$EVID/jamf_url.txt")"
    printf 'Host de destino apresentado no relatório.\n' >"$EVID/jamf_url.txt"
    [ -z "$URL_OVERRIDE" ] || TARGET_URL="$URL_OVERRIDE"
    URL_VALID=0
    if parse_url "$TARGET_URL"; then URL_VALID=1; fi
}
collect_network() {
    local candidate wifi
    progress 3 'Rede, Wi-Fi, DNS, Zscaler/VPN e conexão HTTPS'
    capture network 10 /usr/sbin/scutil --nwi
    capture dns_config 10 /usr/sbin/scutil --dns
    capture proxy 10 /usr/sbin/scutil --proxy
    capture vpn 10 /usr/sbin/scutil --nc list
    capture route 10 /sbin/route -n get default
    [ "$(rc_of route)" = 0 ] || capture route 10 /sbin/route -n get -inet6 default
    capture routes 10 /usr/sbin/netstat -rn -f inet
    capture interfaces 10 /sbin/ifconfig
    capture network_services 10 /usr/sbin/networksetup -listnetworkserviceorder
    # Dispositivo e serviço Wi-Fi, para consultar o DHCP, o rádio e o DNS manual.
    wifi="$(/usr/bin/awk '/^\([0-9*]+\) / {name = $0; sub(/^\([0-9*]+\) \*?/, "", name)}
        /^\(Hardware Port: (Wi-Fi|AirPort),/ {dev = $0; sub(/^.*Device: /, "", dev); sub(/\)$/, "", dev); print dev "|" name; exit}' "$EVID/network_services.txt")"
    WIFI_DEV="${wifi%%|*}" WIFI_SERVICE="${wifi#*|}"
    [[ "$WIFI_DEV" =~ ^[a-z]+[0-9]+$ ]] || WIFI_DEV=''
    if [ -n "$WIFI_DEV" ]; then
        capture wifi_summary 10 /usr/sbin/ipconfig getsummary "$WIFI_DEV"
        [ -z "$WIFI_SERVICE" ] || capture wifi_dns_manual 10 /usr/sbin/networksetup -getdnsservers "$WIFI_SERVICE"
        capture wifi_radio 30 /usr/sbin/system_profiler SPAirPortDataType
        # Somente a interface e a rede atual: redes vizinhas e canais suportados ficam fora.
        /usr/bin/awk '/Other Local Wi-Fi Networks:/ {exit} /^[ \t]*Interfaces:/ {on = 1} on && !/Supported Channels:/' "$EVID/wifi_radio.txt" >"$EVID/wifi_radio.tmp"
        /bin/mv "$EVID/wifi_radio.tmp" "$EVID/wifi_radio.txt"
    fi
    capture sysext 15 /usr/bin/systemextensionsctl list
    ZSCALER_APP='' ZSCALER_VERSION=''
    for candidate in /Applications/Zscaler/Zscaler.app /Applications/Zscaler.app; do
        if [ -d "$candidate" ]; then ZSCALER_APP="$candidate"; break; fi
    done
    if [ -n "$ZSCALER_APP" ]; then
        ZSCALER_VERSION="$(plist_value "$ZSCALER_APP/Contents/Info.plist" CFBundleShortVersionString)"
        # Página de diagnóstico do Zscaler: informa se a saída para a internet passa pela nuvem Zscaler.
        capture zscaler_check 25 /usr/bin/curl -q --silent --show-error --proto '=https' \
            --connect-timeout 8 --max-time 20 https://ip.zscaler.com/
        if [ "$(rc_of zscaler_check)" = 0 ]; then
            /usr/bin/awk '/class="(headline|details)"/ || /You are accessing|not going through/ {
                gsub(/<[^>]*>/, ""); gsub(/[[:space:]]+/, " "); sub(/^ /, ""); sub(/ $/, ""); if ($0 != "") print}' \
                "$EVID/zscaler_check.txt" >"$EVID/zscaler_check.tmp"
            /bin/mv "$EVID/zscaler_check.tmp" "$EVID/zscaler_check.txt"
        fi
    fi
    if [ "$URL_VALID" = 1 ]; then
        capture dns 15 /usr/bin/dscacheutil -q host -a name "$URL_HOST"
        capture https 25 /usr/bin/curl -q --silent --show-error --proto '=https' \
            --connect-timeout 8 --max-time 20 --output /dev/null \
            --write-out '\nhttp_code=%{http_code}\nremote_ip=%{remote_ip}\nssl_verify_result=%{ssl_verify_result}\ntime_connect=%{time_connect}\ntime_tls=%{time_appconnect}\ntime_total=%{time_total}\n' "$TARGET_URL"
    fi
}
collect_certificates() {
    local login jamf_keychain
    progress 4 'Certificados do sistema, usuário e servidor Jamf'
    capture cert_system 20 /usr/bin/security find-certificate -a -p /Library/Keychains/System.keychain
    capture identities_system 20 /usr/bin/security find-identity -p ssl-client /Library/Keychains/System.keychain
    JAMF_KEYCHAIN=0
    for jamf_keychain in '/Library/Application Support/JAMF/JAMF.keychain' '/Library/Application Support/JAMF/JAMF.keychain-db'; do
        [ -f "$jamf_keychain" ] || continue
        JAMF_KEYCHAIN=1
        capture cert_jamf 20 /usr/bin/security find-certificate -a -p "$jamf_keychain"
        capture identities_jamf 20 /usr/bin/security find-identity -p ssl-client "$jamf_keychain"
        capture jamf_keychain_info 5 /usr/bin/stat -f 'Arquivo: %N | Proprietário: %Su | Grupo: %Sg | Permissões: %Sp' "$jamf_keychain"
        break
    done
    USER_KEYCHAIN=0
    if [ -n "$CONSOLE_USER" ] && [[ "$CONSOLE_UID" =~ ^[0-9]+$ ]] && [ -n "$USER_HOME" ]; then
        login="$USER_HOME/Library/Keychains/login.keychain-db"
        [ -f "$login" ] || login="$USER_HOME/Library/Keychains/login.keychain"
        if [ -f "$login" ]; then
            USER_KEYCHAIN=1
            capture cert_user 20 /bin/launchctl asuser "$CONSOLE_UID" /usr/bin/sudo -n -u "$CONSOLE_USER" /usr/bin/security find-certificate -a -p "$login"
            capture identities_user 20 /bin/launchctl asuser "$CONSOLE_UID" /usr/bin/sudo -n -u "$CONSOLE_USER" /usr/bin/security find-identity -p ssl-client "$login"
        fi
    fi
    if [ "$URL_VALID" = 1 ]; then
        # Apenas coleta a cadeia direta com SNI; confiança é verificada pelo curl.
        capture tls_chain 20 /usr/bin/openssl s_client -connect "$URL_HOST:$URL_PORT" -servername "$URL_HOST" -showcerts
    fi
}
collect_logs() {
    progress 5 'Histórico de falhas e atividade de gerenciamento'
    [ "$NO_LOGS" = 0 ] || return 0
    capture jamf_log 10 /usr/bin/tail -n 400 /var/log/jamf.log
    capture install_log 10 /usr/bin/tail -n 200 /var/log/install.log
    capture jamf_log_date 5 /usr/bin/stat -f '%Sm' -t '%d/%m/%Y %H:%M:%S %z' /var/log/jamf.log
    if [ "$DEEP" = 1 ]; then
        capture mdm_log 35 /usr/bin/log show --last 15m --info --style compact \
            --predicate 'process == "mdmclient" OR process == "dmd" OR process == "apsd" OR process == "jamf" OR process == "jamfDaemon"'
        /usr/bin/tail -n 1200 "$EVID/mdm_log.txt" >"$EVID/mdm_log_tail.txt"
        /bin/mv "$EVID/mdm_log_tail.txt" "$EVID/mdm_log.txt"
    fi
}

analyze_machine() {
    local used free name='' model ident chip memory serial macos realname='' admin='Não disponível'
    section 'Computador e usuário' 'Computador'
    [ "$(rc_of computer_name)" != 0 ] || name="$(/bin/cat "$EVID/computer_name.txt")"
    model="$(hardware_value 'Model Name')"; ident="$(hardware_value 'Model Identifier')"
    chip="$(hardware_value 'Chip')$(hardware_value 'Processor Name')"; memory="$(hardware_value 'Memory')"
    serial="$(hardware_value 'Serial Number (system)')"
    macos="$(/usr/bin/awk '{v = $0; sub(/^[^:]*:[ \t]*/, "", v)} /^ProductVersion/ {p = v} /^BuildVersion/ {b = v}
        END {if (p != "") print p (b != "" ? " (" b ")" : "")}' "$EVID/system.txt")"
    if [ -n "$CONSOLE_USER" ]; then
        # dscl coloca nomes com espaço na linha seguinte à chave.
        realname="$(/usr/bin/awk '/^RealName:/ {v = $0; sub(/^RealName:[ \t]*/, "", v)
            if (v == "" && (getline nxt) > 0) {v = nxt; sub(/^[ \t]+/, "", v)}; print v; exit}' "$EVID/user.txt")"
        if /usr/bin/grep -q 'is not a member' "$EVID/user_admin.txt"; then admin='Não'
        elif /usr/bin/grep -q 'is a member' "$EVID/user_admin.txt"; then admin='Sim'; fi
    fi
    detail 'Nome do computador' "$name"
    detail 'Modelo' "$model"
    detail 'Identificador do modelo' "$ident"
    detail 'Número de série' "$serial"
    detail 'UUID de hardware' "$(hardware_value 'Hardware UUID')"
    detail 'Chip / processador' "$chip"
    detail 'Memória RAM' "$memory"
    detail 'Arquitetura' "$(/bin/cat "$EVID/architecture.txt")"
    detail 'macOS' "$macos"
    detail 'Usuário na sessão' "${CONSOLE_USER:-Sem usuário conectado}"
    [ -z "$CONSOLE_USER" ] || detail 'Administrador' "$admin"
    detail 'Executado por' "${SUDO_USER:-root} (privilégios root)"
    REPORT_SUBJECT="$(join_parts "$name" "$serial")"
    fact 'Computador' "$name"
    fact 'Modelo' "$(join_parts "$model${ident:+ ($ident)}" "$chip" "$memory")"
    fact 'Número de série' "$serial"
    fact 'macOS' "$macos"
    if [ -n "$CONSOLE_USER" ]; then
        fact 'Usuário na sessão' "$CONSOLE_USER${realname:+ ($realname)} · administrador: $admin"
    else fact 'Usuário na sessão' 'Sem usuário conectado'; fi
    detail 'Data e fuso do Mac' "$(/bin/date '+%d/%m/%Y %H:%M:%S %Z (%z)')"
    evidence system 'Versão e build do macOS'
    evidence uptime 'Tempo ligado e carga do sistema'
    if [ -n "$CONSOLE_USER" ]; then
        evidence user 'Nome completo, conta, UID, diretório pessoal e shell'
        evidence user_admin 'Privilégio administrativo do usuário'
        if [ "$(rc_of user)" != 0 ]; then finding ATENCAO 'Não foi possível consultar os dados da conta do usuário conectado.'; fi
        if [ "$(rc_of secure_token)" = 0 ] && /usr/bin/grep -q 'Secure token is ENABLED' "$EVID/secure_token.txt"; then
            finding OK "Secure Token habilitado para $CONSOLE_USER."
        elif /usr/bin/grep -q 'Secure token is DISABLED' "$EVID/secure_token.txt"; then
            finding ATENCAO "Secure Token desabilitado para $CONSOLE_USER. Pode afetar autorização de operações do sistema que exigem esse token."
        else finding ATENCAO 'Não foi possível determinar o Secure Token do usuário conectado.'; fi
    fi
    [ "$(rc_of hardware)" = 0 ] || finding ATENCAO 'A consulta de hardware não foi concluída; alguns dados do computador estão indisponíveis.'
    section 'Armazenamento, energia e proteção' 'Armazenamento'
    used="$(/usr/bin/awk 'NR==2 {gsub(/%/, "", $5);print $5}' "$EVID/disk.txt")"
    free="$(/usr/bin/awk 'NR==2 {print $4}' "$EVID/disk.txt")"
    if [[ "$used" =~ ^[0-9]+$ ]]; then
        fact 'Disco' "${used}% usado${free:+ · $free livres}"
        if [ "$used" -ge 95 ]; then
            finding ATENCAO "Volume de dados com ${used}% de uso${free:+ ($free livres)}. Espaço reduzido pode impedir downloads e instalações. Confira os bytes disponíveis e o tamanho do pacote antes de repetir a operação."
        elif [ "$used" -ge 90 ]; then
            finding ATENCAO "Volume de dados com ${used}% de uso${free:+ ($free livres)}. Verifique espaço disponível para atualizações e pacotes."
        else finding OK "Volume de dados com ${used}% de uso${free:+ ($free livres)}."; fi
    else
        fact 'Disco' ''
        finding ATENCAO 'Não foi possível determinar a ocupação do disco.'
    fi
    evidence disk 'Espaço dos volumes'
    evidence disk_info 'Volume de inicialização e sistema de arquivos'
    if [ "$(rc_of filevault)" != 0 ]; then finding ATENCAO 'Estado do FileVault indisponível.'
    elif /usr/bin/grep -q 'FileVault is On' "$EVID/filevault.txt"; then finding OK 'FileVault ativado.'
    elif /usr/bin/grep -q 'FileVault is Off' "$EVID/filevault.txt"; then finding INFO 'FileVault desativado. Confira se a política da empresa exige criptografia.'
    else evidence filevault 'Estado do FileVault'; fi
    evidence battery 'Fonte de energia e carga da bateria'
    evidence power 'Saúde da bateria e configuração de energia'
    if /usr/bin/grep -Eiq 'Condition:.*(Service Recommended|Replace|Service Battery)' "$EVID/power.txt"; then
        finding ATENCAO 'A bateria indica necessidade de manutenção. Instabilidade de energia pode interromper instalações e atualizações.'
    fi
    if [ "$(rc_of time_auto)" = 0 ] && /usr/bin/grep -Eiq 'Network Time: off' "$EVID/time_auto.txt"; then
        finding ATENCAO 'Ajuste automático de data/hora desativado. Se o relógio estiver incorreto, certificados e autenticação podem falhar.'
    elif [ "$(rc_of time_auto)" != 0 ]; then finding ATENCAO 'Não foi possível consultar o ajuste automático de data/hora.'; fi
    evidence time_auto 'Ajuste automático do relógio'
    evidence time_server 'Servidor de horário configurado'
}
analyze_management() {
    local n label file state disabled last_exit found=0 version='' msg mdm
    section 'Agente Jamf e serviços' 'Agente Jamf'
    if [ -n "$JAMF" ]; then
        detail 'Binário Jamf' "$JAMF"
        if [ "$(rc_of jamf_version)" = 0 ]; then
            version="$(/usr/bin/awk 'NF {sub(/^version=/, ""); print; exit}' "$EVID/jamf_version.txt")"
            detail 'Versão do agente' "$version"
        else finding ATENCAO 'O binário Jamf existe, mas não foi possível obter sua versão.'; fi
        fact 'Agente Jamf' "${version:-Instalado; versão indisponível}"
        case "$(rc_of jamf_connection)" in
            0) finding OK 'O agente conseguiu alcançar o Jamf Pro pelo checkJSSConnection.' ;;
            124) AGENT_CONN_FAILED=1
                finding ATENCAO 'O agente não concluiu o teste de comunicação. Rede, VPN, proxy ou servidor sem resposta podem estar envolvidos.' ;;
            *) AGENT_CONN_FAILED=1; msg="$(excerpt jamf_connection last)"
                finding FALHA "O agente falhou no checkJSSConnection${msg:+ (resposta: $msg)}. Verifique os testes de DNS, HTTPS e certificados." ;;
        esac
        evidence jamf_connection 'Resposta do teste do agente'
        if [ "$(rc_of jamf_signature)" = 0 ]; then finding OK 'A assinatura de código do binário Jamf passou pela verificação local.'
        elif [ "$(rc_of jamf_signature)" = 124 ]; then finding ATENCAO 'A verificação da assinatura do binário não foi concluída.'
        else
            finding ATENCAO 'A assinatura de código do binário Jamf não passou na verificação. Confira a integridade e a versão instalada do framework.'
            evidence jamf_signature 'Verificação da assinatura de código'
        fi
    else
        fact 'Agente Jamf' 'Não encontrado nos caminhos padrão'
        finding FALHA 'Agente Jamf ausente nos caminhos padrão. O framework pode estar incompleto ou não instalado, impedindo políticas e inventário pelo agente.'
    fi
    while IFS=$'\t' read -r n label file; do
        [ -n "$n" ] || continue
        found=1
        detail 'Serviço' "$label"
        detail 'Arquivo' "$file"
        disabled="$(/usr/bin/awk -v key="\"$label\"" '$1==key {print $NF}' "$EVID/launch_disabled.txt")"
        if [ "$disabled" = disabled ] || [ "$disabled" = true ]; then
            finding ATENCAO "O serviço $label está desabilitado no launchd. Isso pode impedir a tarefa Jamf correspondente."
        elif [ "$(rc_of "service_$n")" != 0 ]; then
            finding ATENCAO "O serviço $label possui plist, mas não pôde ser consultado no launchd; pode não estar carregado."
        else
            state="$(/usr/bin/awk -F' = ' '/^[[:space:]]*state = / {print $2;exit}' "$EVID/service_$n.txt")"
            detail 'Estado no launchd' "${state:-Carregado}"
            last_exit="$(/usr/bin/awk -F' = ' '/^[[:space:]]*last exit code = / {print $2;exit}' "$EVID/service_$n.txt")"
            if [[ "$last_exit" =~ ^[1-9][0-9]*$ ]]; then
                finding ATENCAO "Última execução de $label terminou com código $last_exit. Confira os logs e o horário da falha."
            fi
        fi
    done <"$EVID/services.tsv"
    [ "$found" = 1 ] || finding ATENCAO 'Nenhum LaunchDaemon com nome Jamf foi encontrado. Verifique os componentes de check-in do framework.'
    /usr/bin/awk 'NR==1 || tolower($0) ~ /jamf|mdmclient|\/apsd$/ {print}' "$EVID/processes.txt" >"$EVID/management_processes.txt"
    evidence management_processes 'Processos de gerenciamento presentes na coleta'
    for file in '/Applications/Self Service.app' '/Applications/Jamf Self Service.app' '/Applications/Self Service+.app'; do
        [ -d "$file" ] || continue
        detail 'Self Service' "$file — $(plist_value "$file/Contents/Info.plist" CFBundleShortVersionString)"
    done
    section 'Inscrição MDM e perfis' 'MDM'
    mdm='Estado não reconhecido'
    if [ "$(rc_of enrollment)" != 0 ]; then mdm='Estado indisponível'; finding ATENCAO 'O macOS não retornou o estado de inscrição MDM.'
    elif /usr/bin/grep -Eq 'MDM enrollment:[[:space:]]*Yes' "$EVID/enrollment.txt"; then
        mdm='Inscrito'
        finding OK 'O macOS informa inscrição MDM ativa.'
        if /usr/bin/grep -q '(User Approved)' "$EVID/enrollment.txt"; then
            mdm='Inscrito, aprovado pelo usuário'
            detail 'Aprovação do MDM' 'Aprovado pelo usuário'
        fi
    elif /usr/bin/grep -Eq 'MDM enrollment:[[:space:]]*No' "$EVID/enrollment.txt"; then
        mdm='Não inscrito'
        finding FALHA 'O macOS informa ausência de inscrição MDM. Comandos remotos e perfis dependentes do MDM não poderão ser entregues por essa inscrição.'
    else finding ATENCAO 'O estado MDM retornou em formato não reconhecido.'; fi
    /usr/bin/grep -Eq 'Enrolled via DEP:[[:space:]]*Yes' "$EVID/enrollment.txt" && mdm="$mdm · via ADE/DEP"
    fact 'Inscrição MDM' "$mdm"
    evidence enrollment 'Inscrição MDM e inscrição automática ADE/DEP'
    if [ "$(rc_of bootstrap)" != 0 ]; then finding ATENCAO 'Não foi possível consultar o Bootstrap Token.'
    elif /usr/bin/grep -Eiq 'escrowed to server:[[:space:]]*YES' "$EVID/bootstrap.txt"; then finding OK 'Bootstrap Token consta como depositado no servidor.'
    elif /usr/bin/grep -Eiq 'supported on server:[[:space:]]*NO' "$EVID/bootstrap.txt"; then finding INFO 'O servidor não anuncia suporte ao Bootstrap Token.'
    elif /usr/bin/grep -Eiq 'escrowed to server:[[:space:]]*NO' "$EVID/bootstrap.txt"; then finding ATENCAO 'Bootstrap Token não consta como depositado. Pode afetar atualizações e autorizações de operações gerenciadas.'
    else finding ATENCAO 'O estado do Bootstrap Token não pôde ser interpretado.'; fi
    evidence bootstrap 'Estado do Bootstrap Token'
    [ "$(rc_of profiles)" = 0 ] || finding ATENCAO 'Não foi possível listar os perfis instalados.'
    evidence profiles 'Perfis de configuração do computador e dos usuários'
    if [ "$(rc_of apsd)" = 0 ] && /usr/bin/grep -Eq 'state = running' "$EVID/apsd.txt"; then finding OK 'O processo apsd está em execução para notificações Apple.'
    else finding ATENCAO 'O apsd não foi identificado em execução. Investigue o serviço e os eventos APNs se houver comandos MDM pendentes.'; fi
}
# Faixa 100.64.0.0/10: adaptador do túnel Zscaler e IPs sintéticos do ZPA.
ZPA_RANGE='100[.](6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])[.]'
# Estado do Zscaler lido das evidências; o túnel também nomeia interfaces no DNS e na rota.
zscaler_state() {
    local line
    ZS_TUNNEL_IF='' ZS_TUNNEL_IP='' ZS_SERVICE=0 ZS_TUNNEL_PROC=0 ZS_TRAY=0 ZS_EXT='' ZS_EXT_STATE=''
    [ -n "$ZSCALER_APP" ] || return 0
    line="$(/usr/bin/awk -v range="^$ZPA_RANGE" '/^[a-z0-9]+: flags=/ {ifn = $1; sub(/:$/, "", ifn)}
        ifn ~ /^utun/ && $1 == "inet" && $2 ~ range {print ifn "|" $2; exit}' "$EVID/interfaces.txt" 2>/dev/null)"
    if [ -n "$line" ]; then ZS_TUNNEL_IF="${line%%|*}" ZS_TUNNEL_IP="${line#*|}"; fi
    if /usr/bin/grep -Eq '/ZscalerService$' "$EVID/processes.txt" 2>/dev/null; then ZS_SERVICE=1; fi
    if /usr/bin/grep -Eq '/ZscalerTunnel$|com\.zscaler\.[A-Za-z.]*Tunnel$' "$EVID/processes.txt" 2>/dev/null; then ZS_TUNNEL_PROC=1; fi
    if /usr/bin/grep -Eq '/Zscaler\.app/Contents/MacOS/Zscaler$' "$EVID/processes.txt" 2>/dev/null; then ZS_TRAY=1; fi
    # Com mais de uma extensão Zscaler (ex.: versão antiga aguardando remoção), vale a mais ativa.
    line="$(/usr/bin/awk '/com\.zscaler/ {
            for (i = 1; i <= NF; i++) if ($i ~ /^com\.zscaler/) {id = $i; v = $(i + 1); sub(/\/.*$/, ")", v)}
            s = $0; sub(/^.*\[/, "", s); sub(/\].*$/, "", s)
            score = (s == "activated enabled") ? 3 : (s ~ /^activated/ ? 2 : 1)
            if (score > best) {best = score; pick = id " " v "|" s}}
        END {if (pick != "") print pick}' "$EVID/sysext.txt" 2>/dev/null)"
    if [ -n "$line" ]; then ZS_EXT="${line%%|*}" ZS_EXT_STATE="${line#*|}"; fi
}
# Interface com o tipo de conexão: en0 (Wi-Fi), utun4 (túnel Zscaler).
iface_label() {
    local port
    [ -n "$1" ] || return 0
    if [ "$1" = "$ZS_TUNNEL_IF" ]; then printf '%s (túnel Zscaler)' "$1"; return 0; fi
    port="$(/usr/bin/awk -v dev="$1" '/^\(Hardware Port: / {p = $0; sub(/^\(Hardware Port: /, "", p); d = p
        sub(/, Device: .*$/, "", p); sub(/^.*, Device: /, "", d); sub(/\)$/, "", d); if (d == dev) {print p; exit}}' "$EVID/network_services.txt" 2>/dev/null)"
    if [ -n "$port" ]; then printf '%s (%s)' "$1" "$port"
    else case "$1" in utun*|ipsec*|ppp*) printf '%s (túnel/VPN)' "$1" ;; *) printf '%s' "$1" ;; esac; fi
}
# Campo da rede Wi-Fi atual no system_profiler (bloco "Current Network Information").
wifi_value() {
    /usr/bin/awk -v key="$1" '/Current Network Information:/ {on = 1; next} /Other Local Wi-Fi Networks:/ {on = 0}
        on {l = $0; sub(/^[ \t]+/, "", l); if (index(l, key ":") == 1) {sub(/^[^:]+:[ \t]*/, "", l); print l; exit}}' "$EVID/wifi_radio.txt" 2>/dev/null
}
summary_value() {
    /usr/bin/awk -v key="$1" '{l = $0; sub(/^[ \t]+/, "", l)} index(l, key " : ") == 1 {print substr(l, length(key) + 4); exit}' "$EVID/wifi_summary.txt" 2>/dev/null
}
proxy_value() { /usr/bin/awk -v key="$1" '$1 == key && $2 == ":" {print $3; exit}' "$EVID/proxy.txt" 2>/dev/null; }
# Wi-Fi: rede, segurança, canal, sinal e origem do endereço; o SSID aparece se o macOS não o ocultar.
analyze_wifi() {
    local out_if="$1" status ssid security channel signal rssi='' noise='' snr='' rate method connected=0 wifi=''
    if [ -n "$WIFI_DEV" ]; then
        status="$(/usr/bin/awk '{l = $0; sub(/^[ \t]+/, "", l)} index(l, "Status:") == 1 {sub(/^Status:[ \t]*/, "", l); print l; exit}' "$EVID/wifi_radio.txt" 2>/dev/null)"
        if [ "$status" = Connected ] || [ "$(summary_value LinkStatusActive)" = TRUE ]; then connected=1; fi
    fi
    if [ "$connected" = 1 ]; then
        ssid="$(/usr/bin/awk '/Current Network Information:/ {if ((getline n) > 0) {sub(/^[ \t]+/, "", n); sub(/:$/, "", n); print n}; exit}' "$EVID/wifi_radio.txt" 2>/dev/null)"
        case "$ssid" in ''|'<redacted>') ssid="$(summary_value SSID)" ;; esac
        [ "$ssid" != '<redacted>' ] || ssid=''
        # O nome da rede é definido por terceiros: sem caracteres de controle no Terminal.
        ssid="$(printf '%s' "$ssid" | /usr/bin/tr -d '\000-\037\177')"
        security="$(wifi_value Security)"; [ -n "$security" ] || security="$(summary_value Security)"
        channel="$(join_parts "$(wifi_value Channel)" "$(wifi_value 'PHY Mode')")"
        signal="$(wifi_value 'Signal / Noise')"; rate="$(wifi_value 'Transmit Rate')"
        read -r rssi _ _ noise _ <<<"$signal"
        [[ "$rssi" =~ ^-[0-9]+$ ]] || rssi=''
        if [ -n "$rssi" ] && [[ "$noise" =~ ^-[0-9]+$ ]]; then snr=$((rssi - noise)); fi
        method="$(summary_value ConfigMethod)"
        detail 'Wi-Fi' "Conectado ($WIFI_DEV)"
        detail 'Rede Wi-Fi (SSID)' "${ssid:-Oculto pelo macOS (privacidade de localização)}"
        detail 'Segurança do Wi-Fi' "$security"
        detail 'Canal e padrão' "$channel"
        detail 'Sinal / ruído' "$signal${snr:+ (SNR $snr dB)}"
        [ -z "$rate" ] || detail 'Taxa de transmissão' "$rate Mbps"
        [ -z "$method" ] || detail 'Endereço IPv4 do Wi-Fi' "$method"
        if [ -n "$rssi" ] && [ "$rssi" -le -75 ]; then
            finding ATENCAO "Sinal Wi-Fi fraco ($rssi dBm${snr:+, SNR $snr dB}). Pode causar lentidão, quedas do túnel Zscaler e falhas em downloads."
        elif [ -n "$snr" ] && [ "$snr" -lt 15 ]; then
            finding ATENCAO "Relação sinal/ruído baixa no Wi-Fi (SNR $snr dB). Interferência pode causar perda de pacotes e quedas de conexão."
        fi
        wifi="$(join_parts "Wi-Fi ($WIFI_DEV)" "$ssid" "$security" "${rssi:+sinal $rssi dBm}")"
    elif [ -n "$WIFI_DEV" ]; then
        case "$status" in Off) detail 'Wi-Fi' "Desligado ($WIFI_DEV)" ;; *) detail 'Wi-Fi' "Sem conexão ($WIFI_DEV)" ;; esac
    fi
    if [ -z "$out_if" ]; then fact 'Rede' "$(join_parts 'Sem rota padrão' "$wifi")"
    elif [ "$out_if" = "$WIFI_DEV" ] && [ -n "$wifi" ]; then fact 'Rede' "$wifi"
    elif [ "$out_if" = "$WIFI_DEV" ]; then fact 'Rede' "$(iface_label "$out_if")"
    else fact 'Rede' "$(join_parts "$(iface_label "$out_if")" "${wifi:+Wi-Fi também conectado}")"; fi
}
# Resolvedores do scutil --dns: tipo|domínio|servidores|interface|domínios de busca.
dns_resolvers() {
    /usr/bin/awk '
        function flush() {
            if (inres && ns != "") print (sec == "scoped" ? "scoped" : (dom == "" ? "default" : "domain")) "|" dom "|" ns "|" ifn "|" search
            inres = 0; dom = ""; ns = ""; ifn = ""; search = ""
        }
        function value(s) {sub(/^[^:]*:[ \t]*/, "", s); return s}
        /^DNS configuration \(for scoped/ {flush(); sec = "scoped"; next}
        /^DNS configuration/ {flush(); sec = "main"; next}
        /^resolver #/ {flush(); inres = 1; next}
        /^[ \t]+domain[ \t]*:/ {dom = value($0)}
        /^[ \t]+nameserver\[/ {ns = ns (ns == "" ? "" : ", ") value($0)}
        /^[ \t]+search domain\[/ {search = search (search == "" ? "" : ", ") value($0)}
        /^[ \t]+if_index[ \t]*:/ {v = value($0); if (match(v, /\(.*\)/)) ifn = substr(v, RSTART + 1, RLENGTH - 2)}
        END {flush()}' "$EVID/dns_config.txt" 2>/dev/null
}
# DNS em uso, origem no Wi-Fi (DHCP ou manual), split DNS por domínio e DNS de outras interfaces.
analyze_dns() {
    local kind dom servers ifn search def='' def_servers='' def_if='' manual='' dhcp='' origin n=0
    dns_resolvers >"$EVID/dns_resolvers.txt"
    def="$(/usr/bin/awk -F'|' '$1 == "default" {print; exit}' "$EVID/dns_resolvers.txt")"
    if [ -n "$def" ]; then IFS='|' read -r kind dom def_servers def_if search <<<"$def"; fi
    if [ -n "$WIFI_DEV" ]; then
        manual="$(/usr/bin/awk '/^[0-9A-Fa-f.:]+$/ {printf "%s%s", (n++ ? ", " : ""), $0}' "$EVID/wifi_dns_manual.txt" 2>/dev/null)"
        dhcp="$(/usr/bin/awk '/domain_name_server/ {v = $0; sub(/^.*\{/, "", v); sub(/\}.*$/, "", v); print v; exit}' "$EVID/wifi_summary.txt" 2>/dev/null)"
    fi
    detail 'DNS em uso' "${def_servers:-Nenhum servidor padrão}"
    [ -z "$def_if" ] || detail 'Interface do DNS em uso' "$(iface_label "$def_if")"
    [ -z "$search" ] || detail 'Domínios de busca' "$search"
    if [ -n "$manual" ]; then detail 'DNS do Wi-Fi' "Configurado manualmente: $manual"
    elif [ -n "$dhcp" ]; then detail 'DNS do Wi-Fi' "Recebido por DHCP: $dhcp"; fi
    while IFS='|' read -r kind dom servers ifn search; do
        case "$kind" in
            domain) n=$((n + 1))
                [ "$n" -gt 15 ] || detail "DNS para $dom" "$servers${ifn:+ via $(iface_label "$ifn")}" ;;
            scoped) [ -z "$ifn" ] || [ "$ifn" = "$def_if" ] || detail "DNS de $(iface_label "$ifn")" "$servers" ;;
        esac
    done <"$EVID/dns_resolvers.txt"
    [ "$n" -le 15 ] || detail 'Outros domínios com DNS próprio' "$((n - 15))"
    origin=''
    if [ -n "$def_if" ] && [ "$def_if" = "$ZS_TUNNEL_IF" ]; then origin='túnel Zscaler'
    elif [ -n "$ZSCALER_APP" ] && printf '%s\n' "$def_servers" | /usr/bin/grep -Eq "(^|[ ,])$ZPA_RANGE"; then origin='Zscaler (100.64.0.0/10)'
    elif [ -n "$def_if" ] && [ "$def_if" = "$WIFI_DEV" ]; then
        if [ -n "$manual" ]; then origin="Wi-Fi ($WIFI_DEV), manual"
        elif [ -n "$dhcp" ]; then origin="Wi-Fi ($WIFI_DEV), DHCP"
        else origin="Wi-Fi ($WIFI_DEV)"; fi
    else origin="$(iface_label "$def_if")"; fi
    if [ -n "$def_servers" ]; then fact 'DNS' "$(join_parts "$def_servers" "$origin")"
    else
        fact 'DNS' 'Nenhum servidor DNS padrão'
        finding ATENCAO 'Nenhum servidor DNS padrão configurado. Sem DNS, o Mac não resolve o Jamf, a nuvem Zscaler nem os serviços Apple.'
    fi
    if [ -n "$manual" ]; then
        finding INFO "DNS do Wi-Fi configurado manualmente ($manual). Ele substitui o DNS entregue pela rede e pode impedir a resolução de nomes internos."
    fi
    evidence dns_config 'Resolvedores DNS do macOS: servidores, domínios e interfaces'
}
analyze_network() {
    local rc http value msg out_if gw
    section 'Rede, Wi-Fi, DNS e comunicação com o Jamf Pro' 'Rede'
    zscaler_state
    ZPA_JAMF=0
    out_if="$(/usr/bin/awk '$1 == "interface:" {print $2; exit}' "$EVID/route.txt" 2>/dev/null)"
    gw="$(/usr/bin/awk '$1 == "gateway:" {print $2; exit}' "$EVID/route.txt" 2>/dev/null)"
    [ -z "$out_if" ] || detail 'Saída padrão' "$(join_parts "$(iface_label "$out_if")" "${gw:+gateway $gw}")"
    analyze_wifi "$out_if"
    analyze_dns
    evidence network 'Interfaces ativas e endereços de rede'
    evidence route 'Rota padrão, gateway e interface de saída'
    [ -z "$WIFI_DEV" ] || evidence wifi_radio 'Wi-Fi: rede atual, canal, segurança e sinal'
    [ -z "$WIFI_DEV" ] || evidence wifi_summary 'Wi-Fi: endereço, roteador e DNS recebidos por DHCP'
    [ "$(rc_of network)" = 0 ] || finding ATENCAO 'Não foi possível consultar o estado das interfaces de rede.'
    [ "$(rc_of route)" = 0 ] || finding ATENCAO 'Rota padrão IPv4/IPv6 não identificada. Confira se existe uma rota específica para o servidor Jamf.'
    if [ "$(rc_of proxy)" = 0 ] && /usr/bin/grep -Eq '(HTTPEnable|HTTPSEnable|SOCKSEnable|ProxyAutoConfigEnable|ProxyAutoDiscoveryEnable)[[:space:]]*:[[:space:]]*1' "$EVID/proxy.txt"; then
        [ "$(proxy_value ProxyAutoConfigEnable)" != 1 ] || detail 'Proxy automático (PAC)' "$(proxy_value ProxyAutoConfigURLString)"
        [ "$(proxy_value HTTPSEnable)" != 1 ] || detail 'Proxy HTTPS' "$(proxy_value HTTPSProxy):$(proxy_value HTTPSPort)"
        finding INFO 'Há proxy ou descoberta automática de proxy configurada. Se houver falha de conexão ou TLS, confira esse caminho de rede.'
    fi
    evidence proxy 'Proxy configurado no macOS'
    if [ "$URL_VALID" != 1 ]; then
        fact 'Servidor Jamf' 'URL não identificada'
        finding ATENCAO 'URL HTTPS do Jamf não identificada em formato válido. Configuração ausente ou incorreta pode impedir a comunicação; use --jamf-url para testar o destino esperado.'
        return
    fi
    detail 'Servidor testado' "$URL_HOST"
    detail 'Porta HTTPS' "$URL_PORT"
    value="$(/usr/bin/awk '/^(ip_address|ipv6_address):/ {printf "%s%s", (n++ ? ", " : ""), $2}' "$EVID/dns.txt" 2>/dev/null)"
    # IP sintético do ZPA: a resposta de DNS vem do Zscaler, não do DNS da rede.
    if [ -n "$ZSCALER_APP" ] && printf '%s\n' "$value" | /usr/bin/grep -Eq "(^|[ ,])$ZPA_RANGE"; then ZPA_JAMF=1; fi
    msg="$URL_HOST"; [ "$URL_PORT" = 443 ] || msg="$URL_HOST:$URL_PORT"
    if [ "$ZPA_JAMF" = 1 ]; then fact 'Servidor Jamf' "$msg · via ZPA ($value)"; else fact 'Servidor Jamf' "$msg"; fi
    if [ "$(rc_of dns)" = 0 ] && [ -n "$value" ]; then
        if [ "$ZPA_JAMF" = 1 ]; then detail 'IP do Jamf' "$value (IP sintético do ZPA, resolvido pelo Zscaler)"; else detail 'IP do Jamf' "$value"; fi
        finding OK 'DNS do servidor Jamf resolvido pelo macOS.'
    else finding ATENCAO 'O resolvedor local não retornou IP para o Jamf. DNS corporativo, VPN ou resolução pelo proxy podem estar envolvidos.'; fi
    evidence dns 'Endereços resolvidos para o servidor'
    rc="$(rc_of https)"
    http="$(/usr/bin/awk -F= '/^http_code=/{print $2}' "$EVID/https.txt" | /usr/bin/tail -n 1)"
    if [ "$rc" = 0 ]; then
        finding OK 'Conexão HTTPS estabelecida com validação TLS pelo curl do macOS.'
        case "$http" in
            2??|3??) detail 'Resposta HTTP' "$http" ;;
            401|403) finding ATENCAO "Servidor respondeu HTTP $http. O endpoint pode exigir autenticação ou estar bloqueado pelo proxy/servidor." ;;
            5??) finding ATENCAO "Servidor respondeu HTTP $http. Pode haver falha no Jamf Pro, proxy ou balanceador." ;;
            *) finding ATENCAO "Servidor respondeu HTTP ${http:-desconhecido}. Confira a URL e o endpoint configurado." ;;
        esac
    else
        # A mensagem do curl entra no achado: o Terminal não exibe as evidências.
        msg="$(excerpt https first)"
        case "$rc" in
            5|6) finding FALHA "Falha de resolução DNS no teste HTTPS${msg:+ ($msg)}. Verifique DNS e conexão com a rede/VPN corporativa." ;;
            7) finding FALHA "Conexão ao servidor/porta recusada ou indisponível${msg:+ ($msg)}. Firewall, rota, VPN ou serviço fora do ar podem estar envolvidos." ;;
            28|124) finding ATENCAO "O servidor não respondeu ao teste HTTPS em tempo hábil${msg:+ ($msg)}. Investigue conectividade, proxy e disponibilidade do Jamf Pro." ;;
            35|51|58|60|77|83|90|91) finding FALHA "Falha TLS ou de certificado no HTTPS (curl $rc${msg:+: $msg}). Verifique validade, nome do servidor, cadeia de confiança, relógio e inspeção HTTPS." ;;
            *) finding ATENCAO "Teste HTTPS não concluído (curl $rc${msg:+: $msg}). Veja a resposta nos detalhes da rede." ;;
        esac
        [ "$AGENT_CONN_FAILED" != 1 ] || START_HINT='Rede — o teste HTTPS direto ao servidor também falhou, o que pode explicar a falha de comunicação do agente.'
    fi
    evidence https 'Resposta HTTPS, IP remoto e tempos de conexão em segundos'
    if [ "$rc" = 0 ]; then
        value="$(/usr/bin/awk -F= '/^time_total=/{print $2}' "$EVID/https.txt")"
        if /usr/bin/awk -v t="$value" 'BEGIN {exit !(t+0>=8)}'; then finding ATENCAO "Resposta HTTPS levou ${value}s. Lentidão de rede ou servidor pode afetar operações do agente."; fi
    fi
}
# Zscaler Client Connector (serviço, extensão, túnel e saída pela nuvem) e VPNs do macOS.
analyze_zscaler() {
    local rc msg headline node='' service internet='' name status label others=''
    section 'Zscaler e VPN' 'Zscaler/VPN'
    if [ -z "$ZSCALER_APP" ]; then
        fact 'Zscaler' 'Não instalado'
        finding ATENCAO 'Zscaler Client Connector não encontrado em /Applications/Zscaler. Sem o cliente, o tráfego não passa pelo Zscaler e aplicações internas publicadas pelo ZPA ficam inacessíveis.'
    else
        detail 'Zscaler Client Connector' "${ZSCALER_VERSION:-Versão indisponível}"
        detail 'Aplicativo' "$ZSCALER_APP"
        if [ "$ZS_SERVICE" = 1 ]; then
            service='serviço ativo'
            finding OK 'Serviço do Zscaler Client Connector (ZscalerService) em execução.'
        else
            service='serviço parado'
            finding FALHA 'O serviço ZscalerService não está em execução. Sem ele, o Client Connector não protege nem encaminha o tráfego, inclusive para aplicações do ZPA.'
        fi
        [ -z "$ZS_EXT" ] || detail 'Extensão de rede' "$ZS_EXT — $ZS_EXT_STATE"
        case "$ZS_EXT_STATE" in
            'activated enabled') finding OK 'Extensão de rede do Zscaler ativada e habilitada.' ;;
            '') if [ "$ZS_TUNNEL_PROC" = 1 ]; then finding OK 'Processo de túnel do Zscaler em execução.'
                else finding ATENCAO 'Nenhuma extensão de rede ou processo de túnel do Zscaler ativo. O tráfego pode não estar passando pelo túnel.'; fi ;;
            *) finding ATENCAO "Extensão de rede do Zscaler em estado \"$ZS_EXT_STATE\". Aprovação pendente em Ajustes do Sistema ou ausência do perfil MDM de extensões impede o túnel." ;;
        esac
        if [ -n "$ZS_TUNNEL_IF" ]; then detail 'Interface do túnel' "$ZS_TUNNEL_IF ($ZS_TUNNEL_IP)"
        else finding INFO 'Nenhuma interface de túnel do Zscaler (utun com 100.64.x.x) encontrada. Se a empresa usa o ZPA para aplicações internas, o usuário pode não estar autenticado nele.'; fi
        if [ -n "$CONSOLE_USER" ] && [ "$ZS_TRAY" = 0 ]; then
            finding INFO 'O aplicativo Zscaler não está aberto na sessão do usuário. Pelo ícone na barra de menus é possível conferir o estado do ZIA/ZPA e autenticar.'
        fi
        rc="$(rc_of zscaler_check)"
        if [ "$rc" = 0 ]; then
            # Conteúdo externo: excerpt remove caracteres de controle e limita o tamanho.
            headline="$(excerpt zscaler_check first)"
            msg="$(/usr/bin/awk '/arriving at this server from the IP address/ {print $NF; exit}' "$EVID/zscaler_check.txt")"
            [[ ! "$msg" =~ ^[0-9A-Fa-f.:]+$ ]] || detail 'IP público de saída' "$msg"
            if printf '%s\n' "$headline" | /usr/bin/grep -Eq '^You are accessing .* via .*Zscaler'; then
                node="${headline##* via }"; node="${node%.}"
                detail 'Saída para a internet' "$node"
                internet="internet via $node"
                finding OK "O tráfego de internet passa pelo Zscaler ($node)."
            elif [ -n "$headline" ]; then
                internet='internet sem Zscaler'
                finding ATENCAO "ip.zscaler.com indica que o tráfego não passa pelo Zscaler (resposta: $headline). O ZIA pode estar desligado, em pausa, sem login ou em rede confiável configurada para saída direta."
            else finding ATENCAO 'A resposta de ip.zscaler.com não foi reconhecida. Confira no navegador se o tráfego passa pelo Zscaler.'; fi
        else
            if [ "$rc" = 124 ]; then msg='sem resposta em tempo hábil'
            else msg="$(excerpt zscaler_check first)"; msg="curl $rc${msg:+: $msg}"; fi
            finding ATENCAO "Não foi possível consultar ip.zscaler.com ($msg). Sem essa resposta, não há confirmação de que a internet passa pelo Zscaler."
        fi
        evidence zscaler_check 'Resposta de ip.zscaler.com: nó Zscaler e IP público de saída'
        if [ "$URL_VALID" = 1 ] && [ "$ZPA_JAMF" = 1 ]; then
            finding INFO "O Jamf ($URL_HOST) resolve para um IP sintético do ZPA (100.64.0.0/10): a resposta de DNS vem do Zscaler, não do DNS da rede, e a comunicação com o Jamf depende do túnel ZPA ativo e autenticado."
        fi
        fact 'Zscaler' "$(join_parts "$ZSCALER_VERSION" "$service" "${ZS_TUNNEL_IF:+túnel $ZS_TUNNEL_IF}" "$internet")"
        /usr/bin/awk 'NR == 1 || tolower($0) ~ /zscaler/' "$EVID/processes.txt" >"$EVID/zscaler_processes.txt"
        evidence zscaler_processes 'Processos do Zscaler presentes na coleta'
    fi
    [ "$(rc_of sysext)" = 0 ] || [ -z "$ZSCALER_APP" ] || finding ATENCAO 'Não foi possível listar as extensões de sistema do macOS.'
    evidence sysext 'Extensões de sistema de rede e segurança'
    # Conexões do macOS (scutil --nc): nome entre aspas e estado entre parênteses.
    /usr/bin/awk '/^[* ]*\([A-Za-z ]+\)/ {s = $0; sub(/^[^(]*\(/, "", s); sub(/\).*$/, "", s); n = "sem nome"
        if (match($0, /"[^"]*"/)) n = substr($0, RSTART + 1, RLENGTH - 2); print n "|" s}' "$EVID/vpn.txt" >"$EVID/vpn_services.txt" 2>/dev/null
    if [ -s "$EVID/vpn_services.txt" ]; then
        while IFS='|' read -r name status; do
            case "$status" in
                Connected) label='conectada' ;; Disconnected) label='desconectada' ;;
                Connecting) label='conectando' ;; Disconnecting) label='desconectando' ;; *) label="$status" ;;
            esac
            detail 'VPN cadastrada' "$name — $label"
            if [ "$status" = Connected ] && ! printf '%s' "$name" | /usr/bin/grep -qi zscaler; then others="${others:+$others, }$name"; fi
        done <"$EVID/vpn_services.txt"
    else detail 'VPNs do macOS' 'Nenhuma cadastrada (o Zscaler usa extensão de rede e não aparece nesta lista)'; fi
    if [ -n "$others" ] && [ "$ZS_SERVICE" = 1 ]; then finding INFO "VPN conectada junto com o Zscaler: $others. Dois túneis ativos podem disputar rotas e DNS."
    elif [ -n "$others" ]; then finding INFO "VPN conectada: $others."; fi
    evidence vpn 'Conexões VPN cadastradas no sistema'
    /usr/bin/awk 'NR <= 4 || $1 == "default" || /utun|ipsec|ppp/' "$EVID/routes.txt" 2>/dev/null | /usr/bin/head -n 80 >"$EVID/routes_tunnel.txt"
    evidence routes_tunnel 'Rotas padrão e rotas por túneis (utun, ipsec, ppp)'
}

date_epoch() { /bin/date -j -u -f '%b %e %T %Y %Z' "$1" '+%s' 2>/dev/null; }
certificate_state() {
    local begin="$1" end="$2" now="$3"
    CERT_STATE='Não determinado' CERT_DAYS=''
    [[ "$begin" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ && "$now" =~ ^[0-9]+$ ]] || return 1
    CERT_DAYS=$(((end - now) / 86400))
    if [ "$begin" -gt "$now" ]; then CERT_STATE='Ainda não válido'
    elif [ "$end" -le "$now" ]; then CERT_STATE='Expirado'
    elif [ "$((end - now))" -le 2592000 ]; then CERT_STATE='Vence em até 30 dias'
    else CERT_STATE='Dentro da validade'; fi
}
split_certificates() {
    /usr/bin/awk -v dir="$2" '
        /-----BEGIN CERTIFICATE-----/ {n++;file=sprintf("%s/cert-%04d.pem",dir,n);active=1}
        active {print > file}
        /-----END CERTIFICATE-----/ {close(file);active=0}' "$1"
}
inspect_certificate() {
    local pem="$1" scope="$2" identity_file="$3" subject issuer start end begin_epoch end_epoch sha1 sha256 serial related=no identity=no
    subject="$(/usr/bin/openssl x509 -in "$pem" -noout -subject -nameopt RFC2253 2>/dev/null)" || return 1
    issuer="$(/usr/bin/openssl x509 -in "$pem" -noout -issuer -nameopt RFC2253 2>/dev/null)"
    start="$(/usr/bin/openssl x509 -in "$pem" -noout -startdate 2>/dev/null)"; start="${start#notBefore=}"
    end="$(/usr/bin/openssl x509 -in "$pem" -noout -enddate 2>/dev/null)"; end="${end#notAfter=}"
    begin_epoch="$(date_epoch "$start")"; end_epoch="$(date_epoch "$end")"
    certificate_state "$begin_epoch" "$end_epoch" "$(/bin/date +%s)" || CERT_STATE='Data não interpretada'
    sha1="$(/usr/bin/openssl x509 -in "$pem" -noout -sha1 -fingerprint 2>/dev/null)"; sha1="${sha1#*=}"
    sha1="$(printf '%s' "$sha1" | /usr/bin/tr -d ':')"
    sha256="$(/usr/bin/openssl x509 -in "$pem" -noout -sha256 -fingerprint 2>/dev/null)"; sha256="${sha256#*=}"
    serial="$(/usr/bin/openssl x509 -in "$pem" -noout -serial 2>/dev/null)"; serial="${serial#serial=}"
    if [ -n "$identity_file" ] && [ -n "$sha1" ] && /usr/bin/grep -Fiq "$sha1" "$identity_file"; then identity=yes; fi
    if printf '%s\n%s\n' "$subject" "$issuer" | /usr/bin/grep -Eiq 'jamf|casper|jss built|mdm|scep|zscaler'; then related=yes; fi
    [ "$scope" != 'Chaveiro Jamf' ] || related=yes
    CERT_TOTAL=$((CERT_TOTAL + 1))
    if [ "$scope" = 'Servidor Jamf — conexão TLS direta' ]; then CERT_SERVER_ISSUER="${issuer#issuer=}"
    elif printf '%s\n' "$subject" | /usr/bin/grep -Fiq zscaler; then
        ZS_CA_N=$((ZS_CA_N + 1))
        [ "$CERT_STATE" = 'Dentro da validade' ] || ZS_CA_BAD=$((ZS_CA_BAD + 1))
        ZS_CA_LIST="$ZS_CA_LIST$scope|$(cert_cn "${subject#subject=}")|$CERT_STATE|$end
"
    fi
    {
        printf '\nCertificado %s | %s\n' "$CERT_TOTAL" "$scope"
        printf '  Titular: %s\n  Emissor: %s\n' "${subject#subject=}" "${issuer#issuer=}"
        printf '  Início (GMT): %s\n  Vencimento (GMT): %s\n  Estado temporal: %s\n' "$start" "$end" "$CERT_STATE"
        [ -z "$CERT_DAYS" ] || printf '  Dias até o vencimento: %s\n' "$CERT_DAYS"
        printf '  Serial do certificado: %s\n  SHA-256: %s\n' "$serial" "$sha256"
        if [ "$scope" != 'Servidor Jamf — conexão TLS direta' ]; then
            printf '  Identidade SSL cliente com chave associada: %s\n' "$identity"
            printf '  Origem ou nome sugere vínculo com Jamf/MDM/SCEP/Zscaler: %s\n' "$related"
        fi
    } >>"$EVID/certificates_details.txt"
    case "$CERT_STATE" in
        Expirado|'Ainda não válido')
            CERT_INVALID=$((CERT_INVALID + 1))
            if [ "$scope" = 'Servidor Jamf — conexão TLS direta' ]; then
                finding ATENCAO "Certificado apresentado na conexão TLS direta: $CERT_STATE ($end). Confira a publicação do certificado, o relógio e a validação HTTPS."
            elif [ "$related" = yes ] || [ "$identity" = yes ]; then
                finding ATENCAO "Certificado em $scope: $CERT_STATE. Titular ${subject#subject=}; emissor ${issuer#issuer=}. Se estiver em uso, pode afetar autenticação, MDM, Wi-Fi ou VPN."
            fi ;;
        'Vence em até 30 dias')
            CERT_SOON=$((CERT_SOON + 1))
            if [ "$related" = yes ] || [ "$identity" = yes ] || [ "$scope" = 'Servidor Jamf — conexão TLS direta' ]; then
                finding ATENCAO "Certificado em $scope vence em ${CERT_DAYS} dia(s): ${subject#subject=}. Verifique a renovação do certificado em uso."
            fi ;;
        'Data não interpretada') finding ATENCAO "Validade não interpretada de certificado em $scope: ${subject#subject=}." ;;
    esac
    return 0
}
analyze_certificates() {
    local key scope identities dir pem before count cn state end issuer_cn
    section 'Certificados e identidades' 'Certificados'
    CERT_TOTAL=0 CERT_INVALID=0 CERT_SOON=0 CERT_SERVER_ISSUER='' ZS_CA_N=0 ZS_CA_BAD=0 ZS_CA_LIST=''
    : >"$EVID/certificates_details.txt"
    for key in cert_jamf cert_system cert_user tls_chain; do
        case "$key" in
            cert_jamf) [ "$JAMF_KEYCHAIN" = 1 ] || continue; scope='Chaveiro Jamf'; identities="$EVID/identities_jamf.txt" ;;
            cert_system) scope='Chaveiro Sistema'; identities="$EVID/identities_system.txt" ;;
            cert_user) [ "$USER_KEYCHAIN" = 1 ] || continue; scope="Chaveiro de $CONSOLE_USER"; identities="$EVID/identities_user.txt" ;;
            tls_chain) [ "$URL_VALID" = 1 ] || continue; scope='Servidor Jamf — conexão TLS direta'; identities='' ;;
        esac
        if [ "$key" != tls_chain ] && [ "$(rc_of "$key")" != 0 ]; then
            if [ "$(rc_of "$key")" = 44 ] && /usr/bin/grep -Eiq 'specified item could not be found|errSecItemNotFound' "$EVID/$key.txt"; then
                detail "$scope" 'Nenhum certificado encontrado'
                [ "$key" != cert_jamf ] || finding ATENCAO 'O chaveiro Jamf não retornou certificados. Confira a identidade usada pelo agente para autenticação.'
                continue
            fi
            finding ATENCAO "Consulta de certificados indisponível em $scope. O chaveiro pode estar bloqueado ou inacessível à sessão."
            continue
        fi
        dir="$OUT/$key-pem"
        /bin/mkdir "$dir" || continue
        split_certificates "$EVID/$key.txt" "$dir"
        before=$CERT_TOTAL
        for pem in "$dir"/*.pem; do
            [ -f "$pem" ] || continue
            inspect_certificate "$pem" "$scope" "$identities" || finding ATENCAO "Um certificado em $scope não pôde ser interpretado."
            [ "$key" != tls_chain ] || break
        done
        count=$((CERT_TOTAL - before))
        detail "$scope" "$count certificado(s) analisado(s)"
        if [ "$key" = cert_jamf ]; then
            evidence jamf_keychain_info 'Arquivo do chaveiro de autenticação do agente Jamf'
            [ "$count" -gt 0 ] || finding ATENCAO 'O chaveiro Jamf foi localizado, mas nenhum certificado pôde ser analisado. Confira a integridade do chaveiro e a identidade do agente.'
        fi
        if [ "$key" = tls_chain ] && [ "$count" = 0 ]; then
            finding ATENCAO 'Não foi possível obter o certificado por TLS direto. Rede, proxy obrigatório ou negociação TLS podem estar envolvidos.'
        fi
        if [ -n "$identities" ]; then
            evidence "identities_${key#cert_}" "Identidades SSL cliente — $scope"
            [ "$(rc_of "identities_${key#cert_}")" = 0 ] || finding ATENCAO "Não foi possível consultar identidades SSL cliente em $scope."
        fi
    done
    if [ -n "$JAMF" ] && [ "$JAMF_KEYCHAIN" = 0 ]; then finding ATENCAO 'Chaveiro JAMF.keychain não localizado nos caminhos padrão. Se a autenticação por certificado estiver habilitada, a ausência da identidade pode impedir a comunicação do agente.'; fi
    if [ -n "$CONSOLE_USER" ] && [ "$USER_KEYCHAIN" = 0 ]; then finding INFO 'Chaveiro login do usuário não localizado no caminho padrão.'; fi
    detail 'Total analisado' "$CERT_TOTAL"
    detail 'Fora da validade' "$CERT_INVALID"
    detail 'Vencem em até 30 dias' "$CERT_SOON"
    if [ "$CERT_TOTAL" -gt 0 ] && [ "$CERT_INVALID" = 0 ] && [ "$CERT_SOON" = 0 ]; then
        finding OK 'Os certificados consultados estão dentro da validade e não vencem nos próximos 30 dias.'
    fi
    # CA do Zscaler: necessária quando a inspeção SSL está ativa; vencida, quebra o HTTPS inspecionado.
    while IFS='|' read -r scope cn state end; do
        [ -z "$scope" ] || detail "Certificado Zscaler — $scope" "$cn · $state · vence $end"
    done <<EOF
$ZS_CA_LIST
EOF
    if [ "$ZS_CA_N" -gt 0 ] && [ "$ZS_CA_BAD" = 0 ]; then finding OK "CA do Zscaler instalada e dentro da validade ($ZS_CA_N certificado(s))."
    elif [ "$ZS_CA_N" = 0 ] && [ -n "$ZSCALER_APP" ]; then
        detail 'Certificado Zscaler' 'Nenhum nos chaveiros consultados (esperado sem inspeção SSL)'
    fi
    # Emissor Zscaler na cadeia do Jamf indica inspeção SSL no caminho até o servidor.
    if printf '%s\n' "$CERT_SERVER_ISSUER" | /usr/bin/grep -Fiq zscaler; then
        issuer_cn="$(cert_cn "$CERT_SERVER_ISSUER")"
        detail 'Inspeção SSL no Jamf' "Sim — emissor $issuer_cn"
        case "$(rc_of https)" in
            35|51|58|60|77|83|90|91)
                finding ATENCAO "A cadeia TLS do Jamf é emitida pelo Zscaler ($issuer_cn) e o teste HTTPS falhou por certificado. A CA do Zscaler pode não ser confiável neste Mac ou faltar exceção de inspeção SSL para o Jamf."
                START_HINT='Certificados — a conexão com o Jamf passa por inspeção SSL do Zscaler e o HTTPS falhou por certificado; confira a CA do Zscaler e a exceção de inspeção para o Jamf.' ;;
            *) finding ATENCAO "A conexão TLS com o Jamf é inspecionada pelo Zscaler ($issuer_cn). A Apple não suporta inspeção HTTPS nos serviços de MDM e APNs; confirme a exceção (bypass) de inspeção SSL para o Jamf e os domínios Apple." ;;
        esac
    elif [ -n "$CERT_SERVER_ISSUER" ] && [ -n "$ZSCALER_APP" ]; then
        finding OK 'A cadeia TLS obtida do Jamf não é emitida pelo Zscaler: sem inspeção SSL visível nesse caminho.'
    fi
    note 'Jamf/MDM/SCEP/Zscaler no titular/emissor é uma pista de vínculo. Certificados antigos podem permanecer instalados; confirme a identidade em uso antes de associar um vencimento ao problema.'
    evidence certificates_details 'Titular, emissor, validade, serial e impressão digital de cada certificado'
}
age_text() {
    if [ "$1" -lt 60 ]; then printf 'agora há pouco'
    elif [ "$1" -lt 3600 ]; then printf 'há %s min' $(($1 / 60))
    elif [ "$1" -lt 172800 ]; then printf 'há %s h' $(($1 / 3600))
    else printf 'há %s dias' $(($1 / 86400)); fi
}
# Horário de uma linha do jamf.log em LOG_WHEN e idade em segundos em LOG_AGE.
log_when() {
    local mon day clock now year epoch
    [[ "$1" =~ ^((Mon|Tue|Wed|Thu|Fri|Sat|Sun)[[:space:]]+)?(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[[:space:]]+([0-9]{1,2})[[:space:]]+([0-9]{2}:[0-9]{2}:[0-9]{2}) ]] || return 1
    mon="${BASH_REMATCH[3]}" day="${BASH_REMATCH[4]}" clock="${BASH_REMATCH[5]}"
    now="$(/bin/date +%s)" year="$(/bin/date +%Y)"
    epoch="$(/bin/date -j -f '%Y %b %d %T' "$year $mon $day $clock" '+%s' 2>/dev/null)"
    # O jamf.log não registra o ano: uma data futura pertence ao ano anterior.
    if [[ "$epoch" =~ ^[0-9]+$ ]] && [ "$epoch" -gt $((now + 86400)) ]; then
        epoch="$(/bin/date -j -f '%Y %b %d %T' "$((year - 1)) $mon $day $clock" '+%s' 2>/dev/null)"
    fi
    [[ "$epoch" =~ ^[0-9]+$ ]] || return 1
    LOG_AGE=$((now - epoch))
    LOG_WHEN="$(/bin/date -j -r "$epoch" '+%d/%m/%Y %H:%M') ($(age_text "$LOG_AGE"))"
}
# Indício no jamf.log com quantidade e última ocorrência; após 7 dias vira observação.
log_rule() {
    local count last level=ATENCAO when='horário não identificado'
    count="$(/usr/bin/grep -Eic -- "$1" "$EVID/jamf_log.txt")"
    [[ "$count" =~ ^[1-9][0-9]*$ ]] || return 0
    last="$(/usr/bin/grep -Ei -- "$1" "$EVID/jamf_log.txt" | /usr/bin/tail -n 1)"
    if log_when "$last"; then
        when="última em $LOG_WHEN"
        [ "$LOG_AGE" -le 604800 ] || level=INFO
    fi
    finding "$level" "$2 — $count ocorrência(s), $when. $3"
}
analyze_logs() {
    local last
    section 'Histórico dos logs' 'Histórico'
    if [ "$NO_LOGS" = 1 ]; then
        detail 'Coleta de logs' 'Desativada por --no-logs'
        fact 'Último check-in' 'Não coletado (--no-logs)'
        return
    fi
    if [ "$(rc_of jamf_log)" = 0 ]; then
        detail 'Última escrita jamf.log' "$(/bin/cat "$EVID/jamf_log_date.txt")"
        last="$(/usr/bin/grep -F 'Checking for policies triggered by' "$EVID/jamf_log.txt" | /usr/bin/tail -n 1)"
        if [ -z "$last" ]; then
            detail 'Último check-in' 'Não encontrado no trecho coletado'
            fact 'Último check-in' 'Não encontrado no jamf.log'
            finding INFO 'Nenhuma busca de políticas (check-in) no trecho coletado do jamf.log.'
        elif log_when "$last"; then
            detail 'Último check-in' "$LOG_WHEN"
            fact 'Último check-in' "$LOG_WHEN"
            if [ "$LOG_AGE" -gt 86400 ]; then
                finding ATENCAO "Último check-in no jamf.log: $LOG_WHEN. Se o Mac esteve ligado e conectado nesse período, o check-in recorrente pode não estar ocorrendo."
            fi
        else
            detail 'Último check-in' 'Horário não identificado'
            fact 'Último check-in' 'Horário não identificado no jamf.log'
        fi
        note 'Cada indício traz a quantidade e a última ocorrência no trecho coletado. Com mais de 7 dias, aparece como INFO. Compare o horário com o problema relatado.'
        log_rule 'Device Signature Error|Device signature (does not match|error)|invalid device signature' 'jamf.log registra erro de assinatura do dispositivo' 'Uma identidade local divergente ou inválida pode impedir autenticação do agente.'
        log_rule 'certificate.*(expired|invalid|not trusted)|SSL.*(error|fail)|unable to get local issuer|certificate verify failed' 'jamf.log registra erro TLS/certificado' 'Compare emissor, validade, relógio e confiança no certificado do servidor.'
        log_rule 'Could not resolve|cannot resolve|unable to resolve|name resolution' 'jamf.log registra falha de resolução de nomes' 'Pode haver indisponibilidade do DNS corporativo ou da VPN.'
        log_rule 'timed out|could not connect|connection refused|network is unreachable' 'jamf.log registra falhas de conexão' 'Investigue quedas de rede, firewall, proxy e disponibilidade do servidor.'
        log_rule 'no space left|disk.*full|not enough.*(space|disk)' 'jamf.log registra falta de espaço' 'Downloads ou instalações podem ter sido interrompidos por armazenamento insuficiente.'
        log_rule 'installation failed|installer.*(failed|error)|package.*(failed|not found)|error.*(download|mount)' 'jamf.log registra falha de pacote, instalação ou download' 'Confira o pacote, o ponto de distribuição e o install.log.'
        log_rule 'Unauthorized|Forbidden|HTTP[^0-9]*(401|403)' 'jamf.log registra acesso negado' 'Autenticação do dispositivo ou bloqueio no servidor/proxy podem estar envolvidos.'
        /usr/bin/grep -Ei 'error|failed|failure|certificate|timed out|signature|no space|could not|unable to' "$EVID/jamf_log.txt" | /usr/bin/tail -n 40 >"$EVID/jamf_events.txt"
        if [ -s "$EVID/jamf_events.txt" ]; then evidence jamf_events 'Eventos relevantes no trecho coletado do jamf.log'
        else finding OK 'Nenhum erro reconhecido no trecho coletado do jamf.log.'; fi
    else
        fact 'Último check-in' 'jamf.log indisponível'
        finding ATENCAO 'jamf.log ausente ou ilegível. O histórico do agente não pôde ser analisado.'
    fi
    if [ "$(rc_of install_log)" = 0 ]; then
        /usr/bin/grep -Ein 'error|failed|failure|no space|not enough' "$EVID/install_log.txt" | /usr/bin/tail -n 25 >"$EVID/install_events.txt"
        if [ -s "$EVID/install_events.txt" ]; then
            finding ATENCAO 'Há eventos de erro no histórico recente do instalador. Confira os horários e os pacotes envolvidos.'
            evidence install_events 'Eventos recentes do instalador'
        fi
    fi
    if [ "$DEEP" = 1 ]; then
        [ "$(rc_of mdm_log)" = 0 ] || finding ATENCAO 'A consulta de eventos MDM/APNs não foi concluída.'
        /usr/bin/grep -Ei 'error|failed|failure|certificate|disconnect|timed out|denied' "$EVID/mdm_log.txt" | /usr/bin/tail -n 60 >"$EVID/mdm_events.txt"
        if [ -s "$EVID/mdm_events.txt" ]; then
            finding ATENCAO 'Eventos MDM/APNs recentes contêm termos de erro ou desconexão. Verifique se coincidem com os comandos pendentes.'
            evidence mdm_events 'Eventos MDM/APNs/Jamf dos últimos 15 minutos'
        elif [ "$(rc_of mdm_log)" = 0 ]; then finding OK 'Nenhum termo de erro reconhecido nos eventos MDM/APNs dos últimos 15 minutos.'; fi
    fi
}

level_label() {
    case "$1" in FALHA) printf 'FALHA' ;; ATENCAO) printf 'ATENÇÃO' ;; OK) printf 'OK' ;; INFO) printf 'OBSERVAÇÃO' ;; *) printf 'NÃO VERIFICADO' ;; esac
}
level_color() {
    case "$1" in FALHA) printf '%s' "$RED" ;; ATENCAO) printf '%s' "$YELLOW" ;; OK) printf '%s' "$GREEN" ;; INFO) printf '%s' "$BLUE" ;; esac
}
level_mark() {
    case "$1" in FALHA) printf '✖' ;; ATENCAO) printf '▲' ;; OK) printf '✔' ;; INFO) printf '•' ;; *) printf '–' ;; esac
}
plural() {
    [ "$1" -gt 0 ] || return 0
    if [ "$1" -eq 1 ]; then printf '1 %s' "$2"; else printf '%s %s' "$1" "$3"; fi
}
# Pior nível encontrado na área e contagem por tipo de achado, para o painel.
area_status() {
    local i="$1"
    AREA_LEVEL=NONE
    [ "${AREA_INFO[i]:-0}" -eq 0 ] || AREA_LEVEL=INFO
    [ "${AREA_OK[i]:-0}" -eq 0 ] || AREA_LEVEL=OK
    [ "${AREA_WARN[i]:-0}" -eq 0 ] || AREA_LEVEL=ATENCAO
    [ "${AREA_FAIL[i]:-0}" -eq 0 ] || AREA_LEVEL=FALHA
    AREA_COUNTS="$(join_parts "$(plural "${AREA_FAIL[i]:-0}" falha falhas)" "$(plural "${AREA_WARN[i]:-0}" atenção atenções)" \
        "$(plural "${AREA_OK[i]:-0}" OK OK)" "$(plural "${AREA_INFO[i]:-0}" observação observações)")"
}
area_index() {
    local i=1 tab=$'\t' out=''
    while [ "$i" -le "$SECTION_N" ]; do out="${out:+$out$tab}${AREA_NAMES[i]}"; i=$((i + 1)); done
    printf '%s' "$out"
}
# Resumo por gravidade; achados.txt mantém a ordem da análise.
sorted_issues() {
    local level
    for level in FALHA ATENCAO INFO; do /usr/bin/grep "^\[$level\] " "$ISSUES"; done
    return 0
}
result_status() {
    STATUS_LEVEL=OK STATUS_TEXT='Sem falha confirmada nas verificações'
    [ "$WARNINGS" -eq 0 ] || { STATUS_LEVEL=ATENCAO; STATUS_TEXT='Há pontos que precisam de atenção'; }
    [ "$FAILS" -eq 0 ] || { STATUS_LEVEL=FALHA; STATUS_TEXT='Foram encontradas falhas'; }
}
HTML_ESC='function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);gsub(/"/,"\\&quot;",s);return s}'

write_reports() {
    local i
    result_status
    {
        printf 'DIAGNÓSTICO JAMF PRO • %s\n%s\n' "$VERSION" "$GENERATED_AT"
        [ -z "$REPORT_SUBJECT" ] || printf '%s\n' "$REPORT_SUBJECT"
        printf '\nRESULTADO: %s\n' "$STATUS_TEXT"
        printf 'Falhas: %s | Atenções: %s | Verificações OK: %s\n' "$FAILS" "$WARNINGS" "$OKS"
        [ -z "$START_HINT" ] || printf 'Por onde começar: %s\n' "$START_HINT"
        printf '\n## Visão geral\n\n'
        i=0
        while [ "$i" -lt "${#FACT_LABELS[@]}" ]; do kv_line "${FACT_LABELS[i]}" "${FACT_VALUES[i]}"; i=$((i + 1)); done
        printf '\n## Situação por área\n\n'
        i=1
        while [ "$i" -le "$SECTION_N" ]; do
            area_status "$i"
            kv_line "${AREA_NAMES[i]}" "$(level_label "$AREA_LEVEL")${AREA_COUNTS:+ ($AREA_COUNTS)}"
            i=$((i + 1))
        done
        printf '\n## O que pode estar acontecendo\n\n'
        if /usr/bin/grep -Eq '^\[(FALHA|ATENCAO|INFO)\] ' "$ISSUES"; then sorted_issues
        else printf '[OK] Nenhuma falha ou atenção reconhecida na coleta.\n'; fi
        /bin/cat "$BODY"
        printf '\nRelatório HTML: %s/relatorio.html\nEvidências da coleta: %s\n' "$OUT" "$EVID"
    } >"$REPORT" || return 1
    {
        cat <<'HTML'
<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Diagnóstico Jamf Pro</title>
<style>
:root{color-scheme:light;--bg:#f1f5f9;--card:#fff;--ink:#182538;--muted:#526378;--line:#dce4ed;--blue:#075985;--green:#14613d;--amber:#854d0e;--red:#a82132}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}main{max-width:1120px;margin:auto;padding:48px 28px}header{padding:36px;border-radius:22px;background:#102a43;color:#f0f7ff;margin-bottom:24px}header p{color:#bfdbed;margin:4px 0}header p.subject{color:#f0f7ff;font-size:18px;font-weight:600}header p.status{display:inline-block;margin-top:16px;padding:6px 16px;border-radius:20px;font-weight:700;color:#fff;background:#334e68}header p.FALHA{background:#b42335}header p.ATENCAO{background:#94600c}header p.OK{background:#17703f}h1{font-size:36px;line-height:1.2;letter-spacing:-1px;margin:8px 0 14px}.eyebrow{font-size:12px;font-weight:700;letter-spacing:2px}
nav{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px}a{color:var(--blue);text-decoration:none}nav a{background:var(--card);border:1px solid var(--line);border-radius:22px;padding:7px 15px;font-size:13px}a:hover{text-decoration:underline}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:24px 0}.card,section{background:var(--card);border:1px solid var(--line);border-radius:16px;padding:25px}.card strong{display:block;font-size:36px;line-height:1.2}.card span{font-size:13px;color:var(--muted)}.bad strong{color:var(--red)}.warn strong{color:var(--amber)}.good strong{color:var(--green)}
.hint{margin:0 0 24px;padding:14px 18px;background:var(--card);border:1px solid var(--line);border-left:4px solid var(--red);border-radius:12px}.hint b{display:block;font-size:11px;letter-spacing:.6px;text-transform:uppercase;color:var(--red)}
section{margin:18px 0}h2{font-size:21px;line-height:1.3;margin:0 0 20px;letter-spacing:-.3px}
.facts{display:grid;grid-template-columns:1fr 1fr;gap:0 28px;margin:0}.facts div{display:grid;grid-template-columns:140px 1fr;gap:12px;padding:8px 0;border-bottom:1px solid var(--line)}dt{color:var(--muted);font-size:13px}dd{margin:0;font-weight:600;overflow-wrap:anywhere}
.areas{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px}.area{display:block;padding:12px 14px;border:1px solid var(--line);border-top:4px solid var(--line);border-radius:12px;color:var(--ink)}.area:hover{text-decoration:none;background:var(--bg)}.area b,.area span{display:block}.area span{font-size:12px;font-weight:700;letter-spacing:.6px;color:var(--muted)}.area small{font-size:12px;color:var(--muted)}.area.FALHA{border-top-color:var(--red)}.area.FALHA span{color:var(--red)}.area.ATENCAO{border-top-color:var(--amber)}.area.ATENCAO span{color:var(--amber)}.area.OK{border-top-color:var(--green)}.area.OK span{color:var(--green)}.area.INFO{border-top-color:var(--blue)}.area.INFO span{color:var(--blue)}
.finding{border-left:3px solid var(--line);padding:10px 14px;margin:10px 0;border-radius:0 8px 8px 0;background:var(--bg);overflow-wrap:anywhere}.finding b{font-size:11px;letter-spacing:.6px;margin-right:10px}.tag{display:inline-block;margin-right:10px;padding:0 9px;border:1px solid var(--line);border-radius:10px;font-size:12px;font-weight:600;color:var(--muted);background:var(--card)}.finding.FALHA{border-color:var(--red)}.finding.FALHA b{color:var(--red)}.finding.ATENCAO{border-color:var(--amber)}.finding.ATENCAO b{color:var(--amber)}.finding.OK{border-color:var(--green)}.finding.OK b{color:var(--green)}.finding.INFO{border-color:var(--blue)}.finding.INFO b{color:var(--blue)}
.kv{display:grid;grid-template-columns:minmax(140px,240px) 1fr;gap:14px;padding:6px 0;border-bottom:1px solid var(--line);font-size:14px;overflow-wrap:anywhere}.kv span:first-child{color:var(--muted)}.note{margin:12px 0;font-size:13px;color:var(--muted)}
details{border:1px solid var(--line);border-radius:10px;margin:15px 0}summary{cursor:pointer;font-size:13px;font-weight:600;padding:12px 16px}pre{margin:0;padding:16px;border-top:1px solid var(--line);white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--bg);border-radius:0 0 10px 10px}footer{font-size:12px;color:var(--muted);padding:16px 0;overflow-wrap:anywhere}
@media(prefers-color-scheme:dark){:root{color-scheme:dark;--bg:#111c28;--card:#192838;--ink:#e2eaf2;--muted:#b1c3d4;--line:#34495e;--blue:#8acbec;--green:#85d3a8;--amber:#f0ca7b;--red:#ff9caa}}
@media(max-width:700px){main{padding:20px 12px}header,section{padding:22px}h1{font-size:29px}.card{padding:15px}.card strong{font-size:28px}.facts{grid-template-columns:1fr}.facts div,.kv{grid-template-columns:1fr;gap:0}}
@media print{:root{--bg:#fff;--card:#fff;--ink:#111;--muted:#444;--line:#ccc}main{max-width:none;padding:0}header{background:#fff;color:#111;border-bottom:2px solid #111;border-radius:0;padding:12px 0}header p,header p.subject{color:#444}header p.status{color:#111;background:#fff;border:1px solid #111}nav{display:none}h2,summary{break-after:avoid}details pre{display:block}details{break-inside:auto}.finding,.area{break-inside:avoid}a{color:#111}}
</style></head><body><main>
HTML
        printf '%s\n' "$VERSION" "$GENERATED_AT" "$REPORT_SUBJECT" "$STATUS_TEXT" | /usr/bin/awk -v level="$STATUS_LEVEL" "$HTML_ESC"'
            {v[NR] = esc($0)}
            END {print "<header><div class=eyebrow>SUPORTE · macOS · JAMF PRO " v[1] "</div><h1>Diagnóstico do computador</h1>"
                if (v[3] != "") print "<p class=subject>" v[3] "</p>"
                print "<p>" v[2] "</p><p class=\"status " level "\">" v[4] "</p></header>"}'
        printf '<div class="cards"><div class="card bad"><strong>%s</strong><span>Falhas encontradas</span></div><div class="card warn"><strong>%s</strong><span>Pontos de atenção</span></div><div class="card good"><strong>%s</strong><span>Verificações OK</span></div></div>\n' "$FAILS" "$WARNINGS" "$OKS"
        [ -z "$START_HINT" ] || printf '%s\n' "$START_HINT" | /usr/bin/awk "$HTML_ESC"'{print "<p class=hint><b>Por onde começar</b>" esc($0) "</p>"}'
        {
            printf 'achados\tAchados\nvisao-geral\tVisão geral\n'
            i=1
            while [ "$i" -le "$SECTION_N" ]; do printf 'sec-%s\t%s\n' "$i" "${AREA_NAMES[i]}"; i=$((i + 1)); done
        } | /usr/bin/awk -F'\t' "$HTML_ESC"'
            BEGIN {printf "<nav aria-label=\"Seções do relatório\">"}
            {printf "<a href=\"#%s\">%s</a>", $1, esc($2)}
            END {print "</nav>"}'
        i=1
        while [ "$i" -le "$SECTION_N" ]; do
            area_status "$i"
            printf '%s\t%s\t%s\t%s\t%s\n' "$i" "$AREA_LEVEL" "$(level_label "$AREA_LEVEL")" "${AREA_NAMES[i]}" "${AREA_COUNTS:-Sem verificações}"
            i=$((i + 1))
        done | /usr/bin/awk -F'\t' "$HTML_ESC"'
            BEGIN {print "<section id=\"areas\"><h2>Situação por área</h2><div class=areas>"}
            {print "<a class=\"area " $2 "\" href=\"#sec-" $1 "\"><b>" esc($4) "</b><span>" esc($3) "</span><small>" esc($5) "</small></a>"}
            END {print "</div></section>"}'
        sorted_issues | /usr/bin/awk -v areas="$(area_index)" "$HTML_ESC"'
            BEGIN {n = split(areas, list, "\t"); for (i = 1; i <= n; i++) id[list[i]] = i
                print "<section id=\"achados\"><h2>O que pode estar acontecendo</h2>"}
            {level = $0; sub(/^\[/, "", level); sub(/\].*$/, "", level); rest = $0; sub(/^\[[^]]+\] /, "", rest)
                p = index(rest, ": "); area = (p ? substr(rest, 1, p - 1) : ""); msg = (p ? substr(rest, p + 2) : rest)
                label = level; if (level == "ATENCAO") label = "ATENÇÃO"
                tag = ""; if (area in id) tag = "<a class=tag href=\"#sec-" id[area] "\">" esc(area) "</a>"; else if (area != "") tag = "<span class=tag>" esc(area) "</span>"
                print "<div class=\"finding " level "\"><b>" label "</b>" tag esc(msg) "</div>"; count++}
            END {if (!count) print "<div class=\"finding OK\"><b>OK</b>Nenhuma falha ou atenção reconhecida na coleta.</div>"
                print "</section>"}'
        i=0
        while [ "$i" -lt "${#FACT_LABELS[@]}" ]; do printf '%s\t%s\n' "${FACT_LABELS[i]}" "${FACT_VALUES[i]}"; i=$((i + 1)); done | /usr/bin/awk -F'\t' "$HTML_ESC"'
            BEGIN {print "<section id=\"visao-geral\"><h2>Visão geral</h2><dl class=facts>"}
            {print "<div><dt>" esc($1) "</dt><dd>" esc($2) "</dd></div>"}
            END {print "</dl></section>"}'
        /usr/bin/awk "$HTML_ESC"'
            !open && !/^## / {next}
            /^## / && !raw {if(open)print "</section>";n++;print "<section id=\"sec-" n "\"><h2>" esc(substr($0,4)) "</h2>";open=1;next}
            /^>>> / && !raw {print "<details><summary>" esc(substr($0,5)) "</summary><pre>";raw=1;next}
            /^<<<$/ && raw {print "</pre></details>";raw=0;next}
            raw {print esc($0);next}
            /^\[(OK|FALHA|ATENCAO|INFO)\] / {level=$0;sub(/^\[/,"",level);sub(/\].*$/,"",level);line=$0;sub(/^\[[^]]+\] /,"",line);label=level;if(level=="ATENCAO")label="ATENÇÃO";print "<div class=\"finding " level "\"><b>" label "</b>" esc(line) "</div>";next}
            /^  [^ :][^:]*: / {p=index($0,": ");key=substr($0,3,p-3);value=substr($0,p+2);sub(/^ +/,"",value);print "<div class=kv><span>" esc(key) "</span><span>" esc(value) "</span></div>";next}
            NF {print "<p class=note>" esc($0) "</p>"}
            END {if(raw)print "</pre></details>";if(open)print "</section>"}' "$BODY"
        printf '%s\n' "$VERSION" "$OUT" | /usr/bin/awk "$HTML_ESC"'
            NR==1 {v = esc($0)}
            NR==2 {print "<footer>Coleta local de diagnóstico · ferramentas nativas do macOS · versão " v "<br>Pasta da coleta: " esc($0) "</footer></main></body></html>"}'
    } >"$OUT/relatorio.html"
}
heading() { printf '\n%s%s%s\n' "$BOLD$BLUE" "$1" "$RESET"; }
# Quebra por palavras com recuo; cores e bytes de continuação UTF-8 não ocupam coluna.
wrap_lines() {
    /usr/bin/awk -v w="$WRAP_WIDTH" -v first="$1" -v rest="$2" '
        function width(s) {gsub(/\033\[[0-9;]*m/, "", s); gsub(/[\200-\277]/, "", s); return length(s)}
        {
            n = split($0, word, " "); line = first; used = width(first); empty = 1
            for (i = 1; i <= n; i++) {
                if (!empty && used + 1 + width(word[i]) > w) {print line; line = rest; used = width(rest); empty = 1}
                line = line (empty ? "" : " ") word[i]; used += (empty ? 0 : 1) + width(word[i]); empty = 0
            }
            print line
        }'
}
show_findings() {
    local level="$1" count line color mark
    count="$(/usr/bin/grep -c "^\[$level\] " "$ISSUES")"
    [ "$count" -gt 0 ] 2>/dev/null || return 0
    color="$(level_color "$level")" mark="$(level_mark "$level")"
    heading "$2 ($count)"
    /usr/bin/sed -n "s/^\[$level\] //p" "$ISSUES" | while IFS= read -r line; do
        printf '%s\n' "$BOLD${line%%: *}:$RESET ${line#*: }" | wrap_lines "  $color$mark$RESET " '    '
    done
}
# Terminal: resultado, dados principais, painel por área e achados por gravidade.
show_summary() {
    local i cols
    cols="$(/usr/bin/tput cols 2>/dev/null)"
    if [ ! -t 1 ] || ! [[ "$cols" =~ ^[0-9]+$ ]]; then cols=100; fi
    [ "$cols" -le 120 ] || cols=120
    [ "$cols" -ge 60 ] || cols=60
    WRAP_WIDTH=$((cols - 2))
    printf '\n%s%s RESULTADO: %s%s\n' "$BOLD$(level_color "$STATUS_LEVEL")" "$(level_mark "$STATUS_LEVEL")" "$STATUS_TEXT" "$RESET"
    printf '  %s falha(s) · %s atenção(ões) · %s verificação(ões) OK\n' "$FAILS" "$WARNINGS" "$OKS"
    [ -z "$START_HINT" ] || printf '%s\n' "${BOLD}Por onde começar:$RESET $START_HINT" | wrap_lines '  ' '  '
    heading 'Visão geral'
    i=0
    while [ "$i" -lt "${#FACT_LABELS[@]}" ]; do
        printf '  %s%s\n' "$(padded 19 "${FACT_LABELS[i]}")" "${FACT_VALUES[i]}"
        i=$((i + 1))
    done
    heading 'Situação por área'
    i=1
    while [ "$i" -le "$SECTION_N" ]; do
        area_status "$i"
        printf '  %s%s%s%s%s\n' "$(padded 17 "${AREA_NAMES[i]}")" "$(level_color "$AREA_LEVEL")" \
            "$(padded 17 "$(level_mark "$AREA_LEVEL") $(level_label "$AREA_LEVEL")")" "$RESET" "$AREA_COUNTS"
        i=$((i + 1))
    done
    show_findings FALHA 'Falhas'
    show_findings ATENCAO 'Pontos de atenção'
    show_findings INFO 'Observações'
    if [ "$FAILS" -eq 0 ] && [ "$WARNINGS" -eq 0 ]; then
        printf '\n%s%s Nenhuma falha ou atenção reconhecida na coleta.%s\n' "$GREEN" "$(level_mark OK)" "$RESET"
    fi
    heading 'Relatórios'
    printf '  %s%s\n' "$(padded 8 HTML)" "$OUT/relatorio.html"
    printf '  %s%s\n' "$(padded 8 Texto)" "$REPORT"
    if [ "${REPORT_OWNER:-root}" != root ]; then
        printf '  %s%s\n' "$(padded 8 Abrir)" "open \"$OUT/relatorio.html\""
        printf '  Relatórios liberados para %s; as evidências continuam restritas a root.\n' "$REPORT_OWNER"
    else
        printf '  %s%s\n' "$(padded 8 Ler)" "sudo cat \"$REPORT\""
        printf '  A pasta e os relatórios pertencem a root.\n'
    fi
}
# Permite que quem invocou sudo abra os dois relatórios; evidências seguem root.
handoff_reports() {
    REPORT_OWNER='root'
    if [[ "${SUDO_UID:-}" =~ ^[1-9][0-9]*$ ]] && [ -n "${SUDO_USER:-}" ] && [ "$(/usr/bin/id -u "$SUDO_USER" 2>/dev/null)" = "$SUDO_UID" ]; then
        if /usr/sbin/chown "$SUDO_UID" "$REPORT" "$OUT/relatorio.html" "$OUT"; then REPORT_OWNER="$SUDO_USER"; fi
    fi
}
main() {
    local base=/private/tmp stamp
    URL_OVERRIDE='' DEEP=0 NO_LOGS=0 NO_COLOR_FLAG=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --help|-h) usage; return 0 ;;
            --output-base|--jamf-url)
                [ "$#" -ge 2 ] && [ -n "$2" ] || die "Falta valor para $1."
                case "$1" in
                    --output-base) base="$2" ;;
                    --jamf-url) URL_OVERRIDE="$2"; parse_url "$2" || die 'URL inválida. Use HTTPS com DNS/IPv4, sem credenciais, query ou fragmento.' ;;
                esac
                shift 2 ;;
            --deep) DEEP=1; shift ;;
            --no-logs) NO_LOGS=1; shift ;;
            --no-color) NO_COLOR_FLAG=1; shift ;;
            *) die "Opção desconhecida: $1. Use --help." ;;
        esac
    done
    [ "$(/usr/bin/uname -s)" = Darwin ] || die 'Este script requer macOS.'
    [ "$EUID" -eq 0 ] || die 'Execute com sudo /bin/bash ./jamf-diagnostico.sh.'
    case "$base" in /*) ;; *) base="$PWD/$base" ;; esac
    [ -d "$base" ] || die 'A pasta --output-base precisa existir.'
    stamp="$(/bin/date '+%Y%m%d-%H%M%S')"
    OUT="$(/usr/bin/mktemp -d "$base/jamf-diagnostico-$stamp.XXXXXX")" || die 'Não foi possível criar a pasta de saída.'
    EVID="$OUT/evidencias" REPORT="$OUT/relatorio.txt" BODY="$OUT/conteudo.txt" ISSUES="$OUT/achados.txt"
    /bin/mkdir "$EVID" || die 'Não foi possível criar a pasta de evidências.'
    : >"$BODY"; : >"$ISSUES"
    init_findings
    ACTIVE_PID='' ACTIVE_GUARD=''
    GENERATED_AT="$(/bin/date '+Coletado em %d/%m/%Y às %H:%M:%S %Z (%z)')"
    init_colors
    trap interrupted INT TERM
    printf '\n%sDIAGNÓSTICO JAMF PRO%s  %s\nColeta local • computador, gerenciamento, rede, Zscaler e certificados\n\n' "$BOLD$BLUE" "$RESET" "$VERSION"
    collect_machine
    collect_management
    collect_network
    collect_certificates
    collect_logs
    progress 6 'Analisando computador, agente, MDM, rede e Zscaler'
    analyze_machine
    analyze_management
    analyze_network
    analyze_zscaler
    progress 7 'Analisando validade dos certificados e possíveis causas'
    analyze_certificates
    analyze_logs
    progress 8 'Gerando os relatórios HTML e texto'
    write_reports || die "Não foi possível salvar os relatórios em $OUT. Verifique espaço e permissões."
    handoff_reports
    show_summary
    trap - INT TERM
    [ "$FAILS" -eq 0 ]
}
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main "$@"; fi
