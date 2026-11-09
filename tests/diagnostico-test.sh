#!/bin/bash
# Verificação sem sudo: usa fixtures, não consulta nem altera gerenciamento real.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/jamf-diagnostico.sh"
TEST_ROOT="$(/usr/bin/mktemp -d /private/tmp/jamf-test.XXXXXX)" || exit 1
trap '/bin/rm -rf "$TEST_ROOT"' EXIT
fail() { printf 'FALHOU: %s\n' "$*" >&2; exit 1; }
assert_eq() { [ "$1" = "$2" ] || fail "$3 (obtido: $1; esperado: $2)"; }
has() { /usr/bin/grep -Fq -- "$2" "$1" || fail "Ausente em $1: $2"; }
lacks() { if /usr/bin/grep -Fq -- "$2" "$1"; then fail "Inesperado em $1: $2"; fi; }
put() { printf '%s\n' "$3" >"$EVID/$1.txt"; printf '%s\n' "$2" >"$EVID/$1.rc"; }
# Horário no formato do jamf.log, relativo ao momento do teste (ex.: -2H, -20d).
log_stamp() { /bin/date "-v$1" '+%a %b %d %H:%M:%S'; }
fixture() {
    OUT="$TEST_ROOT/$1" EVID="$TEST_ROOT/$1/evidencias"
    /bin/mkdir -p "$EVID"
    REPORT="$OUT/relatorio.txt" BODY="$OUT/conteudo.txt" ISSUES="$OUT/achados.txt"
    : >"$BODY"; : >"$ISSUES"
    init_findings
    CONSOLE_USER=usuario.teste JAMF=/mock/jamf URL_VALID=1 URL_HOST=jamf.example.test URL_PORT=443
    USER_KEYCHAIN=1 JAMF_KEYCHAIN=1 NO_LOGS=0 DEEP=1
    WIFI_DEV=en0 WIFI_SERVICE=Wi-Fi ZSCALER_APP=/Applications/Zscaler/Zscaler.app ZSCALER_VERSION=4.8.0.281
    GENERATED_AT='AMOSTRA SIMULADA • 06/11/2026 15:00:00 -0300'
    put hardware 0 'Hardware:
    Model Name: MacBook Pro
    Model Identifier: Mac14,5
    Chip: Apple M2 Max
    Memory: 32 GB
    Serial Number (system): SERIAL-FICTICIO
    Hardware UUID: 00000000-0000-0000-0000-000000000000'
    put computer_name 0 'Mac de demonstração'
    put architecture 0 arm64
    put system 0 'ProductName: macOS
ProductVersion: 15.7
BuildVersion: 24G000'
    put uptime 0 '15:00 up 2 days, 1 user, load averages: 1.2 1.1 1.0'
    put user 0 'RealName: Usuário de demonstração
UniqueID: 501
NFSHomeDirectory: /Users/usuario.teste'
    put user_admin 0 'user is not a member of the group'
    put secure_token 0 'Secure token is ENABLED for user usuario.teste'
    put disk 0 'Filesystem Size Used Avail Capacity iused ifree %iused Mounted on
/dev/disk3s5 460Gi 120Gi 300Gi 29% 1 1 1% /System/Volumes/Data'
    put disk_info 0 'File System Personality: APFS'
    put filevault 0 'FileVault is On.'
    put battery 0 'Now drawing from AC Power'
    put power 0 'Condition: Normal'
    put time_auto 0 'Network Time: On'
    put time_server 0 'Network Time Server: time.apple.com'
    put jamf_version 0 'version=11.0.0'
    put jamf_connection 0 'The JSS is available.'
    put jamf_signature 0 'valid on disk'
    printf '1\tcom.jamfsoftware.task.fixture\t/Library/LaunchDaemons/fixture.plist\n' >"$EVID/services.tsv"
    put service_1 0 'state = not running
last exit code = 0'
    put launch_disabled 0 '"com.jamfsoftware.task.fixture" => enabled'
    put processes 0 'PID PPID USER ELAPSED COMM
100 1 root 01:00 /usr/sbin/apsd
200 1 root 01:00 /Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerService
201 1 root 01:00 /Library/SystemExtensions/X/com.zscaler.zscaler.TRPTunnel.systemextension/Contents/MacOS/com.zscaler.zscaler.TRPTunnel
202 1 usuario.teste 01:00 /Applications/Zscaler/Zscaler.app/Contents/MacOS/Zscaler'
    put enrollment 0 'Enrolled via DEP: Yes
MDM enrollment: Yes (User Approved)'
    put bootstrap 0 'Bootstrap Token supported on server: YES
Bootstrap Token escrowed to server: YES'
    put profiles 0 'Computer Level: 3 configuration profiles are installed'
    put apsd 0 'state = running'
    put network 0 'IPv4 network interface information
 en0 : flags : 0x5 (IPv4,DNS)
 address : 192.0.2.10'
    put route 0 'gateway: 192.0.2.1
interface: en0'
    put proxy 0 '<dictionary> {}'
    put vpn 0 'Available network connection services in the current set:'
    put interfaces 0 'en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1350
	inet 100.64.0.1 --> 100.64.0.1 netmask 0xffff0000'
    put routes 0 'Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.0.2.1          UGScg                 en0
100.64/16          100.64.0.1         UGSc                utun4
192.0.2/24         link#12            UCS                   en0'
    put network_services 0 'An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en7)'
    put dns_config 0 'DNS configuration

resolver #1
  search domain[0] : corp.example.test
  nameserver[0] : 192.0.2.53
  nameserver[1] : 192.0.2.54
  if_index : 12 (en0)
  flags    : Request A records

resolver #2
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.0.2.53
  nameserver[1] : 192.0.2.54
  if_index : 12 (en0)
  flags    : Scoped, Request A records'
    put wifi_summary 0 '<dictionary> {
  IPv4 : <array> {
    0 : <dictionary> {
      ConfigMethod : DHCP
domain_name_server (ip_mult): {192.0.2.53, 192.0.2.54}
    }
  }
  InterfaceType : WiFi
  LinkStatusActive : TRUE
  SSID : <redacted>
  Security : WPA2_8021X
}'
    put wifi_dns_manual 0 "There aren't any DNS Servers set on Wi-Fi."
    put wifi_radio 0 '      Interfaces:
        en0:
          Card Type: Wi-Fi
          Status: Connected
          Current Network Information:
            <redacted>:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 40MHz)
              Security: WPA2 Enterprise
              Signal / Noise: -60 dBm / -95 dBm
              Transmit Rate: 573'
    put sysext 0 '1 extension(s)
--- com.apple.system_extension.network_extension
enabled	active	teamID	bundleID (version)	name	[state]
*	*	PCBCQZJ7S7	com.zscaler.zscaler.TRPTunnel (4.8.0.281/abc123)	TRPTunnel	[activated enabled]'
    put zscaler_check 0 'You are accessing the Internet via Zscaler Cloud: Sao Paulo IV in the zscalertwo.net cloud.
Your request is arriving at this server from the IP address 198.51.100.20
The Zscaler proxy virtual IP is 198.51.100.1.'
    put dns 0 'name: jamf.example.test
ip_address: 192.0.2.100'
    put https 0 'http_code=200
remote_ip=192.0.2.100
ssl_verify_result=0
time_total=0.200000'
    put jamf_log 0 "$(log_stamp -20M) Mac jamf[100]: Checking for policies triggered by \"recurring check-in\" for user \"usuario.teste\"..."
    put install_log 0 'Nov 6 15:00:00 Mac installer: Installation completed successfully'
    put jamf_log_date 0 '06/11/2026 15:00:00 -0300'
    put mdm_log 0 'MDM command completed'
    put cert_system 0 "$(/bin/cat "$TEST_ROOT/cert.pem" "$TEST_ROOT/zscaler-root.pem")"
    put cert_user 44 'security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.'
    put cert_jamf 0 "$(/bin/cat "$TEST_ROOT/cert.pem")"
    put jamf_keychain_info 0 'Arquivo: /Library/Application Support/JAMF/JAMF.keychain | Proprietário: root'
    put identities_system 0 '0 identities found'
    put identities_user 0 '0 identities found'
    put identities_jamf 0 '0 identities found'
    put tls_chain 0 "$(/bin/cat "$TEST_ROOT/cert.pem")"
}

# Parsing de argumentos/URLs: portas com zero inicial, credenciais e injeção.
parse_url 'https://jamf.example.test:00443/path' || fail 'URL válida recusada'
assert_eq "$URL_HOST:$URL_PORT" 'jamf.example.test:443' 'Parsing da URL'
for url in 'http://example.test' 'https://user:pass@example.test' 'https://example.test:0' 'https://example.test:65536' 'https://example.test?token=1' 'https://example.test/#fragment' 'https://example.test\path' $'https://example.test/\033x'; do
    if parse_url "$url"; then fail "URL insegura/inválida aceita: $url"; fi
done
/bin/bash "$SCRIPT_DIR/jamf-diagnostico.sh" --help >"$TEST_ROOT/help.txt" || fail 'Ajuda'
/bin/bash "$SCRIPT_DIR/jamf-diagnostico.sh" --recon >"$TEST_ROOT/removed.txt" 2>&1
assert_eq "$?" 2 'Ação de inventário removida'
/bin/bash "$SCRIPT_DIR/jamf-diagnostico.sh" --jamf-url >"$TEST_ROOT/arguments.txt" 2>&1
assert_eq "$?" 2 'Argumento ausente'

# Fronteiras de datas, incluindo notBefore e vencimento exato.
certificate_state 1 5000000 1000000
assert_eq "$CERT_STATE" 'Dentro da validade' 'Certificado válido'
certificate_state 1 1100000 1000000
assert_eq "$CERT_STATE" 'Vence em até 30 dias' 'Próximo do vencimento'
certificate_state 1 1000000 1000000
assert_eq "$CERT_STATE" Expirado 'Vencimento exato'
certificate_state 1100000 5000000 1000000
assert_eq "$CERT_STATE" 'Ainda não válido' 'Certificado futuro'
if certificate_state invalido 2 1; then fail 'Data inválida aceita'; fi
assert_eq "$(date_epoch 'Nov  6 15:00:00 2026 GMT')" 1793977200 'Parser de data nativo'

# Certificados públicos reais gerados para teste, sem depender de um Jamf real.
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -keyout "$TEST_ROOT/key.pem" -out "$TEST_ROOT/cert.pem" -days 365 -subj '/CN=Jamf Fixture/O=Diagnostic Test' >"$TEST_ROOT/openssl.txt" 2>&1 || fail 'Geração de certificado'
# CA no formato do Zscaler e certificado do Jamf reemitido por ela, como na inspeção SSL.
/usr/bin/openssl req -x509 -new -key "$TEST_ROOT/key.pem" -out "$TEST_ROOT/zscaler-root.pem" -days 365 -subj '/CN=Zscaler Root CA/OU=Zscaler Inc./O=Zscaler Inc.' >>"$TEST_ROOT/openssl.txt" 2>&1 || fail 'Geração da CA Zscaler'
/usr/bin/openssl req -new -key "$TEST_ROOT/key.pem" -out "$TEST_ROOT/jamf.csr" -subj '/CN=jamf.example.test' >>"$TEST_ROOT/openssl.txt" 2>&1 || fail 'Pedido do certificado inspecionado'
/usr/bin/openssl x509 -req -in "$TEST_ROOT/jamf.csr" -CA "$TEST_ROOT/zscaler-root.pem" -CAkey "$TEST_ROOT/key.pem" -set_serial 7 -days 365 -out "$TEST_ROOT/inspected.pem" >>"$TEST_ROOT/openssl.txt" 2>&1 || fail 'Certificado inspecionado'
fixture saudavel
analyze_machine; analyze_management; analyze_network; analyze_zscaler; analyze_certificates; analyze_logs
assert_eq "$FAILS" 0 'Fixture saudável: falhas'
assert_eq "$WARNINGS" 0 'Serviço sob demanda parado não deve virar alerta'
assert_eq "$(/usr/bin/grep -c '^\[INFO\]' "$ISSUES")" 0 'Fixture saudável: observações'
assert_eq "$CERT_TOTAL" 4 'Certificados dos chaveiros e servidor'
has "$BODY" 'SHA-256:'
has "$BODY" 'Nenhum certificado encontrado'
# Rede, Wi-Fi e DNS: SSID oculto, sinal, origem DHCP e túnel do Zscaler nomeado.
has "$BODY" 'Saída padrão:             en0 (Wi-Fi) · gateway 192.0.2.1'
has "$BODY" 'Oculto pelo macOS (privacidade de localização)'
has "$BODY" '-60 dBm / -95 dBm (SNR 35 dB)'
has "$BODY" 'DNS do Wi-Fi:             Recebido por DHCP: 192.0.2.53, 192.0.2.54'
has "$BODY" 'Domínios de busca:        corp.example.test'
has "$BODY" 'Interface do túnel:       utun4 (100.64.0.1)'
has "$BODY" 'com.zscaler.zscaler.TRPTunnel (4.8.0.281) — activated enabled'
has "$BODY" 'Certificado Zscaler — Chaveiro Sistema: Zscaler Root CA · Dentro da validade'
has "$ISSUES" '[OK] Zscaler/VPN: O tráfego de internet passa pelo Zscaler (Zscaler Cloud: Sao Paulo IV in the zscalertwo.net cloud).'
has "$ISSUES" '[OK] Certificados: A cadeia TLS obtida do Jamf não é emitida pelo Zscaler'
lacks "$BODY" 'Other Local Wi-Fi'
# Rótulos acentuados alinham pela quantidade de caracteres, não de bytes.
has "$BODY" "  Modelo:$(printf '%19s' '')MacBook Pro"
has "$BODY" "  Número de série:$(printf '%10s' '')SERIAL-FICTICIO"
has "$BODY" '15.7 (24G000)'
has "$BODY" 'Administrador:'
write_reports || fail 'Geração dos relatórios'
has "$OUT/relatorio.html" '<section id="sec-8">'
lacks "$OUT/relatorio.html" '<section id="sec-9">'
has "$OUT/relatorio.html" '<section id="visao-geral">'
has "$OUT/relatorio.html" '<a class="area OK" href="#sec-3"><b>Agente Jamf</b>'
has "$OUT/relatorio.html" '<a class="area OK" href="#sec-6"><b>Zscaler/VPN</b>'
has "$REPORT" 'RESULTADO: Sem falha confirmada'
has "$REPORT" 'Wi-Fi (en0) · WPA2 Enterprise · sinal -60 dBm'
has "$REPORT" '192.0.2.53, 192.0.2.54 · Wi-Fi (en0), DHCP'
has "$REPORT" '4.8.0.281 · serviço ativo · túnel utun4 · internet via Zscaler Cloud: Sao Paulo IV'
has "$REPORT" 'Usuário na sessão:'
has "$REPORT" 'usuario.teste (Usuário de demonstração) · administrador: Não'
has "$REPORT" 'Inscrito, aprovado pelo usuário · via ADE/DEP'
has "$REPORT" '29% usado · 300Gi livres'
has "$REPORT" '(há 20 min)'
NO_COLOR_FLAG=1; init_colors; REPORT_OWNER=root
show_summary >"$TEST_ROOT/terminal-saudavel.txt"
has "$TEST_ROOT/terminal-saudavel.txt" 'Nenhuma falha ou atenção reconhecida'
lacks "$TEST_ROOT/terminal-saudavel.txt" '>>>'
lacks "$TEST_ROOT/terminal-saudavel.txt" 'SHA-256'
lacks "$REPORT" 'LIMITES E PRÓXIMOS PASSOS'
lacks "$REPORT" 'Referências:'
lacks "$REPORT" 'BEGIN PRIVATE KEY'
lacks "$REPORT" 'BEGIN RSA PRIVATE KEY'
assert_eq "$(/usr/bin/stat -f '%Lp' "$OUT")" 700 'Permissão da pasta'
assert_eq "$(/usr/bin/stat -f '%Lp' "$REPORT")" 600 'Permissão do relatório'

fixture falhas
put enrollment 0 'Enrolled via DEP: No
MDM enrollment: No'
put jamf_connection 1 'Could not connect to the JSS'
put https 60 'SSL certificate problem: certificate has expired'
put service_1 0 'state = not running
last exit code = 6'
put launch_disabled 0 '"com.jamfsoftware.task.fixture" => disabled'
put jamf_log 0 "$(log_stamp -2H) Mac jamf[100]: Device Signature Error - A valid device signature is required"
analyze_machine; analyze_management; analyze_network; analyze_zscaler; analyze_certificates; analyze_logs
assert_eq "$FAILS" 3 'MDM ausente, agente e TLS falhando'
has "$ISSUES" '[ATENCAO] Agente Jamf: O serviço com.jamfsoftware.task.fixture está desabilitado no launchd'
has "$ISSUES" '(resposta: Could not connect to the JSS)'
has "$ISSUES" '[FALHA] Rede: Falha TLS ou de certificado no HTTPS (curl 60: SSL certificate problem: certificate has expired)'
has "$ISSUES" '[ATENCAO] Histórico: jamf.log registra erro de assinatura do dispositivo — 1 ocorrência(s), última em'
has "$ISSUES" '(há 2 h)'
has "$ISSUES" '[INFO] Histórico: Nenhuma busca de políticas'
[ -n "$START_HINT" ] || fail 'Falha de rede com agente falhando deve indicar por onde começar'
write_reports || fail 'Relatório com falhas'
order="$(/usr/bin/awk '/^## O que pode/ {on = 1; next} /^## / {on = 0} on && /^\[/ {sub(/\].*/, ""); sub(/^\[/, ""); printf "%s ", $0}' "$REPORT")"
assert_eq "$order" 'FALHA FALHA FALHA ATENCAO ATENCAO INFO ' 'Resumo ordenado por gravidade'
has "$REPORT" 'Por onde começar: Rede — o teste HTTPS'
has "$REPORT" 'FALHA (1 falha · 1 atenção · 1 OK)'
has "$OUT/relatorio.html" '<a class=tag href="#sec-5">Rede</a>'
has "$OUT/relatorio.html" '<p class=hint>'
has "$OUT/relatorio.html" '<p class="status FALHA">'
show_summary >"$TEST_ROOT/terminal-falhas.txt"
has "$TEST_ROOT/terminal-falhas.txt" 'RESULTADO: Foram encontradas falhas'
has "$TEST_ROOT/terminal-falhas.txt" '✖ Agente Jamf: O agente falhou no checkJSSConnection'
has "$TEST_ROOT/terminal-falhas.txt" 'Falhas (3)'
lacks "$TEST_ROOT/terminal-falhas.txt" 'Nenhuma falha ou atenção'
[ "$(/usr/bin/grep -n 'Falhas (3)' "$TEST_ROOT/terminal-falhas.txt" | /usr/bin/cut -d: -f1)" -lt "$(/usr/bin/grep -n 'Pontos de atenção (2)' "$TEST_ROOT/terminal-falhas.txt" | /usr/bin/cut -d: -f1)" ] || fail 'Terminal deve listar falhas antes das atenções'

# Indícios antigos viram observação; check-in antigo vira atenção.
fixture antigo
put jamf_log 0 "$(log_stamp -20d) Mac jamf[100]: Device Signature Error - A valid device signature is required
$(log_stamp -80H) Mac jamf[100]: Checking for policies triggered by \"recurring check-in\" for user \"usuario.teste\"..."
analyze_logs
has "$ISSUES" '[INFO] Histórico: jamf.log registra erro de assinatura'
has "$ISSUES" '[ATENCAO] Histórico: Último check-in no jamf.log'
has "$ISSUES" '(há 3 dias)'

fixture curto
NO_LOGS=1 URL_VALID=0 JAMF='' USER_KEYCHAIN=0 JAMF_KEYCHAIN=0 ZSCALER_APP='' WIFI_DEV=''
put cert_system 44 'security: keychain unavailable'
put dns_config 0 'DNS configuration

resolver #1
  domain   : local
  options  : mdns'
analyze_management; analyze_network; analyze_zscaler; analyze_certificates; analyze_logs
has "$BODY" 'Desativada por --no-logs'
lacks "$BODY" 'jamf.log registra'
has "$ISSUES" 'Consulta de certificados indisponível'
assert_eq "$CERT_TOTAL" 0 'Certificado inacessível não pode contar como válido'
has "$ISSUES" '[ATENCAO] Zscaler/VPN: Zscaler Client Connector não encontrado'
has "$ISSUES" '[ATENCAO] Rede: Nenhum servidor DNS padrão configurado'
lacks "$BODY" 'Interface do túnel'
lacks "$BODY" 'Certificado Zscaler'
lacks "$BODY" 'Wi-Fi:'

# Zscaler com problemas, DNS manual, split DNS pelo túnel e Jamf via ZPA com inspeção SSL.
fixture zscaler
put processes 0 'PID PPID USER ELAPSED COMM
100 1 root 01:00 /usr/sbin/apsd'
put sysext 0 '1 extension(s)
*	*	PCBCQZJ7S7	com.zscaler.zscaler.TRPTunnel (4.8.0.252/old)	TRPTunnel	[terminated waiting to uninstall on reboot]
*	-	PCBCQZJ7S7	com.zscaler.zscaler.TRPTunnel (4.8.0.281/abc123)	TRPTunnel	[activated waiting for user]'
put zscaler_check 0 "The request received from you didn't come from a Zscaler IP therefore you are not going through the Zscaler proxy service."
put wifi_dns_manual 0 '8.8.8.8
1.1.1.1'
put wifi_radio 0 '      Interfaces:
        en0:
          Status: Connected
          Current Network Information:
            Rede Corporativa:
              Security: WPA2 Enterprise
              Signal / Noise: -80 dBm / -90 dBm'
put dns_config 0 'DNS configuration

resolver #1
  nameserver[0] : 8.8.8.8
  nameserver[1] : 1.1.1.1
  if_index : 12 (en0)

resolver #2
  domain   : corp.example.test
  nameserver[0] : 10.0.0.53
  if_index : 20 (utun4)

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 8.8.8.8
  if_index : 12 (en0)

resolver #2
  nameserver[0] : 100.64.0.53
  if_index : 20 (utun4)'
put vpn 0 'Available network connection services in the current set (*=enabled):
* (Connected)      1A2B3C4D-0000-0000-0000-000000000000 IPSec              "VPN Escritório"          [IPSec]
* (Disconnected)   5E6F7A8B-0000-0000-0000-000000000000 PPP --> L2TP       "VPN Antiga"              [PPP:L2TP]'
put dns 0 'name: jamf.example.test
ip_address: 100.64.3.7'
put https 60 'SSL certificate problem: unable to get local issuer certificate'
put cert_system 0 "$(/bin/cat "$TEST_ROOT/cert.pem")"
put tls_chain 0 "$(/bin/cat "$TEST_ROOT/inspected.pem")"
analyze_network; analyze_zscaler; analyze_certificates
has "$ISSUES" '[FALHA] Zscaler/VPN: O serviço ZscalerService não está em execução'
has "$ISSUES" '[ATENCAO] Zscaler/VPN: Extensão de rede do Zscaler em estado "activated waiting for user"'
has "$ISSUES" '[ATENCAO] Zscaler/VPN: ip.zscaler.com indica que o tráfego não passa pelo Zscaler'
has "$ISSUES" '[INFO] Zscaler/VPN: O aplicativo Zscaler não está aberto'
has "$ISSUES" '[INFO] Zscaler/VPN: O Jamf (jamf.example.test) resolve para um IP sintético do ZPA'
has "$ISSUES" '[INFO] Zscaler/VPN: VPN conectada: VPN Escritório.'
has "$ISSUES" '[ATENCAO] Rede: Sinal Wi-Fi fraco (-80 dBm, SNR 10 dB)'
has "$ISSUES" '[INFO] Rede: DNS do Wi-Fi configurado manualmente (8.8.8.8, 1.1.1.1)'
has "$ISSUES" '[ATENCAO] Certificados: A cadeia TLS do Jamf é emitida pelo Zscaler (Zscaler Root CA) e o teste HTTPS falhou'
has "$BODY" 'Rede Wi-Fi (SSID):        Rede Corporativa'
has "$BODY" 'DNS para corp.example.test: 10.0.0.53 via utun4 (túnel Zscaler)'
has "$BODY" 'DNS de utun4 (túnel Zscaler): 100.64.0.53'
has "$BODY" 'IP do Jamf:               100.64.3.7 (IP sintético do ZPA, resolvido pelo Zscaler)'
has "$BODY" 'VPN cadastrada:           VPN Antiga — desconectada'
has "$BODY" 'Certificado Zscaler:      Nenhum nos chaveiros consultados'
has "$BODY" 'Inspeção SSL no Jamf:     Sim — emissor Zscaler Root CA'
has "$EVID/routes_tunnel.txt" '100.64/16'
lacks "$EVID/routes_tunnel.txt" '192.0.2/24'
case "$START_HINT" in 'Certificados — '*) ;; *) fail "Inspeção SSL com falha TLS deve indicar por onde começar: $START_HINT" ;; esac
write_reports || fail 'Relatório Zscaler'
has "$REPORT" '8.8.8.8, 1.1.1.1 · Wi-Fi (en0), manual'
has "$REPORT" 'jamf.example.test · via ZPA (100.64.3.7)'
has "$REPORT" '4.8.0.281 · serviço parado · túnel utun4 · internet sem Zscaler'
# Falha ao consultar ip.zscaler.com e extensão ausente com túnel por processo.
: >"$ISSUES"
put zscaler_check 6 'curl: (6) Could not resolve host: ip.zscaler.com'
put sysext 0 '0 extension(s)'
put processes 0 'PID PPID USER ELAPSED COMM
200 1 root 01:00 /Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerService
201 1 root 01:00 /Applications/Zscaler/Zscaler.app/Contents/PlugIns/ZscalerTunnel'
analyze_network; analyze_zscaler
has "$ISSUES" '[ATENCAO] Zscaler/VPN: Não foi possível consultar ip.zscaler.com (curl 6: Could not resolve host: ip.zscaler.com)'
has "$ISSUES" '[OK] Zscaler/VPN: Processo de túnel do Zscaler em execução.'
has "$ISSUES" '[INFO] Zscaler/VPN: VPN conectada junto com o Zscaler: VPN Escritório.'

fixture seguranca
printf '</pre><script>alert("x")</script>&\n<<<\n## FALSO\n[FALHA] inventada\n' >"$EVID/untrusted.txt"
section 'Dados <teste> & usuário'
evidence untrusted 'Saída externa'
fact 'Computador' '<script>alert("fato")</script>'
finding ATENCAO 'Mensagem <script>alert("achado")</script>'
write_reports || fail 'Escape do relatório'
has "$OUT/relatorio.html" '&lt;script&gt;'
has "$OUT/relatorio.html" 'Dados &lt;teste&gt; &amp; usuário'
lacks "$OUT/relatorio.html" '<script>'
lacks "$OUT/relatorio.html" '<h2>FALSO</h2>'
lacks "$OUT/relatorio.html" '<b>FALHA</b>inventada'

# capture deve preservar falhas, encerrar demora e permitir nova coleta da chave.
capture command_failure 2 /usr/bin/false
assert_eq "$(rc_of command_failure)" 1 'Retorno de comando com falha'
capture demorado 1 /bin/sleep 5
assert_eq "$(rc_of demorado)" 124 'Consulta demorada'
capture demorado 2 /usr/bin/true
assert_eq "$(rc_of demorado)" 0 'Nova coleta não herda timeout'

# Certificado próximo do vencimento deve alertar por origem no chaveiro Jamf.
/usr/bin/openssl req -new -x509 -key "$TEST_ROOT/key.pem" -out "$TEST_ROOT/soon.pem" -days 1 -subj '/CN=Device Identity' >"$TEST_ROOT/openssl-soon.txt" 2>&1 || fail 'Certificado próximo do vencimento'
inspect_certificate "$TEST_ROOT/soon.pem" 'Chaveiro Jamf' '' || fail 'Inspeção do certificado'
assert_eq "$CERT_STATE" 'Vence em até 30 dias' 'Validade lida do certificado real'
has "$ISSUES" 'Verifique a renovação do certificado em uso'

# Amostra somente sintética para revisar o layout sem expor dados do computador.
if [ -n "${1:-}" ]; then
    /bin/cp "$TEST_ROOT/falhas/relatorio.html" "$1" || fail 'Exportação da amostra'
fi
printf 'OK: URLs, argumentos, datas, certificados reais, análise saudável/com falhas, Wi-Fi, DNS, Zscaler/VPN, inspeção SSL, resumo por gravidade/área, Terminal, HTML, privacidade e timeout.\n'
