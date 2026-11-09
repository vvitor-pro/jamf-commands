# Diagnóstico Jamf Pro para macOS

Script único (`jamf-diagnostico.sh`) que coleta e analisa, somente para leitura, o estado de um Mac gerenciado pelo Jamf Pro: computador, usuário, agente Jamf, MDM, rede, Wi-Fi, DNS, Zscaler/VPN, certificados e logs. Gera `relatorio.html`, `relatorio.txt` e evidências em uma pasta privada. A versão atual fica em `VERSION` e no comentário do cabeçalho do script.

## Comandos

```sh
sudo /bin/bash ./jamf-diagnostico.sh                       # coleta completa
sudo /bin/bash ./jamf-diagnostico.sh --deep                # + eventos MDM/Jamf/APNs dos últimos 15 min
sudo /bin/bash ./jamf-diagnostico.sh --output-base /Users/Shared
sudo /bin/bash ./jamf-diagnostico.sh --no-logs --no-color
sudo /bin/bash ./jamf-diagnostico.sh --jamf-url https://empresa.jamfcloud.com

/bin/bash -n ./jamf-diagnostico.sh                         # sintaxe
/bin/bash ./tests/diagnostico-test.sh                      # testes (sem sudo)
/bin/bash ./tests/diagnostico-test.sh /private/tmp/jamf-amostra.html   # exporta HTML fictício
```

`--jamf-url` aceita DNS/IPv4 e porta opcional; recusa credenciais, query, fragmento e IPv6 literal. Troca o destino dos testes de rede e certificado; o `checkJSSConnection` continua usando a configuração do agente.

Retornos: `0` sem falha confirmada (pode haver atenções); `1` ao menos uma FALHA (relatório gerado normalmente); `2` argumentos, permissões ou ambiente inválidos; `130` interrompido.

## Regras do projeto

- **Somente diagnóstico.** Nunca executar recon, políticas, `manage`, reparos, renovação de certificados, reinscrição, remoção de perfis, reinício de serviços ou mudança de configuração (ex.: `ipconfig setverbose`). `--recon` e `--policy-id` foram retiradas na 2.0.0 e não devem voltar.
- **Conexões externas** apenas ao destino Jamf (DNS, HTTPS, TLS direto) e, com o Zscaler instalado, um GET a `https://ip.zscaler.com`. Qualquer conexão nova precisa ser documentada no `--help` e aqui.
- **Bash 3.2 e ferramentas nativas do macOS**, sempre por caminho absoluto (`PATH=/usr/bin:/bin:/usr/sbin:/sbin`). Sem Homebrew, Python, jq ou API do Jamf. Testar com `/bin/bash`.
- **Privacidade.** Não coletar senhas, chaves privadas nem chave de recuperação do FileVault. Chaveiro do usuário só no contexto da sessão dele, sem desbloqueio. Redes Wi-Fi vizinhas ficam fora. Pastas com permissão 700 e arquivos 600 (`umask 077`).
- **Textos em português (pt-BR)**: mensagens, comentários e documentação.

## Arquitetura

`main` → `collect_*` → `analyze_*` → `write_reports` → `handoff_reports` → `show_summary`. O progresso no Terminal tem 8 etapas fixas (`progress N 'texto'`).

- **Coleta** (`collect_machine`, `collect_management`, `collect_network`, `collect_certificates`, `collect_logs`): todo comando passa por `capture CHAVE SEGUNDOS comando...`, que grava `evidencias/CHAVE.txt` e `evidencias/CHAVE.rc` e encerra o comando no tempo-limite (`.rc` = `124`). `rc_of CHAVE` lê o retorno (`125` se a consulta foi omitida). Pós-processamento de saída (filtrar, remover HTML) acontece aqui.
- **Análise** (`analyze_*`): lê **apenas** as evidências e as globais definidas na coleta (`CONSOLE_USER`, `JAMF`, `URL_VALID`, `URL_HOST`, `URL_PORT`, `JAMF_KEYCHAIN`, `USER_KEYCHAIN`, `WIFI_DEV`, `ZSCALER_APP`, `ZSCALER_VERSION`, `NO_LOGS`, `DEEP`). Não executar comandos do sistema na análise: os testes rodam a análise sobre fixtures. Arquivos derivados (ex.: `zscaler_processes.txt`) podem ser gravados em `evidencias/`.
- **API do relatório**:
  - `section 'Título' 'Área curta'` abre uma seção; a área aparece no painel e nos achados.
  - `detail 'Rótulo' 'valor'` linha chave/valor (valor vazio vira "Não disponível").
  - `fact 'Rótulo' 'valor'` dado da Visão geral (Terminal, texto e HTML).
  - `finding NÍVEL 'mensagem'` com `FALHA`, `ATENCAO`, `OK` ou `INFO`; conta por área e vai para `achados.txt`.
  - `evidence CHAVE 'título'` bloco expansível com a saída do comando.
  - `note 'texto'` parágrafo explicativo.
  - `excerpt CHAVE first|last` linha curta, sem caracteres de controle, para citar a resposta no achado.
  - `START_HINT` "Por onde começar", quando uma falha explica outra; a análise posterior pode sobrescrever com uma causa mais específica.
- **Seções e áreas** (a ordem define `sec-N` no HTML): 1 Computador · 2 Armazenamento · 3 Agente Jamf · 4 MDM · 5 Rede · 6 Zscaler/VPN · 7 Certificados · 8 Histórico.
- **Saída** (pasta `jamf-diagnostico-AAAAMMDD-HHMMSS.XXXXXX`, padrão `/private/tmp`): `relatorio.html` (offline, tema claro/escuro, sem recursos externos), `relatorio.txt`, `conteudo.txt` (seções), `achados.txt` (nível e área), `evidencias/` e `*-pem/` (certificados públicos separados). Com sudo, a pasta e os dois relatórios passam ao usuário que chamou sudo; evidências continuam de root.

## Convenções de código

- `LC_ALL=C`: o `printf` conta bytes. Use `padded`/`kv_line` (coluna de 26 caracteres nos detalhes) e `wrap_lines`, que descontam UTF-8 e cores.
- O nome da área não pode conter `": "` (separa área e mensagem em `achados.txt` e no Terminal). Rótulos de `detail` não podem conter `:` (parser chave/valor do HTML).
- Para registros com campos possivelmente vazios, use `|` com `IFS='|' read`; tabulação colapsa campos vazios no `read`.
- Em regex passada por `awk -v`, prefira `[.]` a `\.` (o `-v` processa escapes).
- Conteúdo de terceiros (páginas, SSID, logs) chega ao Terminal só depois de remover caracteres de controle (`excerpt`, `tr -d '\000-\037\177'`). No HTML, tudo passa por `esc()` (`HTML_ESC`).
- Comentários curtos, de uma linha, acima da função ou do trecho não óbvio.
- Mensagens de achado: sintoma + consequência + o que conferir, citando a resposta do comando quando houver. Níveis:
  - `FALHA` problema confirmado pela verificação (faz o script retornar 1);
  - `ATENCAO` pode causar ou explicar o sintoma;
  - `INFO` contexto, sem indicar problema por si só;
  - `OK` verificação aprovada.

## Testes (`tests/diagnostico-test.sh`)

- Carrega o script com `source` (`main` só roda quando executado diretamente) e não precisa de sudo nem consulta o gerenciamento real.
- `fixture NOME` cria uma pasta, zera os achados e preenche globais e evidências de um Mac saudável. `put CHAVE RC 'conteúdo'` grava uma evidência. Certificados reais são gerados com `/usr/bin/openssl` (incluindo uma CA "Zscaler Root CA" e um certificado do Jamf reemitido por ela).
- A fixture `saudavel` precisa terminar com 0 FALHA, 0 ATENCAO e 0 INFO. A fixture `falhas` fixa a ordem e a contagem do resumo (`FALHA FALHA FALHA ATENCAO ATENCAO INFO`). Novas verificações não podem disparar nessas duas sem ajuste consciente.
- Asserções de `detail` incluem o preenchimento até a coluna 26. Nova seção desloca `sec-N`; atualize `has/lacks ... '<section id="sec-N">'`.
- A pasta temporária `/private/tmp/jamf-test.*` é removida no `EXIT`.

## Comportamento esperado

**Verificações**
- Computador: nome, modelo, identificador, serial, UUID, chip, memória, macOS; usuário da sessão (nome, UID, home, shell, grupo admin, Secure Token).
- Armazenamento: uso do volume de dados, FileVault, bateria/energia, ajuste automático do relógio.
- Agente Jamf: binário, versão, `checkJSSConnection`, assinatura; LaunchDaemons (desabilitado, carregado, último código de saída; tarefas sob demanda podem estar paradas); processos e Self Service.
- MDM: inscrição, ADE/DEP, aprovação do usuário, Bootstrap Token, perfis, `apsd` (processo local; não confirma entrega de comandos).
- Rede: saída padrão (interface e gateway), proxy/PAC, DNS e HTTPS ao Jamf (confiança TLS validada pelo `curl` nativo).
- Wi-Fi: estado, SSID, segurança, canal, sinal/ruído, taxa, DHCP ou manual. A partir do macOS 14.4, o SSID fica oculto sem permissão de localização.
- DNS: resolvedor padrão e interface (`scutil --dns`); origem no Wi-Fi (DHCP ou manual); split DNS por domínio; DNS de outras interfaces; IP resolvido do Jamf.
- Zscaler/VPN: versão do Client Connector, `ZscalerService`, extensão de rede (`systemextensionsctl`), túnel `utun` em `100.64.0.0/10`, app aberto na sessão, `ip.zscaler.com` (nó e IP público), VPNs do `scutil --nc list` e rotas por túneis.
- Certificados: chaveiros Jamf, Sistema e login (titular, emissor, validade, serial, SHA-256); identidades SSL cliente (sem usar a chave); certificado do servidor por TLS direto com SNI; CA do Zscaler; inspeção SSL no Jamf.
- Histórico: último check-in e indícios no `jamf.log` e `install.log`; com `--deep`, eventos de `mdmclient`, `dmd`, `apsd` e Jamf.

**Limites e regras de interpretação**
- Disco: ATENCAO a partir de 90% de uso (mensagem mais forte a partir de 95%).
- Check-in: ATENCAO se o último tiver mais de 24 h.
- Indícios do `jamf.log`: quantidade e última ocorrência; com mais de 7 dias, viram INFO.
- HTTPS ao Jamf: ATENCAO se levar 8 s ou mais.
- Certificados vencidos, ainda não válidos ou que vencem em até 30 dias geram ATENCAO quando:
  - são o certificado do servidor Jamf;
  - estão no chaveiro Jamf;
  - o nome sugere Jamf/MDM/SCEP/Zscaler;
  - existe identidade associada.

  Os demais só entram na contagem. Certificados antigos podem continuar instalados.
- Wi-Fi: ATENCAO com sinal de -75 dBm ou menos, ou SNR abaixo de 15 dB. DNS manual no Wi-Fi gera INFO.

**Zscaler, VPN e DNS**
- O Client Connector não aparece em `scutil --nc list`: o túnel é uma extensão de rede (ex.: `com.zscaler.zscaler.TRPTunnel`). Com mais de uma extensão, vale o estado mais ativo.
- A faixa `100.64.0.0/10` (`ZPA_RANGE`) é a do adaptador do Zscaler e dos IPs sintéticos do ZPA. Se o Jamf resolve para ela, quem responde o DNS é o Zscaler, e o agente depende do túnel ZPA autenticado.
- `ip.zscaler.com`: o título fica em `class="headline"`. Com "You are accessing … via … Zscaler", a saída passa pelo Zscaler; qualquer outro título indica ZIA desligado, em pausa, sem login ou rede confiável com saída direta.
- Extensão em estado diferente de `activated enabled` indica aprovação pendente ou perfil MDM de extensões ausente.
- Emissor com "Zscaler" no certificado do Jamf indica inspeção SSL. A Apple não suporta inspeção HTTPS em MDM/APNs, então o Jamf e os domínios Apple precisam de exceção (bypass). Uma CA própria da empresa não é reconhecida. O TLS direto não usa o proxy do sistema; no modo PAC, a inspeção só no proxy pode não aparecer.

**Leitura do resultado**
- O Terminal mostra: RESULTADO, Por onde começar, Visão geral, Situação por área (pior nível de cada área), Falhas, Pontos de atenção e Observações por gravidade, e os caminhos dos relatórios. Não mostra a saída dos comandos.
- `relatorio.txt` e HTML seguem a mesma ordem. No HTML, a área de cada achado leva à seção detalhada.
- O relatório contém nome, serial, usuário, nomes internos, certificados, DNS, IP público, dados do Wi-Fi e trechos de logs: revisar antes de compartilhar.

## Ao alterar

1. Atualizar `VERSION` e o comentário do cabeçalho em mudanças de comportamento.
2. Ajustar o `--help` (`usage`) e este arquivo quando mudar opções, verificações, conexões ou saídas.
3. Cobrir a mudança em `tests/diagnostico-test.sh` e rodar `/bin/bash -n` e os testes.
4. Validar a coleta real com `sudo` em um Mac gerenciado; os testes não substituem isso.
