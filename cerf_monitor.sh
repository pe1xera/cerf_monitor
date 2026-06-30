#!/bin/bash

# =============================================================================
# monitor_seguranca.sh
# Monitoramento de segurança para macOS — Trustly Security Tool
#
# Funcionalidades:
#   1. Cálculo e registro de hashes SHA-256 de arquivos baixados
#   2. Detecção de tentativas de login falhadas
#   3. Monitoramento de alterações em arquivos sensíveis (sudoers, hosts, etc.)
#   4. Detecção e remoção de malwares via VirusTotal API
#   5. Logs com timestamp para auditoria
#
# Requisitos: macOS (utiliza apenas ferramentas nativas do sistema)
# Uso: bash monitor_seguranca.sh
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------

# Chave da API do VirusTotal
# Obtenha a sua em: https://www.virustotal.com/gui/my-apikey
API_KEY="SUA_CHAVE_AQUI"

# Arquivos sensíveis a serem monitorados quanto a modificações
ARQUIVOS_SENSIVEIS=(
    "/etc/sudoers"
    "/etc/hosts"
    "/Library/Preferences/com.apple.systempreferences.plist"
)

# Diretórios monitorados para arquivos com atributo de quarentena
DIRETORIOS_MONITORADOS=(
    "$HOME/Downloads"
    "$HOME/Desktop"
    "$HOME/Documents"
)

# Intervalo entre verificações (em segundos)
INTERVALO=10

# -----------------------------------------------------------------------------
# INICIALIZAÇÃO DE DIRETÓRIOS E ARQUIVOS DE LOG
# -----------------------------------------------------------------------------

DIRETORIO_SCRIPT=$(dirname "$0")
DIRETORIO_REGISTROS="$DIRETORIO_SCRIPT/registros"

# Cria a pasta de registros caso não exista
if [ ! -d "$DIRETORIO_REGISTROS" ]; then
    mkdir -p "$DIRETORIO_REGISTROS"
fi

DATA_ATUAL=$(date +"%Y-%m-%d")

# Arquivos de log (um por data para facilitar auditoria)
LOG_HASHES="$DIRETORIO_REGISTROS/hashArquivosBaixados_$DATA_ATUAL.log"
LOG_PROCESSADOS="$DIRETORIO_REGISTROS/arquivosProcessados_$DATA_ATUAL.txt"
LOG_FALHAS_LOGIN="$DIRETORIO_REGISTROS/falhasLogin_$DATA_ATUAL.log"
LOG_FALHAS_LOGIN_PROCESSADAS="$DIRETORIO_REGISTROS/falhasLoginProcessadas_$DATA_ATUAL.txt"
LOG_MODIFICACOES="$DIRETORIO_REGISTROS/modificacoesArquivosSensiveis_$DATA_ATUAL.log"
LOG_MALWARES="$DIRETORIO_REGISTROS/malwaresDetectados_$DATA_ATUAL.log"

# Garante que os arquivos de controle existam
touch "$LOG_PROCESSADOS" "$LOG_FALHAS_LOGIN_PROCESSADAS"

# -----------------------------------------------------------------------------
# FUNÇÕES UTILITÁRIAS
# -----------------------------------------------------------------------------

# Exibe uma notificação nativa do macOS
exibir_alerta() {
    local titulo="$1"
    local mensagem="$2"
    osascript -e "display notification \"$mensagem\" with title \"$titulo\" sound name \"Basso\""
}

# Registra uma mensagem nos logs com timestamp
registrar_log() {
    local arquivo_log="$1"
    local mensagem="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $mensagem" >> "$arquivo_log"
}

# Exibe mensagem no terminal com timestamp
log_terminal() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# -----------------------------------------------------------------------------
# FUNÇÃO 1 — CÁLCULO DE HASH E VERIFICAÇÃO NO VIRUSTOTAL
# -----------------------------------------------------------------------------

# Calcula o hash SHA-256 de um arquivo e o envia ao VirusTotal
calcular_hash() {
    local arquivo="$1"

    if [ ! -f "$arquivo" ]; then
        log_terminal "ERRO: Arquivo não encontrado: $arquivo"
        return 1
    fi

    local hash_arquivo
    hash_arquivo=$(shasum -a 256 "$arquivo" | awk '{print $1}')

    # Evita reprocessar o mesmo arquivo na mesma sessão diária
    if grep -qF "$arquivo" "$LOG_PROCESSADOS" 2>/dev/null; then
        return 0
    fi

    # Evita duplicar entradas de hash no log
    if ! grep -qF "$hash_arquivo" "$LOG_HASHES" 2>/dev/null; then
        registrar_log "$LOG_HASHES" "ARQUIVO: $(basename "$arquivo") | HASH: $hash_arquivo | CAMINHO: $arquivo"
        log_terminal "Hash registrado: $(basename "$arquivo") → $hash_arquivo"

        # Consulta o VirusTotal com o hash calculado
        verificar_virus_total "$hash_arquivo" "$arquivo"
    fi

    # Marca o arquivo como processado
    echo "$arquivo" >> "$LOG_PROCESSADOS"
}

# -----------------------------------------------------------------------------
# FUNÇÃO 2 — VERIFICAÇÃO NO VIRUSTOTAL
# -----------------------------------------------------------------------------

# Consulta a API do VirusTotal e remove o arquivo se for malicioso
verificar_virus_total() {
    local hash_arquivo="$1"
    local arquivo="$2"

    log_terminal "Consultando VirusTotal para: $(basename "$arquivo")..."

    local resposta
    resposta=$(curl --silent --max-time 15 --request GET \
        "https://www.virustotal.com/vtapi/v2/file/report?apikey=$API_KEY&resource=$hash_arquivo")

    # Verifica se a resposta é válida
    if [ -z "$resposta" ]; then
        log_terminal "AVISO: Sem resposta do VirusTotal para $(basename "$arquivo"). Verifique sua conexão."
        return 1
    fi

    local response_code
    response_code=$(echo "$resposta" | grep -o '"response_code":[0-9]*' | cut -d':' -f2)

    # Código 0 = arquivo desconhecido no VirusTotal
    if [ "$response_code" -eq 0 ] 2>/dev/null; then
        log_terminal "INFO: Arquivo $(basename "$arquivo") não encontrado na base do VirusTotal."
        return 0
    fi

    local positivos
    positivos=$(echo "$resposta" | grep -o '"positives":[0-9]*' | cut -d':' -f2)

    local total
    total=$(echo "$resposta" | grep -o '"total":[0-9]*' | cut -d':' -f2)

    if [ "${positivos:-0}" -gt 0 ] 2>/dev/null; then
        # Arquivo detectado como malicioso
        local mensagem_alerta="Malware detectado: $(basename "$arquivo") | Detecções: $positivos/$total antivírus"

        log_terminal "⚠️  ALERTA — $mensagem_alerta"
        registrar_log "$LOG_MALWARES" "$mensagem_alerta | HASH: $hash_arquivo | CAMINHO: $arquivo"

        exibir_alerta "⚠️ Alerta de Segurança" \
            "Arquivo malicioso detectado: $(basename "$arquivo") ($positivos/$total antivírus). O arquivo será removido."

        # Remove o arquivo malicioso
        if rm -f "$arquivo"; then
            log_terminal "Arquivo removido: $arquivo"
            registrar_log "$LOG_MALWARES" "REMOVIDO: $arquivo"
        else
            log_terminal "ERRO: Não foi possível remover $arquivo. Verifique as permissões."
            registrar_log "$LOG_MALWARES" "FALHA AO REMOVER: $arquivo"
        fi
    else
        log_terminal "OK: $(basename "$arquivo") verificado — sem ameaças ($positivos/$total)."
    fi
}

# -----------------------------------------------------------------------------
# FUNÇÃO 3 — VERIFICAÇÃO DE ARQUIVOS EM QUARENTENA
# -----------------------------------------------------------------------------

# Varre os diretórios monitorados em busca de arquivos com atributo de quarentena
verificar_arquivos_quarentena() {
    for diretorio in "${DIRETORIOS_MONITORADOS[@]}"; do
        if [ ! -d "$diretorio" ]; then
            continue
        fi

        # Usa find + xargs para lidar com nomes de arquivos com espaços
        find "$diretorio" -type f -print0 | while IFS= read -r -d '' arquivo; do
            # Verifica se o arquivo possui o atributo de quarentena do macOS
            if xattr -p com.apple.quarantine "$arquivo" &>/dev/null; then
                calcular_hash "$arquivo"
            fi
        done
    done
}

# -----------------------------------------------------------------------------
# FUNÇÃO 4 — MONITORAMENTO DE ARQUIVOS SENSÍVEIS
# -----------------------------------------------------------------------------

# Detecta alterações em arquivos críticos do sistema comparando hashes
monitorar_arquivos_sensiveis() {
    for arquivo in "${ARQUIVOS_SENSIVEIS[@]}"; do
        if [ ! -f "$arquivo" ]; then
            continue
        fi

        local hash_atual
        hash_atual=$(shasum -a 256 "$arquivo" 2>/dev/null | awk '{print $1}')

        if [ -z "$hash_atual" ]; then
            log_terminal "AVISO: Não foi possível calcular hash de $arquivo (sem permissão?)"
            continue
        fi

        # Arquivo onde o hash anterior é guardado (substituindo / por _ no nome)
        local arquivo_hash="$DIRETORIO_REGISTROS/hash_${arquivo//\//_}.txt"

        if [ -f "$arquivo_hash" ]; then
            local hash_anterior
            hash_anterior=$(cat "$arquivo_hash")

            if [ "$hash_atual" != "$hash_anterior" ]; then
                local mensagem="Arquivo sensível modificado: $(basename "$arquivo")"
                log_terminal "⚠️  ALERTA — $mensagem"
                registrar_log "$LOG_MODIFICACOES" "$mensagem | HASH ANTERIOR: $hash_anterior | HASH ATUAL: $hash_atual"
                exibir_alerta "⚠️ Alerta de Segurança" "$mensagem"
            fi
        else
            log_terminal "INFO: Hash base registrado para $(basename "$arquivo")."
        fi

        # Atualiza o hash de referência
        echo "$hash_atual" > "$arquivo_hash"
    done
}

# -----------------------------------------------------------------------------
# FUNÇÃO 5 — DETECÇÃO DE TENTATIVAS DE LOGIN FALHADAS
# -----------------------------------------------------------------------------

# Captura tentativas de autenticação falhadas da última hora via log do sistema
capturar_falhas_login() {
    log show \
        --predicate '(eventMessage CONTAINS "Authentication failed") OR (eventMessage CONTAINS "Failed password")' \
        --style syslog \
        --last 1h 2>/dev/null | grep -v "unknown" | while IFS= read -r linha; do

        # Extrai timestamp (3 primeiros campos) e usuário-alvo
        local timestamp
        timestamp=$(echo "$linha" | awk '{print $1, $2, $3}')

        local login
        login=$(echo "$linha" | awk '{
            for (i=1; i<=NF; i++) {
                if ($i == "for" || $i == "user") { print $(i+1); exit }
            }
        }')

        # Ignora entradas sem usuário identificado
        if [ -z "$login" ] || [ -z "$timestamp" ]; then
            continue
        fi

        # Resolve o diretório home do usuário, se existir
        local diretorio_usuario
        diretorio_usuario=$(eval echo "~$login" 2>/dev/null)
        if [ ! -d "$diretorio_usuario" ]; then
            diretorio_usuario="Desconhecido"
        fi

        local chave="$timestamp $login"

        # Evita registrar a mesma tentativa duas vezes
        if ! grep -qF "$chave" "$LOG_FALHAS_LOGIN_PROCESSADAS" 2>/dev/null; then
            local entrada="Tentativa falhada | Usuário: $login | Diretório: $diretorio_usuario"
            registrar_log "$LOG_FALHAS_LOGIN" "$entrada"
            log_terminal "⚠️  $entrada"
            echo "$chave" >> "$LOG_FALHAS_LOGIN_PROCESSADAS"
        fi
    done
}

# -----------------------------------------------------------------------------
# LOOP PRINCIPAL DE MONITORAMENTO
# -----------------------------------------------------------------------------

# Exibe resumo dos logs ao encerrar com Ctrl+C
encerrar() {
    echo ""
    echo "=============================================="
    echo "  Script encerrado. Logs disponíveis em:"
    echo "  $DIRETORIO_REGISTROS"
    echo "  → Hashes:       $LOG_HASHES"
    echo "  → Falhas login: $LOG_FALHAS_LOGIN"
    echo "  → Modificações: $LOG_MODIFICACOES"
    echo "  → Malwares:     $LOG_MALWARES"
    echo "=============================================="
    exit 0
}

trap encerrar SIGINT SIGTERM

# Cabeçalho de inicialização
echo "=============================================="
echo "  Trustly Security Monitor — macOS"
echo "  Iniciado em: $(date '+%d/%m/%Y %H:%M:%S')"
echo "  Logs em: $DIRETORIO_REGISTROS"
echo "  Pressione Ctrl+C para encerrar."
echo "=============================================="
echo ""

# Loop de monitoramento contínuo
while true; do
    log_terminal "--- Iniciando ciclo de verificação ---"

    log_terminal "[1/3] Verificando arquivos em quarentena..."
    verificar_arquivos_quarentena

    log_terminal "[2/3] Verificando tentativas de login falhadas..."
    capturar_falhas_login

    log_terminal "[3/3] Verificando integridade dos arquivos sensíveis..."
    monitorar_arquivos_sensiveis

    log_terminal "--- Ciclo concluído. Próxima verificação em ${INTERVALO}s ---"
    echo ""
    sleep "$INTERVALO"
done
