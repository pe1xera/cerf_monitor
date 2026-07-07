#!/bin/bash

# =============================================================================
# cerf_monitor.sh
# Monitoramento de segurança para macOS — Cerf Security Tool
#
# Funcionalidades:
#   1. Cálculo e registro de hashes SHA-256 de arquivos baixados
#   2. Detecção de tentativas de login falhadas
#   3. Monitoramento de alterações em arquivos sensíveis (sudoers, hosts, etc.)
#   4. Detecção e remoção de malwares via VirusTotal API
#   5. Logs com timestamp para auditoria
#
# Requisitos: macOS (utiliza apenas ferramentas nativas do sistema)
# Uso: bash cerf_monitor.sh
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURAÇÕES
# -----------------------------------------------------------------------------
apiKey="SUA_CHAVE_AQUI"

arquivosSensiveis=(
    "/etc/sudoers"
    "/etc/hosts"
    "/Library/Preferences/com.apple.systempreferences.plist"
)

diretoriosMonitorados=(
    "$HOME/Downloads"
    "$HOME/Desktop"
    "$HOME/Documents"
)

# Diretórios clássicos de persistência no macOS — monitorados recursivamente,
# já que qualquer mudança neles é rara e quase sempre suspeita
diretoriosPersistencia=(
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
    "$HOME/Library/LaunchAgents"
    "/Library/StartupItems"
)

intervalo=10

# -----------------------------------------------------------------------------
# INICIALIZAÇÃO DE DIRETÓRIOS E ARQUIVOS DE LOG
# -----------------------------------------------------------------------------
diretorioScript=$(dirname "$0")
diretorioRegistros="$diretorioScript/registros"

if [ ! -d "$diretorioRegistros" ]; then
    mkdir -p "$diretorioRegistros"
fi

dataAtual=$(date +"%Y-%m-%d")

logHashes="$diretorioRegistros/hashArquivosBaixados_$dataAtual.log"
logProcessados="$diretorioRegistros/arquivosProcessados_$dataAtual.txt"
logFalhasLogin="$diretorioRegistros/falhasLogin_$dataAtual.log"
logFalhasLoginProcessadas="$diretorioRegistros/falhasLoginProcessadas_$dataAtual.txt"
logModificacoes="$diretorioRegistros/modificacoesArquivosSensiveis_$dataAtual.log"
logMalwares="$diretorioRegistros/malwaresDetectados_$dataAtual.log"

touch "$logProcessados" "$logFalhasLoginProcessadas"

# -----------------------------------------------------------------------------
# FUNÇÕES UTILITÁRIAS
# -----------------------------------------------------------------------------
exibir_alerta() {
    local titulo="$1"
    local mensagem="$2"
    osascript -e "display notification \"$mensagem\" with title \"$titulo\" sound name \"Basso\""
}

registrar_log() {
    local arquivoLog="$1"
    local mensagem="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $mensagem" >> "$arquivoLog"
}

log_terminal() {
    echo "[$(date '+%H:%M:%S')] $1"
}

# -----------------------------------------------------------------------------
# FUNÇÃO 1 — CÁLCULO DE HASH E VERIFICAÇÃO NO VIRUSTOTAL
# -----------------------------------------------------------------------------
calcular_hash() {
    local arquivo="$1"

    if [ ! -f "$arquivo" ]; then
        log_terminal "ERRO: Arquivo não encontrado: $arquivo"
        return 1
    fi

    local hashArquivo
    hashArquivo=$(shasum -a 256 "$arquivo" | awk '{print $1}')

    if grep -qF "$arquivo" "$logProcessados" 2>/dev/null; then
        return 0
    fi

    if ! grep -qF "$hashArquivo" "$logHashes" 2>/dev/null; then
        registrar_log "$logHashes" "ARQUIVO: $(basename "$arquivo") | HASH: $hashArquivo | CAMINHO: $arquivo"
        log_terminal "Hash registrado: $(basename "$arquivo") → $hashArquivo"

        verificar_virus_total "$hashArquivo" "$arquivo"
    fi

    echo "$arquivo" >> "$logProcessados"
}

# -----------------------------------------------------------------------------
# FUNÇÃO 2 — VERIFICAÇÃO NO VIRUSTOTAL
# -----------------------------------------------------------------------------
verificar_virus_total() {
    local hashArquivo="$1"
    local arquivo="$2"

    log_terminal "Consultando VirusTotal para: $(basename "$arquivo")..."

    local resposta
    resposta=$(curl --silent --max-time 15 --request GET \
        "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$hashArquivo")

    if [ -z "$resposta" ]; then
        log_terminal "AVISO: Sem resposta do VirusTotal para $(basename "$arquivo"). Verifique sua conexão."
        return 1
    fi

    local responseCode
    responseCode=$(echo "$resposta" | grep -o '"response_code":[0-9]*' | cut -d':' -f2)

    if [ "$responseCode" -eq 0 ] 2>/dev/null; then
        log_terminal "INFO: Arquivo $(basename "$arquivo") não encontrado na base do VirusTotal."
        return 0
    fi

    local positivos
    positivos=$(echo "$resposta" | grep -o '"positives":[0-9]*' | cut -d':' -f2)

    local total
    total=$(echo "$resposta" | grep -o '"total":[0-9]*' | cut -d':' -f2)

    if [ "${positivos:-0}" -gt 0 ] 2>/dev/null; then
        local mensagemAlerta="Malware detectado: $(basename "$arquivo") | Detecções: $positivos/$total antivírus"

        log_terminal "⚠️  ALERTA — $mensagemAlerta"
        registrar_log "$logMalwares" "$mensagemAlerta | HASH: $hashArquivo | CAMINHO: $arquivo"

        exibir_alerta "⚠️ Alerta de Segurança" \
            "Arquivo malicioso detectado: $(basename "$arquivo") ($positivos/$total antivírus). O arquivo será removido."

        if rm -f "$arquivo"; then
            log_terminal "Arquivo removido: $arquivo"
            registrar_log "$logMalwares" "REMOVIDO: $arquivo"
        else
            log_terminal "ERRO: Não foi possível remover $arquivo. Verifique as permissões."
            registrar_log "$logMalwares" "FALHA AO REMOVER: $arquivo"
        fi
    else
        log_terminal "OK: $(basename "$arquivo") verificado — sem ameaças ($positivos/$total)."
    fi
}

# -----------------------------------------------------------------------------
# FUNÇÃO 3 — VERIFICAÇÃO DE ARQUIVOS EM QUARENTENA
# -----------------------------------------------------------------------------
verificar_arquivos_quarentena() {
    for diretorio in "${diretoriosMonitorados[@]}"; do
        if [ ! -d "$diretorio" ]; then
            continue
        fi

        find "$diretorio" -type f -print0 | while IFS= read -r -d '' arquivo; do
            if xattr -p com.apple.quarantine "$arquivo" &>/dev/null; then
                calcular_hash "$arquivo"
            fi
        done
    done
}

# -----------------------------------------------------------------------------
# FUNÇÃO 4 — MONITORAMENTO DE ARQUIVOS SENSÍVEIS
# -----------------------------------------------------------------------------
monitorar_arquivos_sensiveis() {
    for arquivo in "${arquivosSensiveis[@]}"; do
        if [ ! -f "$arquivo" ]; then
            continue
        fi

        local hashAtual
        hashAtual=$(shasum -a 256 "$arquivo" 2>/dev/null | awk '{print $1}')

        if [ -z "$hashAtual" ]; then
            log_terminal "AVISO: Não foi possível calcular hash de $arquivo (sem permissão?)"
            continue
        fi

        local arquivoHash="$diretorioRegistros/hash_${arquivo//\//_}.txt"

        if [ -f "$arquivoHash" ]; then
            local hashAnterior
            hashAnterior=$(cat "$arquivoHash")

            if [ "$hashAtual" != "$hashAnterior" ]; then
                local mensagem="Arquivo sensível modificado: $(basename "$arquivo")"
                log_terminal "⚠️  ALERTA — $mensagem"
                registrar_log "$logModificacoes" "$mensagem | HASH ANTERIOR: $hashAnterior | HASH ATUAL: $hashAtual"
                exibir_alerta "⚠️ Alerta de Segurança" "$mensagem"
            fi
        else
            log_terminal "INFO: Hash base registrado para $(basename "$arquivo")."
        fi

        echo "$hashAtual" > "$arquivoHash"
    done
}

# -----------------------------------------------------------------------------
# FUNÇÃO 5 — MONITORAMENTO RECURSIVO DE DIRETÓRIOS DE PERSISTÊNCIA
# -----------------------------------------------------------------------------
monitorar_diretorios_persistencia() {
    for diretorio in "${diretoriosPersistencia[@]}"; do
        if [ ! -d "$diretorio" ]; then
            continue
        fi

        local arquivoSnapshot="$diretorioRegistros/snapshot_${diretorio//\//_}.txt"

        local snapshotAtual
        snapshotAtual=$(find "$diretorio" -type f -exec shasum -a 256 {} \; 2>/dev/null \
            | awk '{print $2"|"$1}' | sort)

        if [ -f "$arquivoSnapshot" ]; then
            local snapshotAnterior
            snapshotAnterior=$(cat "$arquivoSnapshot")

            local diferencas
            diferencas=$(diff <(echo "$snapshotAnterior") <(echo "$snapshotAtual"))

            if [ -n "$diferencas" ]; then
                local mensagem="Alteração detectada em diretório de persistência: $diretorio"
                log_terminal "⚠️  ALERTA — $mensagem"
                registrar_log "$logModificacoes" "$mensagem | DETALHES: $diferencas"
                exibir_alerta "⚠️ Alerta de Segurança" "$mensagem"
            fi
        else
            log_terminal "INFO: Snapshot base registrado para $diretorio"
        fi

        echo "$snapshotAtual" > "$arquivoSnapshot"
    done
}

# -----------------------------------------------------------------------------
# FUNÇÃO 6 — DETECÇÃO DE TENTATIVAS DE LOGIN FALHADAS
# -----------------------------------------------------------------------------
capturar_falhas_login() {
    log show \
        --predicate '(eventMessage CONTAINS "Authentication failed") OR (eventMessage CONTAINS "Failed password")' \
        --style syslog \
        --last 1h 2>/dev/null | grep -v "unknown" | while IFS= read -r linha; do

        local timestamp
        timestamp=$(echo "$linha" | awk '{print $1, $2, $3}')

        local login
        login=$(echo "$linha" | awk '{
            for (i=1; i<=NF; i++) {
                if ($i == "for" || $i == "user") { print $(i+1); exit }
            }
        }')

        if [ -z "$login" ] || [ -z "$timestamp" ]; then
            continue
        fi

        local diretorioUsuario
        diretorioUsuario=$(eval echo "~$login" 2>/dev/null)
        if [ ! -d "$diretorioUsuario" ]; then
            diretorioUsuario="Desconhecido"
        fi

        local chave="$timestamp $login"

        if ! grep -qF "$chave" "$logFalhasLoginProcessadas" 2>/dev/null; then
            local entrada="Tentativa falhada | Usuário: $login | Diretório: $diretorioUsuario"
            registrar_log "$logFalhasLogin" "$entrada"
            log_terminal "⚠️  $entrada"
            echo "$chave" >> "$logFalhasLoginProcessadas"
        fi
    done
}

# -----------------------------------------------------------------------------
# LOOP PRINCIPAL DE MONITORAMENTO
# -----------------------------------------------------------------------------
encerrar() {
    echo ""
    echo "=============================================="
    echo "  Script encerrado. Logs disponíveis em:"
    echo "  $diretorioRegistros"
    echo "  → Hashes:       $logHashes"
    echo "  → Falhas login: $logFalhasLogin"
    echo "  → Modificações: $logModificacoes"
    echo "  → Malwares:     $logMalwares"
    echo "=============================================="
    exit 0
}

trap encerrar SIGINT SIGTERM

echo "=============================================="
echo "  Cerf Security Monitor — macOS"
echo "  Iniciado em: $(date '+%d/%m/%Y %H:%M:%S')"
echo "  Logs em: $diretorioRegistros"
echo "  Pressione Ctrl+C para encerrar."
echo "=============================================="
echo ""

while true; do
    log_terminal "--- Iniciando ciclo de verificação ---"

    log_terminal "[1/4] Verificando arquivos em quarentena..."
    verificar_arquivos_quarentena

    log_terminal "[2/4] Verificando tentativas de login falhadas..."
    capturar_falhas_login

    log_terminal "[3/4] Verificando integridade dos arquivos sensíveis..."
    monitorar_arquivos_sensiveis

    log_terminal "[4/4] Verificando diretórios de persistência..."
    monitorar_diretorios_persistencia

    log_terminal "--- Ciclo concluído. Próxima verificação em ${intervalo}s ---"
    echo ""
    sleep "$intervalo"
done
