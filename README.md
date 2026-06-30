# Cerf Monitor

Solução open-source, em shell script, para monitoramento da segurança das workstations da empresa Trustly. Trata-se do projeto de um client instalável que coleta logs de diversas fontes, normaliza e encaminha para outros serviços, a fim de que possam ser visualizados pelo time responsável pela tomada de decisões.

<img width="796" height="540" alt="image" src="https://github.com/user-attachments/assets/3fff9019-2013-4c45-a668-a758c28fc4ff" />

> **Nota:** este repositório contém uma **versão adaptada** do script original. **Não é a versão final apresentada à Trustly**, mas sim uma recriação para fins de portfólio, mantendo o mesmo conceito e a mesma lógica de funcionamento.

O projeto nasceu no primeiro ano da faculdade de Defesa Cibernética (FIAP), com o  objetivo de construir uma ferramenta de monitoramento de comportamentos anômalos em endpoints, utilizando **exclusivamente recursos nativos do sistema operacional**, sem qualquer biblioteca externa ou dependência adicional. Essa decisão foi tomada desde o início para garantir **portabilidade**, permitindo que o client funcione independentemente da versão do macOS ou do que já esteja previamente instalado na máquina.

## Funcionalidades

- **Cálculo de hash de arquivos baixados** — todo arquivo com atributo de quarentena (baixado da internet) tem seu hash SHA-256 calculado e registrado.
- **Verificação de malware via VirusTotal** — o hash de cada arquivo é consultado na API pública do VirusTotal; arquivos identificados como maliciosos são automaticamente removidos e um alerta é exibido ao usuário.
- **Monitoramento de arquivos sensíveis** — alterações em arquivos críticos do sistema (`/etc/sudoers`, `/etc/hosts`, preferências do macOS, usuários administradores) são detectadas por comparação de hash e notificadas em tempo real.
- **Detecção de tentativas de login falhadas** — captura e registra tentativas de autenticação sem sucesso, identificando o usuário-alvo e o diretório envolvido.
- **Alertas nativos do sistema** — notificações via `osascript`, sem necessidade de agentes ou serviços de terceiros.
- **Logs estruturados com timestamp** — todas as ocorrências são persistidas em arquivos de log diários, prontos para auditoria ou para ingestão por outras ferramentas (SIEM, dashboards, etc.).

## Motivação e arquitetura

A proposta central do projeto é funcionar como um **client leve e instalável** em estações de trabalho corporativas, coletando eventos de segurança de diferentes fontes do sistema operacional (sistema de arquivos, autenticação, integridade de arquivos), normalizando essas informações em um formato de log consistente, e deixando-as prontas para serem encaminhadas a serviços externos de visualização e análise — permitindo que o time de segurança tenha visibilidade centralizada sobre o comportamento das máquinas da empresa.

Por ser escrito inteiramente em shell script, o client roda nativamente em qualquer macOS sem necessidade de runtime, instalação de pacotes ou configuração de ambiente, o que reduz drasticamente a superfície de ataque e a complexidade de implantação em escala.

## Requisitos

- macOS (utiliza `osascript`, `xattr` e `log show`, nativos do sistema)
- `curl` (nativo do macOS)
- Chave de API do [VirusTotal](https://www.virustotal.com/gui/my-apikey) (gratuita)

## Instalação e uso

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/cerf-sentinel.git
cd cerf-sentinel

# Insira sua chave de API do VirusTotal no script
sed -i '' 's/SUA_CHAVE_AQUI/sua_chave_real/' monitor_seguranca.sh

# Dê permissão de execução
chmod +x monitor_seguranca.sh

# Execute o monitoramento
./monitor_seguranca.sh
```

O script roda em loop contínuo, verificando o sistema em intervalos configuráveis (10 segundos por padrão), até ser interrompido com `Ctrl+C`.

## Estrutura de logs

Todos os registros são salvos na pasta `registros/`, criada automaticamente no diretório do script, com um arquivo por categoria e por data:

```
registros/
├── hashArquivosBaixados_YYYY-MM-DD.log
├── arquivosProcessados_YYYY-MM-DD.txt
├── falhasLogin_YYYY-MM-DD.log
├── falhasLoginProcessadas_YYYY-MM-DD.txt
├── modificacoesArquivosSensiveis_YYYY-MM-DD.log
└── malwaresDetectados_YYYY-MM-DD.log
```

Cada entrada de log contém timestamp, nome do arquivo/usuário envolvido e detalhes do evento, facilitando tanto a leitura manual quanto a ingestão automatizada por outras ferramentas.

## Configuração

As principais variáveis podem ser ajustadas no início do script:

| Variável | Descrição |
|---|---|
| `API_KEY` | Chave de API do VirusTotal |
| `ARQUIVOS_SENSIVEIS` | Lista de arquivos críticos a serem monitorados |
| `DIRETORIOS_MONITORADOS` | Diretórios verificados quanto a arquivos em quarentena |
| `INTERVALO` | Intervalo, em segundos, entre cada ciclo de verificação |

## Licença

Este projeto é open-source e está disponível sob a licença MIT. Sinta-se livre para usar, modificar e distribuir.
