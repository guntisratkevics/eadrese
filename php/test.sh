#!/usr/bin/env bash
# test.sh — Docker-based PHP SDK test helper
#
# Quick start:
#   ./test.sh --setup
#   ./test.sh lint
#   ./test.sh unit
#   ./test.sh vraa_smoke
#
# Individual examples still work:
#   ./test.sh cert_validate
#   ./test.sh send
#   ./test.sh get_message_list
#   ./test.sh receive_and_confirm

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SECRETS_DIR="$REPO_ROOT/.secrets/eadrese"
CERTS_DIR="$SCRIPT_DIR/.test-certs"
DEBUG_DIR_DEFAULT="$SCRIPT_DIR/.debug"
COMPOSER_CACHE_DIR="$SCRIPT_DIR/.docker-cache/composer"
IMAGE="eadrese-php-test:local"
ENV_FILE="$SCRIPT_DIR/.env.test"

COMMON_ENV_VARS=(
    DIV_WSDL_URL
    DIV_CLIENT_CERT
    DIV_CLIENT_KEY
    DIV_SIGN_CERT
    DIV_SIGN_KEY
    DIV_SENDER
    DIV_RECIPIENT
    DIV_RECIPIENTS
    DIV_VERIFY_SSL
    DIV_LOOKUP_VALUES
    DIV_LOOKUP_VALUE
    DIV_CONFIRM
    DIV_MSG_SUBJECT
    DIV_MSG_BODY
    DIV_MESSAGE_ID
    DIV_MSG_ID
    DIV_NOTIFICATION_IDS
    DIV_MAX_RESULT_COUNT
    DIV_MAX_ITEMS
    DIV_ADDRESSEE_UNIT_ID
    DIV_CONTINUATION_TOKEN
    DIV_ALL_PAGES
    DIV_PRINT_MAX
    DIV_EADDRESSES
    DIV_EADDRESS_TYPE
    DIV_LAST_VERSION
    DIV_PRINT_HEADERS
    DIV_PRINT_RESULTS
    DIV_PRINT_NOTIFICATIONS
    DIV_PRINT_KEYS
    DIV_PRINT_ENVELOPE
    DIV_DEBUG_RAW
    DIV_AUTO_CONFIRM
    DIV_INCLUDE_RESTRICTED_OPS
    DIV_RUN_SEND
    DIV_RUN_EINVOICE
    DIV_RUN_RECEIVE
    DIV_RUN_SERVER_CONFIRM
)

setup_certs() {
    echo "[setup] Ekstraktē sertifikātus no client.p12 ..."
    mkdir -p "$CERTS_DIR"
    local p12="$SECRETS_DIR/client.p12"
    local pass_file="$SECRETS_DIR/zip_pass.txt"
    local pass
    if [[ -f "$pass_file" ]]; then
        pass="$(tr -d '\n\r' < "$pass_file")"
    else
        echo "[setup] Nav atrasts $pass_file — izmanto DIV_P12_PASS vai ievadi manuāli." >&2
        pass="${DIV_P12_PASS:-}"
        if [[ -z "$pass" ]]; then
            read -r -s -p "P12 parole: " pass
            echo
        fi
    fi

    openssl pkcs12 -in "$p12" -passin "pass:$pass" -nokeys -clcerts \
        2>/dev/null | openssl x509 > "$CERTS_DIR/client.crt.pem"
    openssl pkcs12 -in "$p12" -passin "pass:$pass" -nocerts -nodes \
        2>/dev/null > "$CERTS_DIR/client.key.pem"
    openssl pkcs12 -in "$p12" -passin "pass:$pass" -nokeys -cacerts \
        2>/dev/null > "$CERTS_DIR/chain.pem" || true

    echo "[setup] Sertifikāti saglabāti: $CERTS_DIR"
    openssl x509 -in "$CERTS_DIR/client.crt.pem" -noout -subject -issuer -dates
}

build_image() {
    echo "[build] Būvē Docker image $IMAGE ..."
    docker build -t "$IMAGE" "$SCRIPT_DIR"
    echo "[build] Gatavs."
}

ensure_image() {
    if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        build_image
    fi
}

load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        set -o allexport
        # shellcheck disable=SC1090
        source "$ENV_FILE"
        set +o allexport
    fi
}

first_token_from_list() {
    local raw="${1:-}"
    local first
    first="$(printf '%s\n' "$raw" | tr ',;' '  ' | awk '{print $1}')"
    printf '%s' "${first:-}"
}

normalize_env() {
    export DIV_WSDL_URL="${DIV_WSDL_URL:-https://divtest.vraa.gov.lv/Vraa.Div.WebService.UnifiedInterface/UnifiedService.svc?wsdl}"
    export DIV_CLIENT_CERT="${DIV_CLIENT_CERT:-/certs/client.crt.pem}"
    export DIV_CLIENT_KEY="${DIV_CLIENT_KEY:-/certs/client.key.pem}"
    export DIV_SIGN_CERT="${DIV_SIGN_CERT:-$DIV_CLIENT_CERT}"
    export DIV_SIGN_KEY="${DIV_SIGN_KEY:-$DIV_CLIENT_KEY}"
    export DIV_VERIFY_SSL="${DIV_VERIFY_SSL:-0}"
    export DIV_CONFIRM="${DIV_CONFIRM:-0}"
    export DIV_ALL_PAGES="${DIV_ALL_PAGES:-1}"
    export DIV_PRINT_MAX="${DIV_PRINT_MAX:-5}"
    export DIV_MAX_RESULT_COUNT="${DIV_MAX_RESULT_COUNT:-10}"
    export DIV_MAX_ITEMS="${DIV_MAX_ITEMS:-50}"
    export DIV_AUTO_CONFIRM="${DIV_AUTO_CONFIRM:-1}"
    export DIV_INCLUDE_RESTRICTED_OPS="${DIV_INCLUDE_RESTRICTED_OPS:-0}"
    export DIV_RUN_SEND="${DIV_RUN_SEND:-1}"
    export DIV_RUN_EINVOICE="${DIV_RUN_EINVOICE:-1}"
    export DIV_RUN_RECEIVE="${DIV_RUN_RECEIVE:-1}"
    export DIV_RUN_SERVER_CONFIRM="${DIV_RUN_SERVER_CONFIRM:-1}"

    if [[ -z "${DIV_RECIPIENTS:-}" && -n "${DIV_RECIPIENT:-}" ]]; then
        export DIV_RECIPIENTS="$DIV_RECIPIENT"
    fi
    if [[ -z "${DIV_LOOKUP_VALUE:-}" && -n "${DIV_LOOKUP_VALUES:-}" ]]; then
        export DIV_LOOKUP_VALUE="$(first_token_from_list "$DIV_LOOKUP_VALUES")"
    fi
    if [[ -z "${DIV_EADDRESSES:-}" && -n "${DIV_RECIPIENTS:-}" ]]; then
        export DIV_EADDRESSES="$DIV_RECIPIENTS"
    fi
    if [[ -z "${DIV_MESSAGE_ID:-}" && -n "${DIV_MSG_ID:-}" ]]; then
        export DIV_MESSAGE_ID="$DIV_MSG_ID"
    fi
    if [[ -z "${DIV_MSG_ID:-}" && -n "${DIV_MESSAGE_ID:-}" ]]; then
        export DIV_MSG_ID="$DIV_MESSAGE_ID"
    fi
}

docker_base_args() {
    local -n _out=$1
    _out=(docker run --rm -i)
    _out+=(-v "$SCRIPT_DIR:/workspace:ro")
}

add_debug_mount() {
    local -n _args=$1
    local debug_dir="${DIV_DEBUG_DIR:-}"
    if [[ -n "$debug_dir" ]]; then
        local host_debug="$debug_dir"
        if [[ "$host_debug" != /* ]]; then
            host_debug="$SCRIPT_DIR/$host_debug"
        fi
        mkdir -p "$host_debug"
        _args+=(-v "$host_debug:/debug")
        _args+=(-e "DIV_DEBUG_DIR=/debug")
    fi
}

add_env_args() {
    local -n _args=$1
    local var
    for var in "${COMMON_ENV_VARS[@]}"; do
        _args+=(-e "$var=${!var-}")
    done
}

run_container_workspace_cmd() {
    local cmd="$1"
    ensure_image
    local args
    docker_base_args args
    args+=(-v "$CERTS_DIR:/certs:ro")
    mkdir -p "$COMPOSER_CACHE_DIR"
    args+=(-v "$COMPOSER_CACHE_DIR:/tmp/composer-cache")
    add_debug_mount args
    add_env_args args
    args+=("$IMAGE" bash -lc "$cmd")
    "${args[@]}"
}

lint_php() {
    echo "[lint] PHP syntax checks"
    run_container_workspace_cmd '
set -euo pipefail
cd /workspace
find src examples tests -type f -name "*.php" -print0 | xargs -0 -n1 php -l
'
}

run_unit_tests() {
    echo "[unit] PHPUnit in Docker"
    run_container_workspace_cmd '
set -euo pipefail
rm -rf /tmp/app
mkdir -p /tmp/app
cp -a /workspace/. /tmp/app
cd /tmp/app
export COMPOSER_CACHE_DIR=/tmp/composer-cache
composer install --no-interaction --prefer-dist --no-progress
vendor/bin/phpunit --colors=always
'
}

example_to_script() {
    case "$1" in
        cert_validate) echo "examples/soap_cert_validate.php" ;;
        send) echo "examples/soap_send.php" ;;
        send_einvoice) echo "examples/test_einvoice.php" ;;
        get_message_list) echo "examples/soap_get_message_list.php" ;;
        get_message) echo "examples/soap_get_message.php" ;;
        receive_and_confirm) echo "examples/soap_receive_and_confirm.php" ;;
        search_addressee) echo "examples/soap_search_addressee.php" ;;
        get_notification_list) echo "examples/soap_get_notification_list.php" ;;
        poll_notifications) echo "examples/soap_poll_notifications.php" ;;
        get_public_key_list) echo "examples/soap_get_public_key_list.php" ;;
        confirm_notifications) echo "examples/soap_confirm_notification_list.php" ;;
        get_addressee_list) echo "examples/soap_get_addressee_list.php" ;;
        validate_eaddress) echo "examples/soap_validate_eaddress.php" ;;
        get_server_confirm) echo "examples/soap_get_message_server_confirmation.php" ;;
        send_raw_envelope) echo "examples/soap_send_raw_envelope.php" ;;
        *)
            echo "Nezināms piemērs: $1" >&2
            return 1
            ;;
    esac
}

run_example_capture() {
    local example="$1"
    shift || true
    load_env
    normalize_env
    local script
    script="$(example_to_script "$example")"
    echo "[run] php $script $*" >&2
    run_container_workspace_cmd "set -euo pipefail; cd /workspace; php \"$script\" $*"
}

run_example() {
    run_example_capture "$@"
}

extract_json_field() {
    local field="$1"
    local raw="${2:-}"
    JSON_INPUT="$raw" python3 -c '
import json
import os
import sys

field = sys.argv[1]
raw = os.environ.get("JSON_INPUT", "").strip()
if not raw:
    sys.exit(0)
try:
    data = json.loads(raw)
except Exception:
    sys.exit(0)
value = data.get(field)
if value is None:
    sys.exit(0)
if isinstance(value, (dict, list)):
    print(json.dumps(value))
else:
    print(value)
' "$field"
}

run_vraa_smoke() {
    load_env
    normalize_env

    echo "[matrix] Docker lint + PHPUnit + VRAA TEST smoke"
    lint_php
    run_unit_tests

    local output
    output="$(run_example_capture cert_validate)"
    echo "$output"

    output="$(run_example_capture search_addressee)"
    echo "$output"

    output="$(run_example_capture get_message_list)"
    echo "$output"

    output="$(run_example_capture get_notification_list)"
    echo "$output"

    output="$(run_example_capture poll_notifications)"
    echo "$output"

    if [[ -n "${DIV_RECIPIENTS:-}" ]]; then
        output="$(run_example_capture get_public_key_list)"
        echo "$output"
    else
        echo "[skip] get_public_key_list — DIV_RECIPIENTS/DIV_RECIPIENT nav iestatīts"
    fi

    local sent_message_id=""
    if [[ "${DIV_RUN_SEND:-1}" != "0" && -n "${DIV_RECIPIENT:-}" ]]; then
        output="$(run_example_capture send)"
        echo "$output"
        sent_message_id="$(extract_json_field message_id "$output" || true)"
    else
        echo "[skip] send — DIV_RUN_SEND=0 vai DIV_RECIPIENT nav iestatīts"
    fi

    if [[ "${DIV_RUN_EINVOICE:-1}" != "0" && -n "${DIV_RECIPIENT:-}" ]]; then
        output="$(run_example_capture send_einvoice)"
        echo "$output"
    else
        echo "[skip] send_einvoice — DIV_RUN_EINVOICE=0 vai DIV_RECIPIENT nav iestatīts"
    fi

    if [[ -n "${DIV_MESSAGE_ID:-}" ]]; then
        output="$(run_example_capture get_message)"
        echo "$output"
    else
        echo "[skip] get_message — DIV_MESSAGE_ID nav iestatīts"
    fi

    if [[ "${DIV_RUN_RECEIVE:-1}" != "0" ]]; then
        output="$(run_example_capture receive_and_confirm)"
        echo "$output"
    else
        echo "[skip] receive_and_confirm — DIV_RUN_RECEIVE=0"
    fi

    if [[ "${DIV_RUN_SERVER_CONFIRM:-1}" != "0" && -n "$sent_message_id" ]]; then
        local old_msg_id="${DIV_MSG_ID:-}"
        local old_message_id="${DIV_MESSAGE_ID:-}"
        export DIV_MSG_ID="$sent_message_id"
        export DIV_MESSAGE_ID="$sent_message_id"
        output="$(run_example_capture get_server_confirm)"
        echo "$output"
        export DIV_MSG_ID="$old_msg_id"
        export DIV_MESSAGE_ID="$old_message_id"
    else
        echo "[skip] get_server_confirm — nav tikko nosūtīta message_id vai DIV_RUN_SERVER_CONFIRM=0"
    fi

    if [[ "${DIV_INCLUDE_RESTRICTED_OPS:-0}" != "0" ]]; then
        output="$(run_example_capture get_addressee_list)"
        echo "$output"
        output="$(run_example_capture validate_eaddress)"
        echo "$output"
    else
        echo "[skip] get_addressee_list / validate_eaddress — restricted VRAA ops, ieslēdz DIV_INCLUDE_RESTRICTED_OPS=1 tikai ja kontam ir tiesības"
    fi
}

print_help() {
    cat <<'EOF'
Izmantošana: ./test.sh <komanda>

Setup:
  --setup              Ekstraktē certs + build image
  --build              Tikai build image
  --certs              Tikai ekstraktē certs

Local-in-Docker checks:
  lint                 PHP syntax checks (`php -l`) visiem src/examples/tests failiem
  unit                 PHPUnit Docker konteinerā ar Composer
  vraa_smoke           lint + unit + VRAA TEST smoke matrix
  all                  Alias uz `vraa_smoke`

Individual VRAA examples:
  cert_validate
  send
  send_einvoice
  get_message_list
  get_message          Iegūst konkrētu ziņu (DIV_MESSAGE_ID vai DIV_MSG_ID)
  receive_and_confirm  Saņem nākamo ziņu (+ DIV_CONFIRM=1)
  search_addressee
  get_notification_list
  poll_notifications
  get_public_key_list
  confirm_notifications
  get_addressee_list
  validate_eaddress
  get_server_confirm   Iegūst servera apstiprinājumu ziņai (DIV_MSG_ID)
  send_raw_envelope

Pamata env:
  Copy `./.env.test.example` -> `./.env.test`
  Fill at least:
    DIV_SENDER
    DIV_RECIPIENT
    DIV_LOOKUP_VALUES

Papildu matrix toggles:
  DIV_INCLUDE_RESTRICTED_OPS=1   # only for government-authorized accounts
  DIV_RUN_SEND=0
  DIV_RUN_EINVOICE=0
  DIV_RUN_RECEIVE=0
  DIV_RUN_SERVER_CONFIRM=0
EOF
}

cmd="${1:-}"
shift || true

case "$cmd" in
    --setup)
        setup_certs
        build_image
        echo
        echo "Gatavs. Tālāk:"
        echo "  ./test.sh lint"
        echo "  ./test.sh unit"
        echo "  ./test.sh vraa_smoke"
        ;;
    --build)
        build_image
        ;;
    --certs)
        setup_certs
        ;;
    lint)
        lint_php
        ;;
    unit)
        run_unit_tests
        ;;
    vraa_smoke|all)
        run_vraa_smoke
        ;;
    "")
        print_help
        ;;
    *)
        run_example "$cmd" "$@"
        ;;
esac
