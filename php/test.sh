#!/usr/bin/env bash
# test.sh — PHP eadrese SDK lokālās testēšanas helper
# Izmantošana:
#   ./test.sh cert_validate
#   ./test.sh send
#   ./test.sh get_message_list
#   ./test.sh receive_and_confirm
#   ./test.sh search_addressee
#   ./test.sh poll_notifications
#   ./test.sh get_public_key_list
#
# Pirmā palaišana: ./test.sh --setup   (ekstraktē PEM no p12, build image)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
SECRETS_DIR="$REPO_ROOT/.secrets/eadrese"
CERTS_DIR="$SCRIPT_DIR/.test-certs"
IMAGE="eadrese-php-test:local"

# ── sertifikātu ekstrakcija ──────────────────────────────────────────────────
setup_certs() {
    echo "[setup] Ekstraktē sertifikātus no client.p12 ..."
    mkdir -p "$CERTS_DIR"
    P12="$SECRETS_DIR/client.p12"
    PASS_FILE="$SECRETS_DIR/zip_pass.txt"
    if [[ -f "$PASS_FILE" ]]; then
        PASS="$(tr -d '\n\r' < "$PASS_FILE")"
    else
        echo "[setup] Nav atrasts $PASS_FILE — izmanto DIV_P12_PASS vai ievadi manuāli." >&2
        PASS="${DIV_P12_PASS:-}"
        if [[ -z "$PASS" ]]; then
            read -r -s -p "P12 parole: " PASS; echo
        fi
    fi

    # Klienta sertifikāts (mTLS + parakstīšana)
    openssl pkcs12 -in "$P12" -passin "pass:$PASS" -nokeys -clcerts \
        2>/dev/null | openssl x509 > "$CERTS_DIR/client.crt.pem"

    # Privātā atslēga
    openssl pkcs12 -in "$P12" -passin "pass:$PASS" -nocerts -nodes \
        2>/dev/null > "$CERTS_DIR/client.key.pem"

    # CA ķēde (vajadzīga WSSE validācijai)
    openssl pkcs12 -in "$P12" -passin "pass:$PASS" -nokeys -cacerts \
        2>/dev/null > "$CERTS_DIR/chain.pem" || true

    echo "[setup] Sertifikāti saglabāti: $CERTS_DIR"
    openssl x509 -in "$CERTS_DIR/client.crt.pem" -noout \
        -subject -issuer -dates
}

# ── docker image build ───────────────────────────────────────────────────────
build_image() {
    echo "[build] Būvē Docker image $IMAGE ..."
    docker build -t "$IMAGE" "$SCRIPT_DIR"
    echo "[build] Gatavs."
}

# ── palīgfunkcija: nolasa .env.test ─────────────────────────────────────────
load_env() {
    ENV_FILE="$SCRIPT_DIR/.env.test"
    if [[ ! -f "$ENV_FILE" ]]; then
        echo "[kļūda] Nav atrasts $ENV_FILE — kopē .env.test.example un aizpildi!" >&2
        exit 1
    fi
    # Eksportē mainīgos (izlaiž komentārus un tukšās rindas)
    set -o allexport
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +o allexport
}

# ── galvenā palaišana ────────────────────────────────────────────────────────
run_example() {
    local example="$1"
    shift
    local script

    case "$example" in
        cert_validate)    script="examples/soap_cert_validate.php" ;;
        send)             script="examples/soap_send.php" ;;
        get_message_list) script="examples/soap_get_message_list.php" ;;
        get_message)      script="examples/soap_get_message.php" ;;
        receive_and_confirm) script="examples/soap_receive_and_confirm.php" ;;
        search_addressee) script="examples/soap_search_addressee.php" ;;
        poll_notifications) script="examples/soap_poll_notifications.php" ;;
        get_public_key_list) script="examples/soap_get_public_key_list.php" ;;
        confirm_notifications) script="examples/soap_confirm_notification_list.php" ;;
        *)
            echo "Nezināms piemērs: $example" >&2
            echo "Pieejamie: cert_validate send get_message_list get_message receive_and_confirm" >&2
            echo "           search_addressee poll_notifications get_public_key_list confirm_notifications" >&2
            exit 1
            ;;
    esac

    load_env

    echo "[run] php $script $*"
    docker run --rm \
        -v "$SCRIPT_DIR:/app:ro" \
        -v "$CERTS_DIR:/certs:ro" \
        -e DIV_WSDL_URL="${DIV_WSDL_URL:-}" \
        -e DIV_CLIENT_CERT="${DIV_CLIENT_CERT:-/certs/client.crt.pem}" \
        -e DIV_CLIENT_KEY="${DIV_CLIENT_KEY:-/certs/client.key.pem}" \
        -e DIV_SIGN_CERT="${DIV_SIGN_CERT:-/certs/client.crt.pem}" \
        -e DIV_SIGN_KEY="${DIV_SIGN_KEY:-/certs/client.key.pem}" \
        -e DIV_SENDER="${DIV_SENDER:-}" \
        -e DIV_RECIPIENT="${DIV_RECIPIENT:-}" \
        -e DIV_VERIFY_SSL="${DIV_VERIFY_SSL:-0}" \
        -e DIV_LOOKUP_VALUES="${DIV_LOOKUP_VALUES:-}" \
        -e DIV_CONFIRM="${DIV_CONFIRM:-0}" \
        -e DIV_DEBUG_DIR="${DIV_DEBUG_DIR:-}" \
        -e DIV_MSG_SUBJECT="${DIV_MSG_SUBJECT:-}" \
        -e DIV_MSG_BODY="${DIV_MSG_BODY:-}" \
        "$IMAGE" php "/app/$script" "$@"
}

# ── komandu apstrāde ─────────────────────────────────────────────────────────
CMD="${1:-}"

case "$CMD" in
    --setup)
        setup_certs
        build_image
        echo ""
        echo "Gatavs! Izmanto:"
        echo "  ./test.sh cert_validate"
        echo "  ./test.sh get_message_list"
        ;;
    --build)
        build_image
        ;;
    --certs)
        setup_certs
        ;;
    "")
        echo "Izmantošana: ./test.sh <komanda>"
        echo "  --setup              Ekstraktē certs + build image"
        echo "  --build              Tikai build image"
        echo "  --certs              Tikai ekstraktē certs"
        echo "  cert_validate        Pārbauda savienojumu ar VRAA"
        echo "  send                 Nosūta testa ziņu"
        echo "  get_message_list     Saraksts ar ienākošajām ziņām"
        echo "  get_message          Iegūst konkrētu ziņu (DIV_MSG_ID=...)"
        echo "  receive_and_confirm  Saņem nākamo ziņu (+ DIV_CONFIRM=1)"
        echo "  search_addressee     Meklē saņēmēju (DIV_LOOKUP_VALUES=...)"
        echo "  poll_notifications   Iegūst notifikācijas"
        ;;
    *)
        run_example "$@"
        ;;
esac
