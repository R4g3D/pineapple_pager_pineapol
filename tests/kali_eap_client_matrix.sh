#!/usr/bin/env bash
#
# Kali-side integration harness for pinEAPol in an explicitly authorised lab.
# It drives a dedicated wireless adapter through capture-relevant EAP client
# configurations, waits for each attempt, then cleanly disconnects.
#
# This script does not alter the Pager. Review the selected profiles and target
# before using --run. It must be run as root on Kali with a dedicated adapter.

set -euo pipefail

SCRIPT_NAME=${0##*/}
IFACE=""
SSID=""
IDENTITY="pinEAPol-test"
PASSWORD=""
CA_CERT=""
PROFILES="all"
ATTEMPT_SECONDS=12
RUN_CONFIRMED=0
SUPPLICANT_PID=""
WORK_DIR=""

usage() {
    cat <<EOF
Usage: sudo ./$SCRIPT_NAME --run --iface <wireless-interface> --ssid <test-ssid> [options]

Required:
  --run                       Confirm this is an authorised lab test.
  --iface <interface>         Dedicated Kali Wi-Fi adapter (for example wlan1).
  --ssid <ssid>               pinEAPol test AP SSID.

Options:
  --identity <identity>       EAP identity (default: $IDENTITY).
  --password <password>       Test password. If omitted, prompt securely once.
  --ca-cert <path>            CA certificate to validate the test AP.
  --profiles <list>           Comma-separated profiles, or all (default: all).
                              Profiles: eap-md5,eap-gtc,eap-mschapv2,
                              ttls-pap,ttls-gtc,ttls-chap,ttls-mschap,
                              ttls-mschapv2,ttls-eap-md5,ttls-eap-gtc,
                              ttls-eap-mschapv2,peap-md5,peap-gtc,
                              peap-mschapv2,fast-gtc,fast-mschapv2
  --attempt-seconds <n>       Maximum time per profile (default: $ATTEMPT_SECONDS).
  --help                      Show this help.

Without --ca-cert, the test AP's certificate identity is not verified.
Use only against the Pager AP you control in an authorised test environment.
EOF
}

die() {
    printf '%s\n' "Error: $*" >&2
    exit 1
}

cleanup() {
    if [ -n "$SUPPLICANT_PID" ] && kill -0 "$SUPPLICANT_PID" 2>/dev/null; then
        kill "$SUPPLICANT_PID" 2>/dev/null || true
        wait "$SUPPLICANT_PID" 2>/dev/null || true
    fi
    [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] && rm -rf -- "$WORK_DIR"
}
trap cleanup EXIT INT TERM

wpa_quote() {
    local value="$1"

    case "$value" in
        *$'\n'*|*$'\r'*) die "wpa_supplicant values cannot contain line breaks." ;;
    esac
    value=${value//\\/\\\\}
    value=${value//\"/\\\"}
    printf '"%s"' "$value"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --run) RUN_CONFIRMED=1 ;;
        --iface) IFACE=${2:?}; shift ;;
        --ssid) SSID=${2:?}; shift ;;
        --identity) IDENTITY=${2:?}; shift ;;
        --password) PASSWORD=${2:?}; shift ;;
        --ca-cert) CA_CERT=${2:?}; shift ;;
        --profiles) PROFILES=${2:?}; shift ;;
        --attempt-seconds) ATTEMPT_SECONDS=${2:?}; shift ;;
        --help|-h) usage; exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
    shift
done

[ "$RUN_CONFIRMED" -eq 1 ] || die "Pass --run to confirm authorised use."
[ "$(id -u)" -eq 0 ] || die "Run this script as root."
[ -n "$IFACE" ] || die "--iface is required."
[ -n "$SSID" ] || die "--ssid is required."
case "$ATTEMPT_SECONDS" in ''|*[!0-9]*|0) die "--attempt-seconds must be a positive integer." ;; esac
ip link show "$IFACE" >/dev/null 2>&1 || die "Interface not found: $IFACE"
command -v wpa_supplicant >/dev/null 2>&1 || die "wpa_supplicant is required."
command -v wpa_cli >/dev/null 2>&1 || die "wpa_cli is required."

if wpa_cli -i "$IFACE" status >/dev/null 2>&1; then
    die "An existing wpa_supplicant controls $IFACE; use a dedicated, unmanaged adapter."
fi

if [ -n "$CA_CERT" ]; then
    [ -r "$CA_CERT" ] || die "Cannot read CA certificate: $CA_CERT"
else
    printf '%s\n' "Warning: no CA certificate supplied; the test AP certificate will not be validated." >&2
fi

if [ -z "$PASSWORD" ]; then
    read -r -s -p "Test password: " PASSWORD
    printf '\n' >&2
fi
[ -n "$PASSWORD" ] || die "A non-empty test password is required."

WORK_DIR=$(mktemp -d /tmp/pineapol-kali-matrix.XXXXXX)
chmod 700 "$WORK_DIR"
mkdir -p "$WORK_DIR/control"
ip link set "$IFACE" up

# Keep the default matrix in broad eap_users offer order. TLS is deliberately
# absent because it does not provide password or challenge-response evidence.
profile_list=(
    eap-md5 eap-gtc eap-mschapv2
    ttls-pap ttls-gtc ttls-chap ttls-mschap ttls-mschapv2
    ttls-eap-md5 ttls-eap-gtc ttls-eap-mschapv2
    peap-md5 peap-gtc peap-mschapv2
    fast-gtc fast-mschapv2
)
if [ "$PROFILES" != "all" ]; then
    IFS=',' read -r -a profile_list <<< "$PROFILES"
fi

write_network() {
    local profile="$1"
    local conf_file="$2"
    local phase2=""
    local phase1=""
    local pac_file=""
    local eap=""

    case "$profile" in
        ttls-pap) eap="TTLS"; phase2='auth=PAP' ;;
        ttls-gtc) eap="TTLS"; phase2='autheap=GTC' ;;
        ttls-chap) eap="TTLS"; phase2='auth=CHAP' ;;
        ttls-mschap) eap="TTLS"; phase2='auth=MSCHAP' ;;
        ttls-mschapv2) eap="TTLS"; phase2='auth=MSCHAPV2' ;;
        ttls-eap-md5) eap="TTLS"; phase2='autheap=MD5' ;;
        ttls-eap-gtc) eap="TTLS"; phase2='autheap=GTC' ;;
        ttls-eap-mschapv2) eap="TTLS"; phase2='autheap=MSCHAPV2' ;;
        peap-md5) eap="PEAP"; phase2='autheap=MD5' ;;
        peap-gtc) eap="PEAP"; phase2='autheap=GTC' ;;
        peap-mschapv2) eap="PEAP"; phase2='autheap=MSCHAPV2' ;;
        fast-gtc) eap="FAST"; phase2='autheap=GTC'; phase1='fast_provisioning=1'; pac_file="$WORK_DIR/fast.pac" ;;
        fast-mschapv2) eap="FAST"; phase2='autheap=MSCHAPV2'; phase1='fast_provisioning=1'; pac_file="$WORK_DIR/fast.pac" ;;
        eap-md5) eap="MD5" ;;
        eap-mschapv2) eap="MSCHAPV2" ;;
        eap-gtc) eap="GTC" ;;
        *) die "Unknown profile: $profile" ;;
    esac

    {
        printf 'ctrl_interface=%s\n' "$WORK_DIR/control"
        printf 'update_config=0\n'
        printf 'network={\n'
        printf '    ssid=%s\n' "$(wpa_quote "$SSID")"
        printf '    key_mgmt=WPA-EAP\n'
        printf '    eap=%s\n' "$eap"
        printf '    identity=%s\n' "$(wpa_quote "$IDENTITY")"
        printf '    password=%s\n' "$(wpa_quote "$PASSWORD")"
        [ -n "$phase1" ] && printf '    phase1="%s"\n' "$phase1"
        [ -n "$phase2" ] && printf '    phase2="%s"\n' "$phase2"
        [ -n "$pac_file" ] && printf '    pac_file=%s\n' "$(wpa_quote "$pac_file")"
        [ -n "$CA_CERT" ] && printf '    ca_cert=%s\n' "$(wpa_quote "$CA_CERT")"
        printf '}\n'
    } > "$conf_file"
    chmod 600 "$conf_file"
}

print_redacted_config() {
    local conf_file="$1"
    sed -E 's/^(    password=).*/\1"[redacted]"/' "$conf_file"
}

print_new_supplicant_log() {
    local log_file="$1"
    local previous_lines="$2"
    local total_lines

    total_lines=$(wc -l < "$log_file" 2>/dev/null | tr -d ' ')
    [ -n "$total_lines" ] || total_lines=0
    if [ "$total_lines" -gt "$previous_lines" ]; then
        sed -n "$((previous_lines + 1)),$total_lines p" "$log_file" | \
            sed 's/^/  wpa_supplicant: /'
    fi
    SUPPLICANT_LOG_LINES="$total_lines"
}

requested_inner_method() {
    case "$1" in
        ttls-pap) printf '%s' PAP ;;
        ttls-gtc|ttls-eap-gtc|peap-gtc|fast-gtc) printf '%s' EAP-GTC ;;
        ttls-chap) printf '%s' CHAP ;;
        ttls-mschap) printf '%s' MSCHAP ;;
        ttls-mschapv2) printf '%s' MSCHAPV2 ;;
        ttls-eap-md5|peap-md5) printf '%s' EAP-MD5 ;;
        ttls-eap-mschapv2|peap-mschapv2|fast-mschapv2) printf '%s' EAP-MSCHAPV2 ;;
    esac
}

negotiated_inner_method() {
    local log_file="$1"
    local method

    method=$(sed -n 's/.*Phase2 method=\([A-Za-z0-9_-][A-Za-z0-9_-]*\).*/\1/p' "$log_file" | tail -n 1)
    case "$method" in
        MD5) printf '%s' EAP-MD5 ;;
        GTC) printf '%s' EAP-GTC ;;
        MSCHAPV2) printf '%s' EAP-MSCHAPV2 ;;
        MSCHAP) printf '%s' MSCHAP ;;
        PAP|CHAP) printf '%s' "$method" ;;
    esac
}

run_profile() {
    local profile="$1"
    local conf_file="$WORK_DIR/$profile.conf"
    local log_file="$WORK_DIR/$profile.log"
    local elapsed=0 status="" log_lines=0 terminal_event="" terminal_line=""
    local expected_inner="" actual_inner=""

    write_network "$profile" "$conf_file"
    printf '\n== %s ==\n' "$profile"
    printf '%s\n' 'Generated wpa_supplicant profile (password redacted):'
    print_redacted_config "$conf_file" | sed 's/^/  /'
    printf '%s\n' 'Starting wpa_supplicant; streaming its log until the first EAP terminal event.'
    wpa_supplicant -t -i "$IFACE" -c "$conf_file" -D nl80211,wext -f "$log_file" &
    SUPPLICANT_PID=$!

    while [ "$elapsed" -lt "$ATTEMPT_SECONDS" ]; do
        sleep 1
        elapsed=$((elapsed + 1))
        status=$(wpa_cli -p "$WORK_DIR/control" -i "$IFACE" status 2>/dev/null || true)
        printf '  [%ss] %s\n' "$elapsed" "$(printf '%s\n' "$status" | tr '\n' ' ' | sed 's/[[:space:]]*$//')"
        print_new_supplicant_log "$log_file" "$log_lines"
        log_lines="$SUPPLICANT_LOG_LINES"

        terminal_line=$(grep -E 'CTRL-EVENT-EAP-(SUCCESS|FAILURE)|CTRL-EVENT-CONNECTED' "$log_file" 2>/dev/null | sed -n '1p' || true)
        if [ -n "$terminal_line" ]; then
            case "$terminal_line" in
                *CTRL-EVENT-EAP-SUCCESS*) terminal_event="EAP success" ;;
                *CTRL-EVENT-EAP-FAILURE*) terminal_event="EAP failure" ;;
                *CTRL-EVENT-CONNECTED*) terminal_event="network connected" ;;
            esac
            printf 'Result: %s after %ss; terminating this test client.\n' "$terminal_event" "$elapsed"
            break
        fi

        if ! kill -0 "$SUPPLICANT_PID" 2>/dev/null; then
            printf 'Result: wpa_supplicant exited before an EAP terminal event.\n'
            break
        fi
    done

    if [ -z "$terminal_event" ] && kill -0 "$SUPPLICANT_PID" 2>/dev/null; then
        printf 'Result: timed out after %ss without an EAP terminal event.\n' "$ATTEMPT_SECONDS"
    fi
    printf '%s\n' 'Final wpa_supplicant log excerpt:'
    tail -n 80 "$log_file" 2>/dev/null | sed 's/^/  wpa_supplicant: /' || true
    expected_inner=$(requested_inner_method "$profile")
    actual_inner=$(negotiated_inner_method "$log_file")
    if [ -n "$expected_inner" ] && [ -n "$actual_inner" ]; then
        printf 'Negotiated inner method: %s (requested: %s).\n' "$actual_inner" "$expected_inner"
        if [ "$actual_inner" != "$expected_inner" ]; then
            printf '%s\n' 'WARNING: the broad Pager profile selected a different inner method. Select the matching focused Pager profile before treating this as an exact-method test.' >&2
        fi
    elif [ -n "$expected_inner" ]; then
        printf '%s\n' 'Negotiated inner method was not reported by wpa_supplicant; inspect the verbose log and Pager hostapd log.' >&2
    fi
    wpa_cli -p "$WORK_DIR/control" -i "$IFACE" terminate >/dev/null 2>&1 || true
    wait "$SUPPLICANT_PID" 2>/dev/null || true
    SUPPLICANT_PID=""
    sleep 2
}

printf 'pinEAPol Kali EAP matrix: SSID=%s interface=%s profiles=%s\n' "$SSID" "$IFACE" "$PROFILES"
for profile in "${profile_list[@]}"; do
    run_profile "$profile"
done

printf '\nCompleted. Inspect the Pager session logs and results after stopping pinEAPol.\n'
