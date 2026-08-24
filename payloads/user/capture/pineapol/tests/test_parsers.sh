#!/bin/bash
set -eu

TEST_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PAYLOAD_DIR=$(CDPATH= cd -- "$TEST_DIR/.." && pwd)
FIXTURE="$TEST_DIR/fixtures/hostapd-eap.log"
MANA_FIXTURE="$TEST_DIR/fixtures/mana-credentials.log"
TEST_OUTPUT=$(mktemp -d)

cleanup_test() {
    case "$(basename "$TEST_OUTPUT")" in
        tmp.*)
            case "$TEST_OUTPUT" in
                /tmp/*|/private/tmp/*|/var/folders/*/T/*) rm -rf "$TEST_OUTPUT" ;;
            esac
            ;;
    esac
}
trap cleanup_test EXIT

PINEAPOL_LIBRARY_ONLY=1 . "$PAYLOAD_DIR/payload.sh"
LOG() { :; }
MANA_CREDOUT="$MANA_FIXTURE"
SESSION_WORK_DIR="$TEST_OUTPUT/work"

# Simulate the Pager UI staging payload.sh away from its installed support
# files. An explicit installed-folder hint must still resolve the bundled bin.
mkdir -p "$TEST_OUTPUT/ui-stage"
cp "$PAYLOAD_DIR/payload.sh" "$TEST_OUTPUT/ui-stage/payload.sh"
PINEAPOL_PAYLOAD_DIR="$PAYLOAD_DIR" bash -c '
    export PINEAPOL_LIBRARY_ONLY=1
    . "$1"
    test "$PAYLOAD_DIR" = "$2"
    test -f "$MANA_BUNDLED_BIN"
' _ "$TEST_OUTPUT/ui-stage/payload.sh" "$PAYLOAD_DIR"

is_hostapd_version_output 'hostapd-mana v2.12
MANA Edition https://github.com/sensepost/hostapd-mana'
is_hostapd_version_output 'hostapd v2.12'
! is_hostapd_version_output 'unrelated program v2.12'

METHOD_FIXTURE="$TEST_OUTPUT/eap-methods.log"
cat > "$METHOD_FIXTURE" << 'EOF'
wlan_pineapol: AP-STA-CONNECTED aa:bb:cc:dd:ee:ff
received EAP packet: EAP Response-PEAP (25)
EAP-PEAP: Phase 2 EAP-MSCHAPV2
wlan_pineapol: CTRL-EVENT-EAP-SUCCESS aa:bb:cc:dd:ee:ff
EOF
test "$(detect_outer_eap_method "$METHOD_FIXTURE")" = "PEAP"
test "$(detect_inner_eap_method "$METHOD_FIXTURE")" = "MSCHAPv2"
test "$(eap_negotiation_label PEAP MSCHAPv2)" = "PEAP -> MSCHAPv2"
test "$(eap_negotiation_label EAP-TLS '')" = "EAP-TLS"
test "$(eap_negotiation_label '' '')" = "not established"

PINEAPOL_IFACE="wlan_test"
HOSTAPD_CTRL_DIR="$TEST_OUTPUT/hostapd-control"
deauthorized_station=""
hostapd_cli() {
    case "$*" in
        "-p $HOSTAPD_CTRL_DIR -i wlan_test deauthenticate aa:bb:cc:dd:ee:ff 3") deauthorized_station="aa:bb:cc:dd:ee:ff" ;;
        *) return 1 ;;
    esac
}
deauthorize_connected_station aa:bb:cc:dd:ee:ff
test "$deauthorized_station" = "aa:bb:cc:dd:ee:ff"
! deauthorize_connected_station not-a-mac
unset -f hostapd_cli

ORDERED_EVENT_FIXTURE="$TEST_OUTPUT/ordered-events.log"
cat > "$ORDERED_EVENT_FIXTURE" << 'EOF'
wlan_pineapol: STA aa:bb:cc:dd:ee:ff IEEE 802.11: associated (aid 1)
wlan_pineapol: CTRL-EVENT-EAP-STARTED aa:bb:cc:dd:ee:ff
wlan_pineapol: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=1
received EAP packet: EAP Response-Identity (1)
EAP: EAP entering state NAK
wlan_pineapol: CTRL-EVENT-EAP-PROPOSED-METHOD vendor=0 method=21
received EAP packet: EAP Response-TTLS (21)
MANA EAP GTC | fixture-user:fixture-password
wlan_pineapol: CTRL-EVENT-EAP-SUCCESS aa:bb:cc:dd:ee:ff
wlan_pineapol: AP-STA-CONNECTED aa:bb:cc:dd:ee:ff
EOF
test "$(live_event_stream "$ORDERED_EVENT_FIXTURE")" = "$(printf '%s\n' \
    $'ASSOCIATED\taa:bb:cc:dd:ee:ff' EAP_STARTED $'PROPOSED\tIdentity' IDENTITY NAK \
    $'PROPOSED\tEAP-TTLS' $'OUTER\tTTLS' $'CLEAR\tEAP-GTC' SUCCESS \
    $'CONNECTED\taa:bb:cc:dd:ee:ff')"

TTLS_METHOD_EVENT_FIXTURE="$TEST_OUTPUT/ttls-method-events.log"
cat > "$TTLS_METHOD_EVENT_FIXTURE" << 'EOF'
received EAP packet: EAP Response-TTLS (21)
MANA EAP TTLS-MSCHAP HASHCAT | fixture-user::::0123456789abcdef:0123456789abcdef
EOF
test "$(live_event_stream "$TTLS_METHOD_EVENT_FIXTURE")" = "$(printf '%s\n' \
    $'OUTER\tTTLS' $'INNER\tMSCHAPv1' MSCHAPV2)"

extract_eap_identities "$FIXTURE" | sort -u > "$TEST_OUTPUT/identities.actual"
grep -Fxq 'outer@example.com' "$TEST_OUTPUT/identities.actual"
grep -Fxq 'fixture-user' "$TEST_OUTPUT/identities.actual"
! grep -Fxq 'Peer' "$TEST_OUTPUT/identities.actual"

extract_contextual_cleartext "$FIXTURE" > "$TEST_OUTPUT/cleartext.actual"
grep -Fq $'GTC\tfixture-password' "$TEST_OUTPUT/cleartext.actual"

parse_credentials "$FIXTURE" "$TEST_OUTPUT"
test ! -d "$SESSION_WORK_DIR/.parse.$$"
grep -Fxq '[TTLS-PAP] pap-user:fixture-pap-password' "$TEST_OUTPUT/cleartext.txt"
grep -Fxq '[EAP-GTC] gtc-user:fixture-gtc-password' "$TEST_OUTPUT/cleartext.txt"
grep -Fxq 'ffeeddccbbaa99887766554433221100:00112233445566778899aabbccddeeff:01' \
    "$TEST_OUTPUT/hashcat_4800.txt"
for unexpected_result in identities.txt eap_sessions.tsv mana_cleartext_creds.tsv \
    mana_mschapv2.tsv mana_chap.tsv mschapv2_raw.tsv tls_evidence.txt report.txt; do
    test ! -e "$TEST_OUTPUT/$unexpected_result"
done
test ! -e "$TEST_OUTPUT/hashcat_22000.txt"

test -s "$TEST_OUTPUT/hashcat_5500.txt"
grep -Fxq 'User::::82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df:d02e4386bce91226' \
    "$TEST_OUTPUT/hashcat_5500.txt"
test "$(grep -Fxc 'User::::82309ecd8d708b5ea08faa3981cd83544233114a3d85d6df:d02e4386bce91226' \
    "$TEST_OUTPUT/hashcat_5500.txt")" = 1

# Live monitoring consumes MANA's immediate stdout records, which are available
# before its dedicated credential file is necessarily flushed.
LIVE_MANA_FIXTURE="$TEST_OUTPUT/live-mana.log"
cat > "$LIVE_MANA_FIXTURE" << 'EOF'
MANA EAP EAP-MSCHAPV2 HASHCAT | fixture-one::::03e3368898f83ae16bc694025a6f62d8cd5f22be57530371:31eaa0499a8ceb48
MANA EAP EAP-MSCHAPV2 HASHCAT | testing::::810a78653a7cf5e9818bdf8ddf42bffecb0829fe16d04f01:604a3d8c04124aff
MANA EAP EAP-MSCHAPV2 HASHCAT | hello::::663c171e5b0227bd65ec7e14e6979330d0c4ec63d38c1d91:2fd64e09365cc1e1
MANA EAP TTLS-PAP | pap-live:fixture-pap-password
MANA EAP EAP-GTC | gtc-live:fixture-gtc-password
MANA EAP MD5 HASHCAT user=chap-live | ffeeddccbbaa99887766554433221100:00112233445566778899aabbccddeeff:01
TLS: peer certificate subject='/CN=fixture-client'
MANA WPA2 HASHCAT | WPA*02*0123456789abcdef0123456789abcdef*001122334455*66778899aabb*74657374*00112233445566778899aabbccddeeff*0103007502010a00000000000000000001*00
EOF
extract_mana_hashcat_hostapd "$LIVE_MANA_FIXTURE" > "$TEST_OUTPUT/live-mana.actual"
test "$(wc -l < "$TEST_OUTPUT/live-mana.actual" | tr -d ' ')" = 3
grep -Fxq 'testing::::810a78653a7cf5e9818bdf8ddf42bffecb0829fe16d04f01:604a3d8c04124aff' \
    "$TEST_OUTPUT/live-mana.actual"

extract_mana_cleartext_hostapd "$LIVE_MANA_FIXTURE" > "$TEST_OUTPUT/live-cleartext.actual"
grep -Fq $'TTLS-PAP\tpap-live\tfixture-pap-password' "$TEST_OUTPUT/live-cleartext.actual"
grep -Fq $'EAP-GTC\tgtc-live\tfixture-gtc-password' "$TEST_OUTPUT/live-cleartext.actual"
extract_mana_chap_hostapd "$LIVE_MANA_FIXTURE" > "$TEST_OUTPUT/live-chap.actual"
grep -Fq $'MD5\tchap-live\tffeeddccbbaa99887766554433221100\t00112233445566778899aabbccddeeff\t01' \
    "$TEST_OUTPUT/live-chap.actual"
extract_tls_evidence "$LIVE_MANA_FIXTURE" > "$TEST_OUTPUT/live-tls.actual"
grep -Fxq "TLS: peer certificate subject='/CN=fixture-client'" "$TEST_OUTPUT/live-tls.actual"
extract_mana_hashcat_22000_hostapd "$LIVE_MANA_FIXTURE" > "$TEST_OUTPUT/live-wpa.actual"
grep -Fxq 'WPA*02*0123456789abcdef0123456789abcdef*001122334455*66778899aabb*74657374*00112233445566778899aabbccddeeff*0103007502010a00000000000000000001*00' \
    "$TEST_OUTPUT/live-wpa.actual"
mkdir -p "$TEST_OUTPUT/wpa-results"
parse_credentials "$LIVE_MANA_FIXTURE" "$TEST_OUTPUT/wpa-results"
grep -Fxq 'WPA*02*0123456789abcdef0123456789abcdef*001122334455*66778899aabb*74657374*00112233445566778899aabbccddeeff*0103007502010a00000000000000000001*00' \
    "$TEST_OUTPUT/wpa-results/hashcat_22000.txt"
test ! -d "$SESSION_WORK_DIR/.parse.$$"

publish_unique_lines_atomic "$TEST_OUTPUT/live-hashcat.txt" "$(cat "$TEST_OUTPUT/live-mana.actual")"
test "$(wc -l < "$TEST_OUTPUT/live-hashcat.txt" | tr -d ' ')" = 3

# RFC 2759 section 9 example: ChallengeHash must be D02E4386BCE91226.
rfc_challenge=$(derive_mschapv2_challenge \
    '21402324255E262A28295F2B3A337C7E' \
    '5B5D7C7D7B3F2F3E3C2C602132262628' \
    'User')
test "$rfc_challenge" = 'd02e4386bce91226'

EAP_PROFILE_DIR="$TEST_OUTPUT/eap-profiles"
SESSION_LOG=""
mkdir -p "$EAP_PROFILE_DIR"
for profile in broad peap-mschapv2 peap-gtc peap-md5 \
    ttls-eap-md5 ttls-eap-gtc ttls-eap-mschapv2 ttls-pap ttls-chap \
    ttls-mschap ttls-mschapv2 eap-tls eap-tls-accept-any \
    fast-mschapv2 fast-gtc md5 mschapv2 gtc; do
    EAP_PROFILE="$profile"
    EAP_USER_FILE="$TEST_OUTPUT/$profile.eap_user"
    write_eap_user_file
    test -s "$EAP_USER_FILE"
done

! grep -Rq '"anonymous".*\[2\]' "$TEST_OUTPUT"/*.eap_user
for tunneled_profile in broad peap-mschapv2 peap-gtc peap-md5 \
    ttls-eap-md5 ttls-eap-gtc ttls-eap-mschapv2 ttls-pap ttls-chap \
    ttls-mschap ttls-mschapv2 fast-mschapv2 fast-gtc; do
    grep -Eq '^"t"[[:space:]].*\[2\]$' "$TEST_OUTPUT/$tunneled_profile.eap_user"
    ! grep -Eq '^\*[[:space:]].*\[2\]$' "$TEST_OUTPUT/$tunneled_profile.eap_user"
done
grep -Fxq '* MD5,GTC,MSCHAPV2,TTLS,PEAP,FAST,TLS "password"' "$TEST_OUTPUT/broad.eap_user"
grep -Fxq '"t" TTLS-PAP,GTC,TTLS-CHAP,TTLS-MSCHAP,TTLS-MSCHAPV2,MD5,MSCHAPV2 "password" [2]' \
    "$TEST_OUTPUT/broad.eap_user"

# Unknown persisted profile values must fail explicitly rather than being
# silently converted to the Broad profile.
EAP_PROFILE="fast"
EAP_USER_FILE="$TEST_OUTPUT/invalid.eap_user"
! write_eap_user_file
test ! -e "$EAP_USER_FILE"
test "$(eap_profile_label "$EAP_PROFILE")" = "Invalid EAP profile"

EAP_PROFILE="peap-mschapv2"
EAP_USER_FILE="$TEST_OUTPUT/peap-mschapv2.eap_user"
HOSTAPD_CONF="$TEST_OUTPUT/hostapd.conf"
CERT_DIR="$TEST_OUTPUT/certificates"
PINEAPOL_IFACE="wlan_test"
HOSTAPD_CTRL_DIR="$TEST_OUTPUT/hostapd-control"
FAST_PAC_KEY_FILE="$TEST_OUTPUT/fast-pac-opaque.key"
write_hostapd_config 'FixtureSSID' 6
hostapd_config_is_managed "$HOSTAPD_CONF"
grep -Fxq 'eap_server=1' "$HOSTAPD_CONF"
grep -Fxq 'mana_wpe=1' "$HOSTAPD_CONF"
grep -Fxq "mana_credout=$MANA_CREDOUT" "$HOSTAPD_CONF"
grep -Fxq 'enable_mana=0' "$HOSTAPD_CONF"
grep -Fxq 'mana_eapsuccess=0' "$HOSTAPD_CONF"
grep -Fxq 'mana_eaptls=0' "$HOSTAPD_CONF"
grep -Fxq "ctrl_interface=$HOSTAPD_CTRL_DIR" "$HOSTAPD_CONF"
! grep -q '^eap_fast_' "$HOSTAPD_CONF"

EAP_PROFILE="fast-gtc"
printf '%s\n' '0a1b2c3d4e5f60718293a4b5c6d7e8f9' > "$FAST_PAC_KEY_FILE"
write_hostapd_config 'FixtureSSID' 6
grep -Fxq 'pac_opaque_encr_key=0a1b2c3d4e5f60718293a4b5c6d7e8f9' "$HOSTAPD_CONF"
grep -Fxq 'eap_fast_prov=3' "$HOSTAPD_CONF"
test "$(stat -c '%a' "$FAST_PAC_KEY_FILE" 2>/dev/null || stat -f '%Lp' "$FAST_PAC_KEY_FILE")" = 600

test -f "$PAYLOAD_DIR/bin/hostapd-mana-mipsel_24kc"
test "$(calculate_sha256 "$PAYLOAD_DIR/bin/hostapd-mana-mipsel_24kc")" = "$MANA_EXPECTED_SHA256"

PINEAPOL_HOME="$TEST_OUTPUT/persistent"
LOOT_DIR="$PINEAPOL_HOME/sessions"
PERSISTENT_CONFIG_DIR="$PINEAPOL_HOME/config"
EAP_PROFILE_DIR="$PERSISTENT_CONFIG_DIR/eap-profiles"
HOSTAPD_CACHE_DIR="$PINEAPOL_HOME/bin"
CERT_STORE="$PINEAPOL_HOME/certificates"
CURRENT_LINK="$PINEAPOL_HOME/current"
TARGET_SSID=""
initialize_persistent_storage
test -d "$SESSION_RESULTS_DIR"
test -f "$SESSION_LOG"
test -d "$RUNTIME_DIR"
test -d "$RUNTIME_LOCK_DIR"
test "$(sed -n '1p' "$PAYLOAD_PID_FILE")" = "$$"
test -s "$PAYLOAD_START_FILE"
# Simulate a concurrent launcher: it must not steal a live owner's lock.
RUNTIME_LOCK_HELD=0
! acquire_runtime_lock
RUNTIME_LOCK_HELD=1
TARGET_SSID="Fixture SSID"
rename_session_for_target
case "$SESSION_DIR" in "$PINEAPOL_HOME"/sessions/*_Fixture_SSID) ;; *) exit 1 ;; esac
release_runtime_lock
test ! -d "$RUNTIME_LOCK_DIR"

# A lock whose owner is no longer alive is recoverable.
mkdir "$RUNTIME_LOCK_DIR"
printf '%s\n' 999999 > "$PAYLOAD_PID_FILE"
printf '%s\n' 1 > "$PAYLOAD_START_FILE"
acquire_runtime_lock
test "$(sed -n '1p' "$PAYLOAD_PID_FILE")" = "$$"
release_runtime_lock

unmanaged_hostapd_conf="$TEST_OUTPUT/unmanaged-hostapd.conf"
printf '%s\n' '# pinEAPol hostapd-mana configuration' 'interface=wlan1mon' > "$unmanaged_hostapd_conf"
! hostapd_config_is_managed "$unmanaged_hostapd_conf"
! grep -Eq '(pkill|killall)' "$PAYLOAD_DIR/payload.sh"

# Simulate a payload parent that vanished without running EXIT cleanup. The
# supervisor must remove only wlan_pineapol, clear stale state, and release the
# dead owner's lock even when no child process remains.
watchdog_home="$TEST_OUTPUT/watchdog"
watchdog_session="$watchdog_home/sessions/fixture"
mkdir -p "$watchdog_home/run/lock" "$watchdog_session/config" "$watchdog_session/logs" "$watchdog_session/results"
cp "$FIXTURE" "$watchdog_session/logs/hostapd.log"
cp "$MANA_FIXTURE" "$watchdog_session/logs/mana-credentials.log"
printf '%s\n' "$watchdog_session/config/hostapd.conf" > "$watchdog_home/run/hostapd.config"
printf '%s\n' 999999 > "$watchdog_home/run/lock/payload.pid"
printf '%s\n' 1 > "$watchdog_home/run/lock/payload.start"
touch "$TEST_OUTPUT/wlan_pineapol.exists"
iw() {
    case "$*" in
        "dev wlan_pineapol info") [ -e "$TEST_OUTPUT/wlan_pineapol.exists" ] ;;
        "dev wlan_pineapol del") rm -f "$TEST_OUTPUT/wlan_pineapol.exists" ;;
        *) return 1 ;;
    esac
}
ifconfig() { :; }
(
    cleanup_watchdog_main 999999 1 "$watchdog_home" /proc wlan_pineapol \
        "$MANA_EXPECTED_SHA256"
)
test ! -e "$TEST_OUTPUT/wlan_pineapol.exists"
test ! -d "$watchdog_home/run/lock"
grep -Fq 'Detached watchdog cleanup complete' "$watchdog_session/logs/session.log"
grep -Fq 'Detached watchdog evidence publication complete' "$watchdog_session/logs/session.log"
grep -Fxq 'ffeeddccbbaa99887766554433221100:00112233445566778899aabbccddeeff:01' \
    "$watchdog_session/results/hashcat_4800.txt"
test ! -e "$watchdog_session/results/mana_chap.tsv"
unset -f iw ifconfig

CERT_CN='unsafe/value'
CERT_DNS_SANS=''
CERT_KEY_BITS=1234
normalize_certificate_settings
test "$CERT_CN" = 'radius-server-auth.local'
test "$CERT_DNS_SANS" = 'radius-server-auth.local'
test "$CERT_KEY_BITS" = 2048

test "$(eap_profile_label broad)" = 'Broad / automatic'
test "$(eap_profile_label peap-mschapv2)" = 'PEAP + MSCHAPv2 [hash]'

# The UI chooses an outer method first, then exposes only that method's valid
# inner methods. Exercise each dependent selector without a Pager UI.
ORIGINAL_UI_LIST_PICKER=$(declare -f ui_list_picker)
write_persistent_settings() { :; }
ui_list_picker() {
    case "$1" in
        "EAP Profile")
            if [ -f "$TEST_OUTPUT/back-selection-used" ]; then
                printf '%s' 'TTLS'
            else
                : > "$TEST_OUTPUT/back-selection-used"
                printf '%s' 'PEAP'
            fi
            ;;
        "PEAP Inner Method") printf '%s' 'Back' ;;
        "TTLS Inner Method") printf '%s' 'PAP [cleartext]' ;;
    esac
}
EAP_PROFILE=peap-mschapv2
select_eap_profile
test "$EAP_PROFILE" = ttls-pap
ui_list_picker() {
    case "$1" in
        "EAP Profile") printf '%s' 'PEAP' ;;
        "PEAP Inner Method") printf '%s' 'MD5 [hash]' ;;
    esac
}
EAP_PROFILE=broad
select_eap_profile
test "$EAP_PROFILE" = peap-md5
ui_list_picker() {
    case "$1" in
        "EAP Profile") printf '%s' 'TTLS' ;;
        "TTLS Inner Method") printf '%s' 'EAP-GTC [cleartext]' ;;
    esac
}
select_eap_profile
test "$EAP_PROFILE" = ttls-eap-gtc
ui_list_picker() {
    case "$1" in
        "EAP Profile") printf '%s' 'EAP-TLS' ;;
        "EAP-TLS Mode") printf '%s' 'Accept presented client certificate' ;;
    esac
}
select_eap_profile
test "$EAP_PROFILE" = eap-tls-accept-any
unset -f ui_list_picker write_persistent_settings
eval "$ORIGINAL_UI_LIST_PICKER"

PROMPT() { return 0; }
NUMBER_PICKER() { printf '%s' 2; }
fallback_choice=$(ui_list_picker "Fixture Picker" "First" "First" "Second")
test "$fallback_choice" = 'Second'
unset -f PROMPT NUMBER_PICKER

LIST_PICKER() { printf '%s' "$3"; }
native_choice=$(ui_list_picker "Fixture Picker" "Second" "First" "Second")
test "$native_choice" = 'Second'
unset -f LIST_PICKER

mkdir -p "$CERT_STORE/alpha" "$CERT_STORE/beta" "$CERT_STORE/ignored"
touch "$CERT_STORE/alpha/profile.conf" "$CERT_STORE/beta/profile.conf"
discovered_profiles=$(discover_certificate_profiles)
printf '%s\n' "$discovered_profiles" | grep -Fxq alpha
printf '%s\n' "$discovered_profiles" | grep -Fxq beta
! printf '%s\n' "$discovered_profiles" | grep -Fxq ignored

# A launcher that does not own the runtime lock must not tear down the active
# instance when its EXIT cleanup runs.
cleanup_probe="$TEST_OUTPUT/non-owner-cleanup-called"
stop_runtime_watchdog() { touch "$cleanup_probe"; }
stop_managed_hostapd() { touch "$cleanup_probe"; }
stop_capture() { touch "$cleanup_probe"; }
remove_managed_interfaces() { touch "$cleanup_probe"; }
LED() { :; }
RUNTIME_LOCK_HELD=0
CLEANUP_ACTIVE=0
SESSION_LOG=""
SESSION_DIR=""
START_TIME=""
cleanup
test ! -e "$cleanup_probe"

# An owning cleanup must leave its detached supervisor active until hostapd,
# tcpdump, and the managed interface have all been handled.
cleanup_order=""
stop_managed_hostapd() { cleanup_order="${cleanup_order} hostapd"; }
stop_capture() { cleanup_order="${cleanup_order} capture"; }
remove_managed_interfaces() { cleanup_order="${cleanup_order} interface"; }
stop_runtime_watchdog() { cleanup_order="${cleanup_order} watchdog"; }
release_runtime_lock() { cleanup_order="${cleanup_order} unlock"; }
RUNTIME_LOCK_HELD=1
CLEANUP_ACTIVE=0
cleanup
test "$cleanup_order" = " hostapd capture interface watchdog unlock"

grep -Fq 'setsid "$bash_bin" "$PAYLOAD_DIR/payload.sh" --cleanup-watchdog' "$PAYLOAD_DIR/payload.sh"
grep -Fq "trap '' HUP INT TERM QUIT" "$PAYLOAD_DIR/payload.sh"

echo "pinEAPol parser fixtures passed"
