#!/bin/bash
# shellcheck disable=SC2154  # Variables defined in reconftw.cfg
# reconFTW - Vulnerability scanning module
# Contains: xss, ssrf_checks, crlf_checks, lfi, ssti,
#           sqli, test_ssl, spraying, command_injection, 4xxbypass,
#           smuggling, webcache, fuzzparams, nuclei_dast, wp_brute_pro
# This file is sourced by reconftw.sh - do not execute directly
[[ -z "${SCRIPTPATH:-}" ]] && {
    echo "Error: This module must be sourced by reconftw.sh" >&2
    exit 1
}

# Build injectable URL list for sqlmap/commix/TInjA from gf output.
# Replace parameter values with FUZZ; fall back to raw parameterized URLs if needed.
# Usage: _vulns_build_qsreplace_fuzz_list <source_gf_file> <dest_tmp_file>
_vulns_build_qsreplace_fuzz_list() {
    local src="$1"
    local dest="$2"

    : >"$dest"
    [[ ! -s "$src" ]] && return 1

    if command -v qsreplace >/dev/null 2>&1; then
        qsreplace "FUZZ" <"$src" 2>>"$LOGFILE" | grep -a 'FUZZ' | sed 's/\r$//' | anew -q "$dest"
    fi

    if [[ ! -s "$dest" ]]; then
        grep -aE '^https?://[^[:space:]]*\?[^[:space:]]*=' "$src" 2>/dev/null \
            | sed 's/\r$//' | anew -q "$dest"
    fi

    [[ -s "$dest" ]]
}

# Merge per-target ghauri part logs into vulns/ghauri_log.txt (safe after crash or success).
_vulns_merge_ghauri_parts() {
    local log="vulns/ghauri_log.txt"
    local part

    [[ -d .tmp/ghauri_parts ]] || return 0
    for part in .tmp/ghauri_parts/*.txt; do
        [[ -f "$part" ]] || continue
        cat "$part" >>"$log" 2>/dev/null || true
    done
}

function xss() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $XSS == true ]] && [[ -s "gf/xss.txt" ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "XSS Analysis"

        # Process gf/xss.txt with qsreplace and Gxss
        if [[ -s "gf/xss.txt" ]]; then
            _print_msg INFO "Running: XSS Payload Generation"
            run_command qsreplace FUZZ <"gf/xss.txt" | sed '/FUZZ/!d' | Gxss -c 100 -p Xss | qsreplace FUZZ | sed '/FUZZ/!d' \
                | anew -q ".tmp/xss_reflected.txt"
        fi

        # Determine whether to use Axiom or Katana for scanning
        if [[ $AXIOM != true ]]; then
            # Using Katana
            if [[ $DEEP == true ]]; then
                DEPTH=3
            else
                DEPTH=2
            fi

            if [[ -n $XSS_SERVER ]]; then
                OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
            else
                _print_msg WARN "No XSS_SERVER defined, blind XSS skipped"
                OPTIONS="-w $DALFOX_THREADS"
            fi

                # Run Dalfox with Katana output
                if [[ -s ".tmp/xss_reflected.txt" ]]; then
                    _print_msg INFO "Running: Dalfox with Katana"
                    run_command dalfox pipe --silence --no-color --no-spinner --only-poc r --ignore-return 302,404,403 --skip-bav $OPTIONS -d "$DEPTH" <".tmp/xss_reflected.txt" 2>>"$LOGFILE" |
                        anew -q "vulns/xss.txt"
                fi

            
        else
            # Using Axiom
            if [[ $DEEP == true ]]; then
                DEPTH=3
                AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
            else
                DEPTH=2
                AXIOM_ARGS="$AXIOM_EXTRA_ARGS"
            fi

            if [[ -n $XSS_SERVER ]]; then
                OPTIONS="-b ${XSS_SERVER} -w $DALFOX_THREADS"
            else
                _print_msg WARN "No XSS_SERVER defined, blind XSS skipped"
                OPTIONS="-w $DALFOX_THREADS"
            fi

            # Run Dalfox with Axiom-scan output
            if [[ -s ".tmp/xss_reflected.txt" ]]; then
                _print_msg INFO "Running: Dalfox with Axiom"
                run_command axiom-scan ".tmp/xss_reflected.txt" -m dalfox --skip-bav $OPTIONS -d "$DEPTH" -o "vulns/xss.txt" $AXIOM_ARGS 2>>"$LOGFILE" >/dev/null
            fi
        fi

        end_func "Results are saved in vulns/xss.txt" "${FUNCNAME[0]}"
    else
        if [[ $XSS == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/xss.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function ssrf_checks() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSRF_CHECKS == true ]] \
        && [[ -s "gf/ssrf.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SSRF Checks"

        # Handle COLLAB_SERVER configuration
        if [[ -z $COLLAB_SERVER ]]; then
            # -json emits each OOB interaction as a JSONL record (full-id/unique-id/
            # protocol/raw-request/...) instead of only a human-readable line. We need
            # the "full-id" field later to correlate a received callback back to the
            # exact ffuf request that triggered it (see the confirmation block below).
            # The [INF] startup banner (used to detect the assigned domain) remains
            # plain text regardless of this flag.
            interactsh-client -json &>.tmp/ssrf_callback.txt &
            INTERACTSH_PID=$!
            # Ensure interactsh is killed on function exit (prevents orphan processes)
            trap 'kill "$INTERACTSH_PID" 2>/dev/null; trap - RETURN' RETURN
            # Poll up to 15s for interactsh to print its callback domain (avoids the old
            # fixed 'sleep 2' race where the process hadn't initialised yet, causing
            # COLLAB_SERVER_FIX to become "FFUFHASH." with an empty suffix).
            local _isc_domain="" _isc_waited=0
            while [[ -z "$_isc_domain" && $_isc_waited -lt 15 ]]; do
                sleep 1
                (( _isc_waited++ ))
                # interactsh-client prints the assigned domain on its own [INF] line at
                # startup, e.g.:
                #   [INF] Listing 1 payload for OOB Testing
                #   [INF] c23b2la0kl1krjcrdj10cndmnioyyyyyn.oast.pro
                _isc_domain=$(grep -aoE '^\[INF\][[:space:]]+[a-z0-9]{10,}\.[a-z0-9.]+$' .tmp/ssrf_callback.txt 2>/dev/null \
                    | awk '{print $2}' | tail -1)
                # Fallback: grab any interactsh-style domain directly, in case the
                # banner format changes between client versions.
                if [[ -z "$_isc_domain" ]]; then
                    _isc_domain=$(grep -aoE '[a-z0-9]{10,}\.(oast\.[a-z]+|interact\.sh)' \
                        .tmp/ssrf_callback.txt 2>/dev/null | tail -1)
                fi
            done
            if [[ -n "$_isc_domain" ]]; then
                COLLAB_SERVER_FIX="FFUFHASH.${_isc_domain}"
            else
                _print_msg WARN "interactsh did not return a callback URL within 15s; SSRF OOB detection may be unreliable"
                COLLAB_SERVER_FIX="FFUFHASH.$(tail -n1 .tmp/ssrf_callback.txt | cut -c 16-)"
            fi
            COLLAB_SERVER_URL="http://${COLLAB_SERVER_FIX}"
            INTERACT=true
        else
            # Strip scheme for the raw-token form; keep original URL for HTTP-scheme form.
            # Note: COLLAB_SERVER_URL was previously undefined in this branch, causing
            # qsreplace and ffuf header-injection calls below to use an empty value.
            COLLAB_SERVER_FIX="FFUFHASH.$(echo "$COLLAB_SERVER" | sed -r "s|https?://||")"
            COLLAB_SERVER_URL="${COLLAB_SERVER}"
            INTERACT=false
        fi

        # Determine whether to proceed based on DEEP flag or URL count
        URL_COUNT=$(wc -l <"gf/ssrf.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: SSRF Payload Generation"

            # Generate classic callback payloads.
            run_command qsreplace "$COLLAB_SERVER_FIX" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf.txt"
            run_command qsreplace "$COLLAB_SERVER_URL" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf.txt"

            # Run FFUF to find requested URLs.
            _print_msg INFO "Running: FFUF for SSRF Requested URLs"
            run_command ffuf -v -H "${HEADER}" -t "$FFUF_THREADS" -rate "$FFUF_RATELIMIT" -w ".tmp/tmp_ssrf.txt" -u "FUZZ" 2>/dev/null \
                | anew -q "vulns/ssrf_requested.txt"

            # Run FFUF with header injection for SSRF.
            _print_msg INFO "Running: FFUF for SSRF Requested Headers with callback tokens"
            run_command ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${headers_inject}:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_FIX}" -t "$FFUF_THREADS" \
                -rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"
            run_command ffuf -v -w ".tmp/tmp_ssrf.txt:W1,${headers_inject}:W2" -H "${HEADER}" -H "W2: ${COLLAB_SERVER_URL}" -t "$FFUF_THREADS" \
                -rate "$FFUF_RATELIMIT" -u "W1" 2>/dev/null | anew -q "vulns/ssrf_requested_headers.txt"

            # Additional protocol payloads (gopher/dict/file/metadata endpoints).
            local ssrf_payloads_file="${SCRIPTPATH}/config/ssrf_payloads.txt"
            if [[ -s "$ssrf_payloads_file" ]]; then
                : >".tmp/tmp_ssrf_protocols.txt"
                while IFS= read -r payload || [[ -n "$payload" ]]; do
                    [[ -z "$payload" || "$payload" =~ ^# ]] && continue
                    payload="${payload//\{COLLAB\}/$COLLAB_SERVER_FIX}"
                    payload="${payload//\{COLLAB_URL\}/$COLLAB_SERVER_URL}"
                        run_command qsreplace "$payload" <"gf/ssrf.txt" | anew -q ".tmp/tmp_ssrf_protocols.txt"
                done <"$ssrf_payloads_file"

                if [[ -s ".tmp/tmp_ssrf_protocols.txt" ]]; then
                    _print_msg INFO "Running: FFUF for SSRF alternate protocols"
                    run_command ffuf -v -H "${HEADER}" -t "$FFUF_THREADS" -rate "$FFUF_RATELIMIT" -w ".tmp/tmp_ssrf_protocols.txt" -u "FUZZ" \
                        -mr "${SSRF_ALT_MATCH_REGEX:-169\\.254\\.169\\.254|latest/meta-data|root:|127\\.0\\.0\\.1|localhost|gopher://|dict://|file://}" 2>/dev/null \
                        | grep -aF "| URL |" | sed 's/.*| URL | //' | anew -q "vulns/ssrf_alt_protocols.txt"
                fi
            fi

            # Framework-specific SSRF endpoint probing (Next.js Image Optimization,
            # Vercel OG image API, Nuxt IPX, Astro image endpoint). These are common,
            # *guessable* SSRF sinks that gf's URL-pattern matching can miss entirely
            # when the endpoint is never linked from a crawled page (e.g. /_next/image
            # is invoked client-side by <Image> components, not hyperlinked, so it may
            # never show up in webs/url_extract.txt -> gf/ssrf.txt at all). We probe
            # them directly against every known live host instead of relying on prior
            # discovery. Both raw and percent-encoded payload forms are tried since
            # frameworks differ in whether they expect the target URL encoded.
            if [[ -s "webs/webs_all.txt" ]]; then
                local _fw_hosts_file="webs/webs_all.txt"
                local _fw_host_count
                _fw_host_count=$(wc -l <"$_fw_hosts_file")
                # Cap default-mode blast radius; --deep removes the cap.
                if [[ $DEEP != true ]] && [[ $_fw_host_count -gt 200 ]]; then
                    head -n 200 "$_fw_hosts_file" >".tmp/ssrf_framework_hosts.txt"
                    _fw_hosts_file=".tmp/ssrf_framework_hosts.txt"
                fi

                local -a _ssrf_framework_paths=(
                    "/_next/image?url={PAYLOAD}&w=256&q=75"
                    "/_vercel/image?url={PAYLOAD}&w=256&q=75"
                    "/api/og?url={PAYLOAD}"
                    "/_ipx/w_256/{PAYLOAD}"
                    "/_image?href={PAYLOAD}"
                )
                local _fw_encoded_collab
                _fw_encoded_collab=$(printf '%s' "${COLLAB_SERVER_URL}" | sed 's/:/%3A/g; s#/#%2F#g')

                : >".tmp/tmp_ssrf_framework.txt"
                while IFS= read -r _fw_base_url || [[ -n "$_fw_base_url" ]]; do
                    [[ -z "$_fw_base_url" ]] && continue
                    _fw_base_url="${_fw_base_url%/}"
                    for _fw_path in "${_ssrf_framework_paths[@]}"; do
                        printf '%s%s\n' "${_fw_base_url}" "${_fw_path//\{PAYLOAD\}/$COLLAB_SERVER_URL}" >>".tmp/tmp_ssrf_framework.txt"
                        printf '%s%s\n' "${_fw_base_url}" "${_fw_path//\{PAYLOAD\}/$_fw_encoded_collab}" >>".tmp/tmp_ssrf_framework.txt"
                    done
                done <"$_fw_hosts_file"

                if [[ -s ".tmp/tmp_ssrf_framework.txt" ]]; then
                    _print_msg INFO "Running: FFUF for framework-specific SSRF endpoints (Next.js/Vercel/Nuxt/Astro)"
                    run_command ffuf -v -H "${HEADER}" -t "$FFUF_THREADS" -rate "$FFUF_RATELIMIT" -w ".tmp/tmp_ssrf_framework.txt" -u "FUZZ" 2>/dev/null \
                        | anew -q "vulns/ssrf_framework_endpoints.txt"
                fi
            fi

            # Nuclei SSRF/OAST template pass — covers IMDSv2, blind-SSRF via OAST,
            # and cloud-metadata templates that ffuf+qsreplace miss.
            if command -v nuclei &>/dev/null && [[ -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
                _print_msg INFO "Running: Nuclei SSRF/OAST template scan"
                run_command nuclei -l "gf/ssrf.txt" -tags ssrf,oast -nh \
                    -rl "$NUCLEI_RATELIMIT" -silent -retries 2 ${NUCLEI_EXTRA_ARGS} \
                    -j -o "vulns/ssrf_nuclei_json.txt" 2>>"$LOGFILE" >/dev/null || true
            fi

            # Allow time for OOB/DNS callbacks to be received.
            # Hard-coded to 10s (was 5s) to reduce false negatives on slower DNS resolvers.
            sleep 10

            # Process SSRF callback results if INTERACT is enabled.
            if [[ $INTERACT == true ]] && [[ -s ".tmp/ssrf_callback.txt" ]]; then
                tail -n +11 .tmp/ssrf_callback.txt | anew -q "vulns/ssrf_callback.txt"
                if ! NUMOFLINES=$(tail -n +12 .tmp/ssrf_callback.txt | sed '/^$/d' | wc -l); then
                    NUMOFLINES=0
                fi
                notification "SSRF: ${NUMOFLINES} callbacks received" info

                # Correlate each OOB hit back to the exact request that triggered it,
                # using ffuf's built-in FFUFHASH history mapping (`ffuf -search <hash>`,
                # see https://github.com/ffuf/ffuf/wiki/Ffufhash-mapping). This is the
                # actual CONFIRMATION step that was previously missing: vulns/ssrf_
                # requested*.txt only ever recorded "we fired a payload at this URL",
                # never proof it was vulnerable. A real OOB interaction here proves it.
                #
                # Mechanism: COLLAB_SERVER_FIX/_URL embed the literal string FFUFHASH,
                # which ffuf replaces with a unique per-request hash before sending
                # (in the URL, and in headers/body -- confirmed supported). When
                # interactsh (in -json mode) receives that hit, its "full-id" field
                # is "<ffuf-hash>.<our-assigned-domain>" -- so the first dot-separated
                # label of full-id IS the ffuf hash we can feed back into
                # `ffuf -search` to reconstruct the original request (URL/host/header).
                if [[ "$NUMOFLINES" -gt 0 ]] && command -v ffuf &>/dev/null && command -v jq &>/dev/null; then
                    _print_msg INFO "Running: Correlating OOB callbacks to source requests (ffuf -search)"
                    {
                        printf '# SSRF OOB confirmed findings\n'
                        printf '# Meaning: interactsh received a callback whose full-id embeds an ffuf request hash.\n'
                        printf '# That proves something on the request path resolved/fetched our OAST domain.\n'
                        printf '# It does NOT always identify the single sink parameter (qsreplace may replace all params).\n'
                        printf '# Format: url | method | vector | hash | oob_protocol | note\n'
                    } >"vulns/ssrf_confirmed.txt"

                    # Only keep full-ids that look like "<ffufhash>.<interactsh-id>" (skip bare interactsh probes).
                    jq -R -r 'fromjson? | select((."full-id" // "") | test("^[A-Za-z0-9]{6,}\\.")) | [."full-id", (."protocol" // "unknown")] | @tsv' \
                        ".tmp/ssrf_callback.txt" 2>/dev/null \
                        | sed '/^$/d' | sort -u >".tmp/ssrf_hit_map.tsv"
                    cut -f1 ".tmp/ssrf_hit_map.tsv" 2>/dev/null | cut -d'.' -f1 | sort -u >".tmp/ssrf_hit_hashes.txt"

                    if [[ -s ".tmp/ssrf_hit_hashes.txt" ]]; then
                        while IFS= read -r _ssrf_hash; do
                            [[ -z "$_ssrf_hash" ]] && continue
                            _ssrf_req=$(ffuf -search "$_ssrf_hash" 2>/dev/null)
                            [[ -z "$_ssrf_req" ]] && continue
                            _ssrf_host=$(grep -aim1 '^Host:' <<<"$_ssrf_req" | sed 's/^[Hh]ost:[[:space:]]*//' | tr -d '\r')
                            _ssrf_method=$(grep -aoE '^(GET|POST|PUT|HEAD|PATCH|DELETE) ' <<<"$_ssrf_req" | head -1 | tr -d ' ')
                            _ssrf_path=$(grep -aoE '^(GET|POST|PUT|HEAD|PATCH|DELETE) [^ ]+' <<<"$_ssrf_req" | head -1 | awk '{print $2}')
                            [[ -z "$_ssrf_host" || -z "$_ssrf_path" ]] && continue
                            [[ -z "$_ssrf_method" ]] && _ssrf_method="GET"

                            # Real injected HTTP header only (ignore ffuf -search meta lines).
                            _ssrf_hdr=$(grep -aiE "^[A-Za-z0-9-]+:.*${_ssrf_hash}" <<<"$_ssrf_req" | grep -aivE '^(Host|GET|POST|PUT|HEAD|PATCH|DELETE)[: ]' | head -1 | cut -d: -f1)
                            _ssrf_proto=$(awk -F'\t' -v h="$_ssrf_hash" 'index($1,h)==1 {print $2; exit}' ".tmp/ssrf_hit_map.tsv" 2>/dev/null)
                            [[ -z "$_ssrf_proto" ]] && _ssrf_proto="unknown"

                            if [[ -n "$_ssrf_hdr" ]]; then
                                _ssrf_vector="header:${_ssrf_hdr}"
                                _ssrf_note="OAST ${_ssrf_proto} callback matched ffuf hash in header ${_ssrf_hdr}"
                            elif [[ "$_ssrf_path" == *"$_ssrf_hash"* ]]; then
                                _ssrf_vector="url-query"
                                _ssrf_note="OAST ${_ssrf_proto} callback matched ffuf hash in URL (all qsreplace params may contain payload; sink param unknown)"
                            else
                                _ssrf_vector="unknown"
                                _ssrf_note="OAST ${_ssrf_proto} callback matched ffuf hash; request reconstructed but hash location unclear"
                            fi

                            printf 'https://%s%s | %s | %s | hash=%s | oob=%s | %s\n' \
                                "$_ssrf_host" "$_ssrf_path" "$_ssrf_method" "$_ssrf_vector" "$_ssrf_hash" "$_ssrf_proto" "$_ssrf_note"
                        done <".tmp/ssrf_hit_hashes.txt" | anew -q "vulns/ssrf_confirmed.txt"
                    fi

                    if grep -qE '^https?://' "vulns/ssrf_confirmed.txt" 2>/dev/null; then
                        notification "SSRF: $(grep -cE '^https?://' "vulns/ssrf_confirmed.txt") CONFIRMED OOB finding(s) - see vulns/ssrf_confirmed.txt" warn
                    fi
                fi
            fi

            end_func "Results are saved in vulns/ssrf_* -- vulns/ssrf_confirmed.txt = OOB-verified, others = unconfirmed candidates" "${FUNCNAME[0]}"
        else
            end_func "Skipping SSRF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

        # Terminate interactsh-client if it was started
        if [[ $INTERACT == true ]] && [[ -n "${INTERACTSH_PID:-}" ]]; then
            kill "$INTERACTSH_PID" 2>/dev/null || true
            unset INTERACTSH_PID
        fi

    else
        if [[ $SSRF_CHECKS == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/ssrf.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function crlf_checks() {

    # Create necessary directories
    if ! ensure_dirs webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $CRLF_CHECKS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ! command -v crlfuzz >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: crlfuzz not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "CRLF Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: CRLF Fuzzing"

            # Run CRLFuzz
            run_command crlfuzz -l "webs/webs_all.txt" -o "vulns/crlf.txt" 2>>"$LOGFILE" >/dev/null

            end_func "Results are saved in vulns/crlf.txt" "${FUNCNAME[0]}"
        else
            end_func "Skipping CRLF: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi
    else
        if [[ $CRLF_CHECKS == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi

}

function lfi() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $LFI == true ]] \
        && [[ -s "gf/lfi.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "LFI Checks"

        # Ensure gf/lfi.txt is not empty
        if [[ -s "gf/lfi.txt" ]]; then
            _print_msg INFO "Running: LFI Payload Generation"

            # Process lfi.txt with qsreplace and filter lines containing 'FUZZ'
            if ! _vulns_build_qsreplace_fuzz_list "gf/lfi.txt" ".tmp/tmp_lfi.txt"; then
                end_func "LFI: no injectable query parameters in gf/lfi.txt after FUZZ prep." "${FUNCNAME[0]}" "SKIP_NOINPUT"
                return 0
            fi

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_lfi.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

                _print_msg INFO "Running: LFI Fuzzing with FFUF"

                # Use Interlace to parallelize FFUF scanning
                run_command interlace -tL ".tmp/tmp_lfi.txt" -threads "$INTERLACE_THREADS" -c "ffuf -v -r -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -w \"${lfi_wordlist}\" -u \"_target_\" -mr \"root:\" " 2>>"$LOGFILE" \
                    | grep -aF "| URL |" | sed 's/.*| URL | //' | anew -q "vulns/lfi.txt"

                # Additional LFI engine: exhumed. Runs alongside the ffuf pass above
                # (not a replacement, not optional) -- it walks a curated high-value
                # file-path database with parser-aware content confirmation (ssh-key,
                # proc-environ, config, unix-passwd, ...) instead of ffuf's single
                # "root:" body-regex match, and additionally covers POST body, JSON
                # body, header and cookie injection points via its own request-shape
                # detection against each candidate URL.
                local exhumed_bin="${tools}/exhumed/exhumed"
                if [[ -x "$exhumed_bin" ]]; then
                    _print_msg INFO "Running: LFI Fuzzing with exhumed (additional engine)"

                    if ensure_dirs .tmp/exhumed_out; then
                        : >"vulns/lfi_exhumed.txt"

                        run_command interlace -tL ".tmp/tmp_lfi.txt" -threads "$INTERLACE_THREADS" \
                            -c "{ printf 'TARGET:%s\n' \"_target_\"; \"${exhumed_bin}\" scan --url \"_target_\" --marker FUZZ --concurrency 10 --rate 20 --timeout 10s --traversal-depth 10 --only-hits; } > .tmp/exhumed_out/_cleantarget_.txt 2>>\"${LOGFILE}\"" \
                            2>>"$LOGFILE" >/dev/null

                        for _exhumed_out_file in .tmp/exhumed_out/*.txt; do
                            [[ -s "$_exhumed_out_file" ]] || continue
                            _exhumed_target=$(grep -m1 '^TARGET:' "$_exhumed_out_file" 2>/dev/null | sed 's/^TARGET://')
                            grep '^\[CONFIRMED\]' "$_exhumed_out_file" 2>/dev/null | while IFS= read -r _exhumed_hit; do
                                printf '%s :: %s\n' "${_exhumed_target:-unknown}" "$_exhumed_hit"
                            done
                        done | anew -q "vulns/lfi_exhumed.txt"

                        if [[ -s "vulns/lfi_exhumed.txt" ]]; then
                            cat "vulns/lfi_exhumed.txt" 2>/dev/null | anew -q "vulns/lfi.txt" || true
                        fi
                        rm -rf .tmp/exhumed_out 2>/dev/null || true
                    fi
                else
                    _print_msg WARN "exhumed binary not found at ${exhumed_bin} (install.sh builds it from bugsyhewitt/exhumed); skipping additional LFI engine"
                fi

                end_func "Results are saved in vulns/lfi.txt (additional confirmed hits in vulns/lfi_exhumed.txt)" "${FUNCNAME[0]}"
            else
                end_func "Skipping LFI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/lfi.txt file found, LFI Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $LFI == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/lfi.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function ssti() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SSTI == true ]] \
        && [[ -s "gf/ssti.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SSTI Checks"

        # Ensure gf/ssti.txt is not empty
        if [[ -s "gf/ssti.txt" ]]; then
            local ssti_engine="${SSTI_ENGINE:-TInjA}"

            _print_msg INFO "Running: SSTI Payload Generation"

            # Process ssti.txt with qsreplace and filter lines containing 'FUZZ'
            if ! _vulns_build_qsreplace_fuzz_list "gf/ssti.txt" ".tmp/tmp_ssti.txt"; then
                end_func "SSTI: no injectable query parameters in gf/ssti.txt after FUZZ prep." "${FUNCNAME[0]}" "SKIP_NOINPUT"
                return 0
            fi

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_ssti.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then
                : >".tmp/ssti_candidates.txt"

                if [[ "$ssti_engine" == "SSTImap" ]]; then
                    # --- SSTImap branch ---
                    local sstimap_bin="${tools}/SSTImap/sstimap.py"
                    local sstimap_python="${tools}/SSTImap/venv/bin/python3"
                    if [[ ! -f "$sstimap_bin" ]] || [[ ! -f "$sstimap_python" ]]; then
                        end_func "Skipping SSTI: SSTImap not installed." "${FUNCNAME[0]}" "SKIP_MISSING_TOOL"
                        return 0
                    fi

                    _print_msg INFO "Running: SSTI Checks with SSTImap (level ${SSTIMAP_LEVEL:-1})"

                    local -a sstimap_cmd=("$sstimap_python" "$sstimap_bin"
                        --level "${SSTIMAP_LEVEL:-1}"
                        --no-color
                    )
                    [[ "${SSTIMAP_LEGACY:-false}" == "true" ]] && sstimap_cmd+=(--legacy)
                    [[ "${SSTIMAP_GENERIC:-false}" == "true" ]] && sstimap_cmd+=(--generic)
                    [[ "${SSTIMAP_DELAY:-0}" -gt 0 ]] && sstimap_cmd+=(--delay "${SSTIMAP_DELAY}")
                    [[ -n "${HEADER:-}" ]] && sstimap_cmd+=(-H "${HEADER}")

                    sstimap_cmd+=(--load-urls ".tmp/tmp_ssti.txt")

                    if ! run_command "${sstimap_cmd[@]}" 2>>"$LOGFILE" | tee ".tmp/sstimap_raw.txt" | grep -i "confirmed\|identified" | grep -oP 'https?://[^\s]+' | anew -q ".tmp/ssti_candidates.txt"; then
                        log_note "ssti: SSTImap execution failed or no findings" "${FUNCNAME[0]}" "${LINENO}"
                    fi
                else
                    # --- TInjA branch (default) ---
                    if ! command -v TInjA >/dev/null 2>&1; then
                        end_func "Skipping SSTI: TInjA not installed." "${FUNCNAME[0]}" "SKIP_MISSING_TOOL"
                        return 0
                    fi

                    _print_msg INFO "Running: SSTI Checks with TInjA"
                    local TInjA_report_dir="$dir/.tmp/TInjA"
                    mkdir -p "$TInjA_report_dir"
                    local -a TInjA_cmd=(TInjA url --reportpath "${TInjA_report_dir}/" --ratelimit "${TInjA_RATELIMIT:-0}" --timeout "${TInjA_TIMEOUT:-15}" --verbosity 0)
                    if [[ -n "${HEADER:-}" ]]; then
                        TInjA_cmd+=(-H "${HEADER}")
                    fi
                    while IFS= read -r u; do
                        [[ -n "$u" ]] && TInjA_cmd+=(--url "$u")
                    done <".tmp/tmp_ssti.txt"

                    if ! run_command "${TInjA_cmd[@]}" 2>>"$LOGFILE" >/dev/null; then
                        log_note "ssti: TInjA execution failed, no findings collected" "${FUNCNAME[0]}" "${LINENO}"
                    fi

                    local report_file=""
                    report_file=$(ls -1t "${TInjA_report_dir}"/*.jsonl 2>/dev/null | head -n 1 || true)
                    if [[ -n "$report_file" && -s "$report_file" ]]; then
                        jq -r 'select((.isWebpageVulnerable == true) or any(.parameters[]?; .isParameterVulnerable == true)) | (.url // empty) + " [certainty:" + (.certainty // "unknown") + "]"' "$report_file" 2>/dev/null \
                            | sed '/^\s*$/d' \
                            | anew -q ".tmp/ssti_candidates.txt"
                    fi
                fi

                if [[ -s ".tmp/ssti_candidates.txt" ]]; then
                    cat ".tmp/ssti_candidates.txt" | anew -q "vulns/ssti_${ssti_engine}.txt"
                    cat ".tmp/ssti_candidates.txt" | anew -q "vulns/ssti.txt"
                fi

                end_func "Results are saved in vulns/ssti.txt" "${FUNCNAME[0]}"
            else
                end_func "Skipping SSTI: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}" "SKIP"
            fi
        else
            end_func "No gf/ssti.txt file found, SSTI Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $SSTI == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/ssti.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

# Legacy single .sqli marker → per-engine markers (sqlmap only if log dir exists; ghauri only if log exists).
_sqli_migrate_legacy_cache() {
    [[ -f "${called_fn_dir:-.called_fn}/.sqli" ]] || return 0
    [[ ! -f "${called_fn_dir}/.sqli_sqlmap" ]] && touch "${called_fn_dir}/.sqli_sqlmap"
    if [[ ! -f "${called_fn_dir}/.sqli_ghauri" ]] && [[ -s "vulns/ghauri_log.txt" ]]; then
        touch "${called_fn_dir}/.sqli_ghauri"
    fi
}

# Build .tmp/tmp_sqli.txt from gf/sqli.txt; honor DEEP_LIMIT.
_sqli_prepare_targets() {
    if ! ensure_dirs .tmp gf vulns; then
        return 1
    fi

    if [[ ! -s "gf/sqli.txt" ]]; then
        return 1
    fi

    if [[ -s ".tmp/tmp_sqli.txt" ]]; then
        local URL_COUNT
        URL_COUNT=$(wc -l <".tmp/tmp_sqli.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then
            return 0
        fi
    fi

    _print_msg INFO "Running: SQLi Payload Generation"
    if ! _vulns_build_qsreplace_fuzz_list "gf/sqli.txt" ".tmp/tmp_sqli.txt"; then
        _print_msg WARN "SQLi: no injectable query parameters in gf/sqli.txt after FUZZ prep (need URLs with ?param=)."
        return 1
    fi

    local URL_COUNT
    URL_COUNT=$(wc -l <".tmp/tmp_sqli.txt")
    if [[ $DEEP != true ]] && [[ $URL_COUNT -gt $DEEP_LIMIT ]]; then
        _print_msg WARN "SQLi: too many URLs (${URL_COUNT}), try with --deep flag."
        return 1
    fi

    return 0
}

_sqli_ensure_targets() {
    if [[ -s ".tmp/tmp_sqli.txt" ]]; then
        local URL_COUNT
        URL_COUNT=$(wc -l <".tmp/tmp_sqli.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then
            return 0
        fi
    fi
    _sqli_prepare_targets
}

_sqli_has_crawl_roots() {
    [[ ${SQLMAP_CRAWL_FALLBACK:-true} == true ]] || return 1
    [[ -s "webs/webs_all.txt" || -s "webs/webs.txt" || -s "webs/webs_uncommon_ports.txt" ]]
}

_sqli_prepare_crawl_roots() {
    local roots_file=".tmp/tmp_sqli_crawl_roots.txt"
    local max_roots="${SQLMAP_CRAWL_MAX_ROOTS:-25}"

    ensure_dirs .tmp webs || return 1
    : >"$roots_file"

    if [[ ! -s "webs/webs_all.txt" ]]; then
        cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | sed '/^$/d' | sort -u >"webs/webs_all.txt" || true
    fi

    cat webs/webs_all.txt webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null \
        | grep -aE '^https?://' \
        | sed 's/[[:space:]]*$//' \
        | awk '
            NF {
                u=$0
                lu=tolower(u)
                rank=3
                if (lu ~ /^https:\/\/[^\/:]+(:443)?([\/?#]|$)/) rank=1
                else if (lu ~ /^http:\/\/[^\/:]+(:80)?([\/?#]|$)/) rank=2
                print rank "\t" u
            }
        ' \
        | sort -k1,1n -k2,2 \
        | awk -F'\t' '!seen[$2]++ { print $2 }' >"$roots_file" || true

    [[ -s "$roots_file" ]] || return 1

    if [[ $DEEP != true && "$max_roots" -gt 0 ]]; then
        local root_count
        root_count=$(wc -l <"$roots_file" 2>/dev/null || echo 0)
        if [[ "$root_count" -gt "$max_roots" ]]; then
            sed -n "1,${max_roots}p" "$roots_file" >"${roots_file}.cap"
            mv "${roots_file}.cap" "$roots_file"
            _print_msg WARN "SQLMap crawl fallback: capped web roots to ${max_roots} (set SQLMAP_CRAWL_MAX_ROOTS or use --deep for more)"
        fi
    fi

    [[ -s "$roots_file" ]]
}

# Pick interlace worker count from GHAURI_THREADS and available RAM ( ~700MB per worker ).
_sqli_ghauri_pick_threads() {
    local target_count="$1"
    local want="${GHAURI_THREADS:-3}"
    local avail_mb max_threads threads

    avail_mb=$(awk '/MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    if [[ "$avail_mb" -ge 12000 ]]; then
        max_threads=4
    elif [[ "$avail_mb" -ge 8000 ]]; then
        max_threads=3
    elif [[ "$avail_mb" -ge 5000 ]]; then
        max_threads=2
    elif [[ "$avail_mb" -gt 0 ]]; then
        max_threads=1
    else
        max_threads=3
    fi

    threads="$want"
    [[ "$threads" -gt "$max_threads" ]] && threads="$max_threads"

    # Very large lists: avoid 3+ sustained workers even when RAM looks fine
    if [[ "$target_count" -gt 1200 ]] && [[ "$threads" -gt 2 ]]; then
        threads=2
    fi

    printf '%s' "$threads"
}

# Free RAM before ghauri (sqlmap may have just finished in sqli()).
_sqli_prep_before_ghauri() {
    pkill -f "ghauri -u" 2>/dev/null || true
    sleep 1
}

# Run ghauri via interlace in URL batches; merge logs after each batch to cap peak RAM.
_sqli_ghauri_run_batches() {
    local list="$1"
    local threads="$2"
    local confirm_flag="$3"
    local batch_size="${GHAURI_BATCH_SIZE:-50}"
    local batch_file=".tmp/ghauri_batch.txt"
    local total line_no=1 batch_num=0

    total=$(wc -l <"$list" 2>/dev/null || echo 0)
    [[ "$total" -eq 0 ]] && return 0

    mkdir -p .tmp/ghauri_parts

    while [[ $line_no -le $total ]]; do
        batch_num=$((batch_num + 1))
        sed -n "${line_no},$((line_no + batch_size - 1))p" "$list" >"$batch_file"
        [[ ! -s "$batch_file" ]] && break

        _print_msg INFO "Ghauri batch ${batch_num}: lines ${line_no}-$((line_no + $(wc -l <"$batch_file") - 1)) / ${total}"
        run_command interlace -tL "$batch_file" -threads "$threads" \
            -c "printf '%s\n' '=== TARGET: _target_ ===' >> .tmp/ghauri_parts/_cleantarget_.txt; ghauri -u \"_target_\" --batch ${confirm_flag} -H \"${HEADER}\" --force-ssl >> .tmp/ghauri_parts/_cleantarget_.txt 2>&1" \
            2>>"$LOGFILE" >/dev/null || true

        _vulns_merge_ghauri_parts || true
        rm -rf .tmp/ghauri_parts/*
        pkill -f "ghauri -u" 2>/dev/null || true
        line_no=$((line_no + batch_size))
    done
}

function sqli_sqlmap() {
    local fn="sqli_sqlmap"

    if [[ $SQLI != true ]] || [[ $SQLMAP != true ]] \
        || [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if [[ $SQLMAP == false ]]; then
            skip_notification "disabled"
        elif [[ $SQLI == false ]]; then
            skip_notification "disabled"
        fi
        return 0
    fi

    if [[ ! -s "gf/sqli.txt" ]] && ! _sqli_has_crawl_roots; then
            skip_notification "noinput"
        return 0
    fi

    if [[ -f "$called_fn_dir/.${fn}" ]] && [[ $DIFF != true ]]; then
        skip_notification "processed"
        return 0
    fi

    local crawl_fallback=false
    if ! _sqli_ensure_targets; then
        if _sqli_prepare_crawl_roots; then
            crawl_fallback=true
        else
        end_func "SQLi: no targets for sqlmap." "$fn" "SKIP_NOINPUT"
        return 0
        fi
    fi

    start_func "$fn" "SQLMap SQLi Checks"
    mkdir -p vulns/sqlmap
    if [[ "$crawl_fallback" == true ]]; then
        local crawl_depth="${SQLMAP_CRAWL_DEPTH:-2}"
        local crawl_roots_count sqlmap_log sqlmap_cmd_file
        crawl_roots_count=$(wc -l <".tmp/tmp_sqli_crawl_roots.txt" 2>/dev/null || echo 0)
        sqlmap_log="vulns/sqlmap/crawl_fallback.log"
        sqlmap_cmd_file="vulns/sqlmap/crawl_fallback_command.txt"
        cp ".tmp/tmp_sqli_crawl_roots.txt" "vulns/sqlmap/crawl_fallback_targets.txt" 2>/dev/null || true
        {
            printf 'Started: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')"
            printf 'Mode: crawl fallback\n'
            printf 'Targets: %s\n' "$crawl_roots_count"
            printf 'Crawl depth: %s\n' "$crawl_depth"
            printf 'Command:\n'
            printf 'python3 %q -m %q --crawl=%q --forms -b -o --smart --batch --disable-coloring --random-agent --level=3 --risk=2 --output-dir=%q\n' \
                "${tools}/sqlmap/sqlmap.py" ".tmp/tmp_sqli_crawl_roots.txt" "$crawl_depth" "vulns/sqlmap"
        } >"$sqlmap_cmd_file"
        : >"$sqlmap_log"
        _print_msg INFO "Running: SQLMap crawl fallback (${crawl_roots_count} root(s), crawl depth ${crawl_depth})"
        run_command python3 "${tools}/sqlmap/sqlmap.py" -m ".tmp/tmp_sqli_crawl_roots.txt" --crawl="$crawl_depth" --forms -b -o --smart \
            --batch --disable-coloring --random-agent --level=3 --risk=2 \
            --output-dir="vulns/sqlmap" >>"$sqlmap_log" 2>&1 || true
        cat "$sqlmap_log" >>"$LOGFILE" 2>/dev/null || true
        _sqli_sqlmap_write_crawl_findings
    else
        _print_msg INFO "Running: SQLMap for SQLi Checks"
        run_command python3 "${tools}/sqlmap/sqlmap.py" -m ".tmp/tmp_sqli.txt" -b -o --smart \
            --batch --disable-coloring --random-agent --level=5 --risk=3 \
            --output-dir="vulns/sqlmap" 2>>"$LOGFILE" >/dev/null
    fi
    end_func "Results are saved in vulns/sqlmap (crawl hits also summarized in vulns/sqlmap/crawl_findings.txt)" "$fn"
}

# Summarize sqlmap crawl outcome into a short file so hits are obvious without reading the full log.
_sqli_sqlmap_write_crawl_findings() {
    local findings="vulns/sqlmap/crawl_findings.txt"
    local csv_hits=0
    local log_hits=0
    local forms_tested=0
    local no_usable=0
    local csv_file

    mkdir -p vulns/sqlmap
    {
        printf 'Started: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')"
        printf 'Source log: vulns/sqlmap/crawl_fallback.log\n'
        printf '\n== How to read this ==\n'
        printf 'HIT  = sqlmap reported injectable/vulnerable parameter(s)\n'
        printf 'CSV  = rows in vulns/sqlmap/results-*.csv\n'
        printf 'NO   = crawl ran but found no injectable params\n\n'
    } >"$findings"

    forms_tested=$(grep -acE '^\[.*/.*\] Form:' "vulns/sqlmap/crawl_fallback.log" 2>/dev/null || echo 0)
    no_usable=$(grep -ac 'no usable links found' "vulns/sqlmap/crawl_fallback.log" 2>/dev/null || echo 0)
    printf 'Forms discovered/tested: %s\n' "$forms_tested" >>"$findings"
    printf 'Roots with no usable links/forms: %s\n\n' "$no_usable" >>"$findings"

    # Prefer sqlmap multi-target CSV (only real confirmed injectables land here).
    for csv_file in vulns/sqlmap/results-*.csv; do
        [[ -s "$csv_file" ]] || continue
        if awk 'NR>1 && NF>0 {found=1; exit} END{exit !found}' "$csv_file" 2>/dev/null; then
            printf '== CSV hits from %s ==\n' "$csv_file" >>"$findings"
            awk 'NR==1 || NF>0' "$csv_file" >>"$findings"
            printf '\n' >>"$findings"
            csv_hits=$(awk 'NR>1 && NF>0 {c++} END{print c+0}' "$csv_file")
        fi
    done

    # Also pull high-signal lines from the raw crawl log.
    if [[ -s "vulns/sqlmap/crawl_fallback.log" ]]; then
        grep -aE 'is vulnerable|appears to be injectable|sqlmap identified the following injection|Parameter: .* \|' \
            "vulns/sqlmap/crawl_fallback.log" 2>/dev/null \
            | sed 's/\r$//' | anew -q ".tmp/sqlmap_crawl_hit_lines.txt" || true
        if [[ -s ".tmp/sqlmap_crawl_hit_lines.txt" ]]; then
            printf '== High-signal lines from crawl_fallback.log ==\n' >>"$findings"
            cat ".tmp/sqlmap_crawl_hit_lines.txt" >>"$findings"
            printf '\n' >>"$findings"
            log_hits=$(wc -l <".tmp/sqlmap_crawl_hit_lines.txt" | tr -d ' ')
        fi
    fi

    if ((csv_hits > 0 || log_hits > 0)); then
        printf 'RESULT: HIT (csv_hits=%s, log_hit_lines=%s)\n' "$csv_hits" "$log_hits" >>"$findings"
        notification "SQLMap crawl: HIT detected - see vulns/sqlmap/crawl_findings.txt" warn
        _print_msg WARN "SQLMap crawl findings written to vulns/sqlmap/crawl_findings.txt"
    else
        printf 'RESULT: NO injectable parameters found by crawl fallback\n' >>"$findings"
        _print_msg INFO "SQLMap crawl: no injectable findings (summary in vulns/sqlmap/crawl_findings.txt)"
    fi
}

function sqli_ghauri() {
    local fn="sqli_ghauri"

    if [[ $SQLI != true ]] || [[ $GHAURI != true ]] \
        || [[ ! -s "gf/sqli.txt" ]] || [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if [[ $GHAURI == false ]]; then
            skip_notification "disabled"
        elif [[ $SQLI == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/sqli.txt" ]]; then
            skip_notification "noinput"
        fi
        return 0
    fi

    if [[ -f "$called_fn_dir/.${fn}" ]] && [[ $DIFF != true ]]; then
        skip_notification "processed"
        return 0
    fi

    if ! command -v ghauri >/dev/null 2>&1; then
        _print_msg WARN "${fn}: ghauri not found in PATH"
        return 0
    fi

    if ! _sqli_ensure_targets; then
        end_func "SQLi: no targets for ghauri." "$fn" "SKIP_NOINPUT"
        return 0
    fi

    _sqli_prep_before_ghauri

    start_func "$fn" "Ghauri SQLi Checks"
    _print_msg INFO "Running: Ghauri for SQLi Checks"
    mkdir -p .tmp/ghauri_parts vulns
    rm -rf .tmp/ghauri_parts/*
    rm -f vulns/ghauri.txt
    : >vulns/ghauri_log.txt

    local ghauri_target_count=0
    ghauri_target_count=$(wc -l <".tmp/tmp_sqli.txt" 2>/dev/null || echo 0)

    local ghauri_threads
    ghauri_threads=$(_sqli_ghauri_pick_threads "$ghauri_target_count")
    if [[ "${GHAURI_THREADS:-3}" -gt "$ghauri_threads" ]]; then
        _print_msg INFO "Ghauri: using ${ghauri_threads} worker(s) (${ghauri_target_count} targets, ~$(awk '/MemAvailable:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo '?')MB RAM available)"
    fi

    if [[ ! -s ".tmp/tmp_sqli.txt" ]]; then
        printf '%s\n' "No ghauri targets in .tmp/tmp_sqli.txt." >>vulns/ghauri_log.txt
        end_func "No ghauri targets." "$fn" "SKIP_NOINPUT"
        return 0
    fi

    local ghauri_confirm_flag=""
    case "${GHAURI_CONFIRM:-current-db}" in
        dbs|true)
            ghauri_confirm_flag="--dbs"
            ;;
        current-db|current_db|currentdb)
            ghauri_confirm_flag="--current-db"
            ;;
        none|false)
            ghauri_confirm_flag=""
            ;;
    esac
    [[ "${GHAURI_ENUM_DBS:-}" == "true" ]] && ghauri_confirm_flag="--dbs"

    {
        printf '=== GHAURI RUN %s ===\n' "$(date +'%Y-%m-%d %H:%M:%S')"
        printf 'targets=%s threads=%s batch=%s confirm=%s\n' \
            "$ghauri_target_count" "$ghauri_threads" "${GHAURI_BATCH_SIZE:-50}" "${ghauri_confirm_flag:-none}"
    } >>vulns/ghauri_log.txt

    local _ghauri_merge_done=false
    _ghauri_finalize_parts() {
        [[ "$_ghauri_merge_done" == true ]] && return 0
        _ghauri_merge_done=true
        _vulns_merge_ghauri_parts || true
        rm -rf .tmp/ghauri_parts 2>/dev/null || true
    }
    trap '_ghauri_finalize_parts' RETURN

    _sqli_ghauri_run_batches ".tmp/tmp_sqli.txt" "$ghauri_threads" "$ghauri_confirm_flag"

    trap - RETURN
    _ghauri_finalize_parts
    end_func "Results are saved in vulns/ghauri_log.txt" "$fn"
}

function sqli() {
    if [[ $SQLI != true ]] \
        || [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        if [[ $SQLI == false ]]; then
            skip_notification "disabled"
        fi
        return 0
    fi

    if [[ ! -s "gf/sqli.txt" ]] && ! _sqli_has_crawl_roots; then
        skip_notification "noinput"
        return 0
    fi

    _sqli_migrate_legacy_cache
    sqli_sqlmap
    sqli_ghauri
}

function test_ssl() {

    # Create necessary directories
    if ! ensure_dirs hosts vulns; then return 1; fi

    # Check if the function should run
    if should_run "TEST_SSL"; then

        start_func "${FUNCNAME[0]}" "SSL Test"

        # Handle multi-domain scenarios
        if [[ -n $multi ]] && [[ ! -f "$dir/hosts/ips.txt" ]]; then
            echo "$domain" >"$dir/hosts/ips.txt"
        fi

        # Run testssl.sh — prefer non-CDN IPs to avoid testing CDN TLS configs
        local testssl_input="$dir/hosts/ips.txt"
        if [[ -s "$dir/.tmp/ips_nocdn.txt" ]]; then
            testssl_input="$dir/.tmp/ips_nocdn.txt"
        fi
        _print_msg INFO "Running: SSL Test with testssl.sh"
        run_command "${tools}/testssl.sh/testssl.sh" --quiet --color 0 -U -iL "$testssl_input" 2>>"$LOGFILE" >"vulns/testssl.txt"

        end_func "Results are saved in vulns/testssl.txt" "${FUNCNAME[0]}"

    else
        if [[ $TEST_SSL == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "vulns/testssl.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function spraying() {

    # Create necessary directories
    if ! ensure_dirs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SPRAY == true ]] \
        && [[ -s "$dir/hosts/portscan_active.gnmap" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Password Spraying"

        # Ensure portscan_active.gnmap exists and is not empty
        if [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
            print_warnf "File %s/hosts/portscan_active.gnmap does not exist or is empty." "$dir"
            end_func "Port scan results missing. Password Spraying aborted." "${FUNCNAME[0]}"
            return 1
        fi

        local spray_engine="${SPRAY_ENGINE:-brutespray}"
        if [[ "$spray_engine" == "brutus" ]]; then
            if [[ "${SPRAY_BRUTUS_ONLY_DEEP:-true}" == "true" && "${DEEP:-false}" != "true" ]]; then
                end_func "Brutus spraying is DEEP-gated (set DEEP=true or SPRAY_BRUTUS_ONLY_DEEP=false)" "${FUNCNAME[0]}" SKIP
                return 0
            fi
            if ! command -v brutus >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: brutus not found in PATH"
                end_func "Brutus not available, skipping" "${FUNCNAME[0]}" SKIP
                return 0
            fi

            local brutus_input=""
            if [[ -s "$dir/hosts/service_fingerprints.jsonl" ]]; then
                brutus_input="$dir/hosts/service_fingerprints.jsonl"
            elif [[ -s "$dir/hosts/naabu_open.txt" ]] && command -v nerva >/dev/null 2>&1; then
                run_command nerva --json -l "$dir/hosts/naabu_open.txt" -o "$dir/.tmp/service_fp_for_brutus.jsonl" 2>>"$LOGFILE" >/dev/null || true
                [[ -s "$dir/.tmp/service_fp_for_brutus.jsonl" ]] && brutus_input="$dir/.tmp/service_fp_for_brutus.jsonl"
            fi

            if [[ -z "$brutus_input" ]]; then
                end_func "No service fingerprint JSON input for brutus (run portscan with SERVICE_FINGERPRINT=true)" "${FUNCNAME[0]}" SKIP
                return 0
            fi

            local -a brutus_cmd=(brutus --json -o "$dir/vulns/brutus.jsonl")
            [[ -n "${BRUTUS_USERNAMES:-}" ]] && brutus_cmd+=(-u "$BRUTUS_USERNAMES")
            [[ -n "${BRUTUS_PASSWORDS:-}" ]] && brutus_cmd+=(-p "$BRUTUS_PASSWORDS")
            [[ -n "${BRUTUS_KEY_FILE:-}" ]] && brutus_cmd+=(-k "$BRUTUS_KEY_FILE")

            _print_msg INFO "Running: Password Spraying with Brutus"
            if ! run_command "${brutus_cmd[@]}" <"$brutus_input" 2>>"$LOGFILE" >/dev/null; then
                _print_msg WARN "Brutus command failed, continuing"
            fi
            end_func "Results are saved in vulns/brutus.jsonl" "${FUNCNAME[0]}"
            return 0
        fi

        if ! command -v brutespray >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: brutespray not found in PATH"
            end_func "BruteSpray not available, skipping" "${FUNCNAME[0]}" SKIP
            return 0
        fi

        _print_msg INFO "Running: Password Spraying with BruteSpray"
        brutespray -f "$dir/hosts/portscan_active.gnmap" -T "$BRUTESPRAY_CONCURRENCE" -o "$dir/vulns/brutespray" 2>>"$LOGFILE" >/dev/null
        end_func "Results are saved in vulns/brutespray folder" "${FUNCNAME[0]}"

    else
        if [[ $SPRAY == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "$dir/hosts/portscan_active.gnmap" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function command_injection() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $COMM_INJ == true ]] \
        && [[ -s "gf/rce.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "Command Injection Checks"

        # Ensure gf/rce.txt is not empty and process it
        if [[ -s "gf/rce.txt" ]]; then
            _print_msg INFO "Running: Command Injection Payload Generation"

            # Process rce.txt with qsreplace and filter lines containing 'FUZZ'
            if ! _vulns_build_qsreplace_fuzz_list "gf/rce.txt" ".tmp/tmp_rce.txt"; then
                end_func "Command injection: no injectable query parameters in gf/rce.txt after FUZZ prep." "${FUNCNAME[0]}" "SKIP_NOINPUT"
                return 0
            fi

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_rce.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

    # Run Commix if enabled (COMM_INJ enables by default when COMMIX unset)
    if [[ ${COMMIX:-$COMM_INJ} == true ]]; then
        _print_msg INFO "Running: Commix for Command Injection Checks"
        mkdir -p "vulns/command_injection/logs"
        : >"vulns/command_injection/targets.txt"
        : >"vulns/command_injection/confirmed.txt"
        cp ".tmp/tmp_rce.txt" "vulns/command_injection/targets.txt" 2>/dev/null || true

        local commix_timeout="${COMMIX_TIMEOUT:-60m}"
        local commix_answers="${COMMIX_ANSWERS:-pseudo-terminal=N}"
        local commix_target commix_idx=0 commix_total commix_hash commix_one commix_log
        commix_total=$(wc -l <".tmp/tmp_rce.txt" 2>/dev/null || echo 0)

        while IFS= read -r commix_target || [[ -n "$commix_target" ]]; do
            [[ -z "$commix_target" ]] && continue
            commix_idx=$((commix_idx + 1))
            commix_hash=$(_hash_string "$commix_target")
            commix_one=".tmp/commix_target_${commix_hash}.txt"
            commix_log="vulns/command_injection/logs/${commix_idx}_${commix_hash}.log"
            printf '%s\n' "$commix_target" >"$commix_one"
            {
                printf 'Started: %s\n' "$(date +'%Y-%m-%d %H:%M:%S')"
                printf 'Target %s/%s: %s\n' "$commix_idx" "$commix_total" "$commix_target"
                printf 'Timeout: %s\n\n' "$commix_timeout"
                printf 'Answers: %s\n\n' "$commix_answers"
            } >"$commix_log"

            _print_msg INFO "Commix target ${commix_idx}/${commix_total}"
            local -a commix_cmd=(commix --batch -m "$commix_one" --output-dir "vulns/command_injection")
            [[ -n "$commix_answers" ]] && commix_cmd+=(--answers="$commix_answers")
            if [[ -n "${TIMEOUT_CMD:-}" && "$commix_timeout" != "0" && "$commix_timeout" != "false" ]]; then
                run_command "$TIMEOUT_CMD" -k 30s "$commix_timeout" "${commix_cmd[@]}" \
                    </dev/null >>"$commix_log" 2>&1 || {
                    local commix_rc=$?
                    if [[ "$commix_rc" -eq 124 || "$commix_rc" -eq 137 ]]; then
                        printf '\nTimed out after %s\n' "$commix_timeout" >>"$commix_log"
                        printf '%s\n' "$commix_target" | anew -q "vulns/command_injection/timed_out.txt"
                    else
                        printf '\nCommix exited with code %s\n' "$commix_rc" >>"$commix_log"
                    fi
                }
            else
                run_command "${commix_cmd[@]}" </dev/null >>"$commix_log" 2>&1 || true
            fi

            # Extract genuine confirmations from the raw log. Commix prints an
            # unambiguous line only when it actually confirms injectability:
            #   "The <method> parameter '<name>' seems injectable via
            #    (<technique>) ... command injection technique."
            # Everything else in the log (negotiation prompts, "not injectable",
            # progress noise) is not a finding. Without this, the raw per-target
            # logs are indistinguishable noise vs. real hits at a glance.
            if grep -aq "seems injectable via" "$commix_log" 2>/dev/null; then
                {
                    printf '%s\n' "$commix_target"
                    grep -a "seems injectable via" "$commix_log" | sed 's/^/    /'
                    printf '    log: %s\n' "$commix_log"
                } >>"vulns/command_injection/confirmed.txt"
            fi

            cat "$commix_log" >>"$LOGFILE" 2>/dev/null || true
            rm -f "$commix_one" 2>/dev/null || true
        done <".tmp/tmp_rce.txt"
    fi

                # Additional tools can be integrated here (e.g., Ghauri, sqlmap)

                end_func "Results are saved in vulns/command_injection folder -- vulns/command_injection/confirmed.txt holds actual confirmed hits, logs/*.log are raw per-target output" "${FUNCNAME[0]}"
            else
                end_func "Skipping Command Injection: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
            fi
        else
            end_func "No gf/rce.txt file found, Command Injection Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $COMM_INJ == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/rce.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function 4xxbypass() {

    # Create necessary directories
    if ! ensure_dirs .tmp fuzzing vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $BYPASSER4XX == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        # Extract relevant URLs starting with 4xx but not 404
        grep -E '^4' "fuzzing/fuzzing_full.txt" 2>/dev/null | grep -Ev '^404' | awk '{print $3}' | anew -q ".tmp/403test.txt"

        # Count the number of URLs to process
        URL_COUNT=$(wc -l <".tmp/403test.txt")

        start_func "${FUNCNAME[0]}" "403 Bypass"

        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            # Run nomore403 in a subshell to avoid CWD pollution
            (
                cd "${tools}/nomore403" || exit 1
                ./nomore403 <"$dir/.tmp/403test.txt" >"$dir/.tmp/4xxbypass.txt" 2>>"$LOGFILE"
            )
            if [[ $? -ne 0 ]]; then
                print_warnf "nomore403 failed or directory not found."
                end_func "Failed during 403 Bypass." "${FUNCNAME[0]}"
                return 1
            fi

            # Append unique bypassed URLs to the vulns directory
            if [[ -s "$dir/.tmp/4xxbypass.txt" ]]; then
                cat "$dir/.tmp/4xxbypass.txt" | anew -q "vulns/4xxbypass.txt"
            fi

            end_func "Results are saved in vulns/4xxbypass.txt" "${FUNCNAME[0]}"

        else
            notification "Too many URLs to bypass, skipping" warn
            end_func "Skipping 403 Bypass: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        if [[ $BYPASSER4XX == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function smuggling() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns/smuggling; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SMUGGLING == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ! command -v smugglex >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: smugglex not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "HTTP Request Smuggling Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat "webs/webs.txt" "webs/webs_uncommon_ports.txt" 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: HTTP Request Smuggling Checks"

            # Run smugglex on the list of URLs
            cat "$dir/webs/webs_all.txt" | smugglex -f plain -o "$dir/.tmp/smuggling.txt" 2>>"$LOGFILE" >/dev/null

            # Append unique smuggling results to vulns directory
            if [[ -s "$dir/.tmp/smuggling.txt" ]]; then
                jq -c < "$dir/.tmp/smuggling.txt" 2>>"$LOGFILE" | anew -q "vulns/smuggling.txt"
            fi

            end_func "Findings are saved in vulns/smuggling.txt" "${FUNCNAME[0]}"

        else
            notification "Too many URLs to bypass, skipping" warn
            end_func "Skipping HTTP Request Smuggling: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        if [[ $SMUGGLING == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "webs/webs_all.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function webcache() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $WEBCACHE == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if ! command -v Web-Cache-Vulnerability-Scanner >/dev/null 2>&1; then
            _print_msg WARN "${FUNCNAME[0]}: Web-Cache-Vulnerability-Scanner not found in PATH"
            return 0
        fi
        start_func "${FUNCNAME[0]}" "Web Cache Poisoning Checks"

        # Combine webs.txt and webs_uncommon_ports.txt into webs_all.txt if it doesn't exist
        if [[ ! -s "webs/webs_all.txt" ]]; then
            cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q "webs/webs_all.txt"
        fi

        # Determine whether to proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/webs_all.txt")
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

            _print_msg INFO "Running: Web Cache Poisoning Checks"

            # Run Web-Cache-Vulnerability-Scanner in a subshell to avoid CWD pollution
            (
                cd "${tools}/Web-Cache-Vulnerability-Scanner" || exit 1
                Web-Cache-Vulnerability-Scanner -u "file:$dir/webs/webs_all.txt" -v 0 2>>"$LOGFILE" \
                    | anew -q "$dir/.tmp/webcache.txt"
            )
            if [[ $? -ne 0 ]]; then
                print_warnf "Web-Cache-Vulnerability-Scanner failed or directory not found."
            fi

            # Append unique findings to vulns/webcache.txt
            if [[ -s "$dir/.tmp/webcache.txt" ]]; then
                cat "$dir/.tmp/webcache.txt" | anew -q "vulns/webcache.txt"
            fi

            # Optional second engine (toxicache) to complement findings
            if [[ ${WEBCACHE_TOXICACHE:-true} == true ]] && command -v toxicache >/dev/null 2>&1; then
                local toxicache_out="$dir/.tmp/webcache_toxicache.txt"
                run_command toxicache -i "$dir/webs/webs_all.txt" -o "$toxicache_out" -t "${TOXICACHE_THREADS:-70}" -ua "${TOXICACHE_USER_AGENT:-Mozilla/5.0 (X11; Linux x86_64)}" 2>>"$LOGFILE" >/dev/null || true
                if [[ -s "$toxicache_out" ]]; then
                    cat "$toxicache_out" | anew -q "vulns/webcache_toxicache.txt"
                fi
            fi

            end_func "Results are saved in vulns/webcache.txt" "${FUNCNAME[0]}"

        else
            end_func "Skipping Web Cache Poisoning: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}"
        fi

    else
        if [[ $WEBCACHE == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "fuzzing/fuzzing_full.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

function fuzzparams() {

    # Create necessary directories
    if ! ensure_dirs .tmp webs vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $FUZZPARAMS == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        if [[ $AXIOM != true ]]; then
            if ! command -v nuclei >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei binary not found in PATH - install nuclei first"
                return 0
            fi
            if [[ ! -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei templates not found at '${NUCLEI_TEMPLATES_PATH}'"
                return 0
            fi
        fi
        start_func "${FUNCNAME[0]}" "Fuzzing Parameters Values Checks"

        if [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            _print_msg WARN "File webs/url_extract_nodupes.txt is missing or empty."
            end_func "Skipping fuzzparams: missing URL candidates." "${FUNCNAME[0]}" "SKIP"
            return
        fi

        # Determine if we should proceed based on DEEP flag or number of URLs
        URL_COUNT=$(wc -l <"webs/url_extract_nodupes.txt" 2>/dev/null || echo 0)
        if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT2 ]]; then

            #cent update -p ${NUCLEI_TEMPLATES_PATH} &>/dev/null

            if [[ $AXIOM != true ]]; then
                _print_msg INFO "Running: Nuclei Setup and Execution"

                # Update Nuclei once per run
                maybe_update_nuclei

                        # Execute Nuclei with the fuzzing templates

                        run_command nuclei -l webs/url_extract_nodupes.txt -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 ${NUCLEI_EXTRA_ARGS} -t ${NUCLEI_TEMPLATES_PATH}/dast -dast -j -o ".tmp/fuzzparams_json.txt" <"webs/url_extract_nodupes.txt" 2>>"$LOGFILE" >/dev/null

                    else

                        _print_msg INFO "Running: Axiom with Nuclei"

                        run_command axiom-scan webs/url_extract_nodupes.txt -m nuclei \
                            -dast -nh -rl "$NUCLEI_RATELIMIT" \
                            -silent -retries 2 "$NUCLEI_EXTRA_ARGS" -dast -j -o ".tmp/fuzzparams_json.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null

                    fi

                

            # Convert JSON output to text
            if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host) + (if .["extracted-results"] != null then " " + (.["extracted-results"] | @json) else "" end)] | .[]' .tmp/fuzzparams_json.txt >.tmp/fuzzparams.txt
            else
                : >.tmp/fuzzparams.txt
                log_note "fuzzparams: nuclei produced no JSON output; skipping conversion" "${FUNCNAME[0]}" "${LINENO}"
            fi

            # Append unique results to vulns/fuzzparams.txt
            if [[ -s ".tmp/fuzzparams.txt" ]]; then
                cat ".tmp/fuzzparams.txt" | anew -q "vulns/fuzzparams.txt"
            fi

            # Faraday integration
            if [[ $FARADAY == true ]]; then
                # Check if the Faraday server is running
                if ! faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                    print_warnf "Faraday server is not running. Skipping Faraday integration."
                else
                    if [[ -s ".tmp/fuzzparams_json.txt" ]]; then
                        faraday-cli tool report -w $FARADAY_WORKSPACE --plugin-id nuclei .tmp/fuzzparams_json.txt 2>>"$LOGFILE" >/dev/null
                    fi
                fi
            fi

            end_func "Results are saved in vulns/fuzzparams.txt" "${FUNCNAME[0]}"

        else
            end_func "Fuzzing Parameters Values: Too many entries to test, try with --deep flag" "${FUNCNAME[0]}"
        fi

    else
        if [[ $FUZZPARAMS == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "webs/url_extract_nodupes.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

}

_nuclei_dast_collect_targets() {
    : >".tmp/nuclei_dast_targets.txt"

    # Baseline web targets.
    if [[ -s "webs/webs_all.txt" ]]; then
        grep -aE '^https?://' "webs/webs_all.txt" | anew -q ".tmp/nuclei_dast_targets.txt"
    fi
    if [[ -s "hosts/webs.txt" ]]; then
        grep -aE '^https?://' "hosts/webs.txt" | anew -q ".tmp/nuclei_dast_targets.txt"
    fi
    if [[ -s "webs/url_extract_nodupes.txt" ]]; then
        grep -aE '^https?://' "webs/url_extract_nodupes.txt" | anew -q ".tmp/nuclei_dast_targets.txt"
    fi

    # Candidate URLs generated by GF patterns across vuln modules.
    local gf_file
    for gf_file in gf/*.txt; do
        [[ -s "$gf_file" ]] || continue
        grep -aE '^https?://' "$gf_file" | anew -q ".tmp/nuclei_dast_targets.txt"
    done

    sort -u ".tmp/nuclei_dast_targets.txt" -o ".tmp/nuclei_dast_targets.txt" 2>/dev/null || true
}

function nuclei_dast() {

    if ! ensure_dirs .tmp webs gf vulns nuclei_output; then return 1; fi

    # nuclei_dast is part of the vulnerability scanning pipeline.
    # If the user enables vulns (e.g. `-a`), force-enable this DAST pass to replace deprecated single-purpose modules.
    local dast_enabled="${NUCLEI_DAST:-true}"
    if [[ ${VULNS_GENERAL:-false} == true ]]; then
        if [[ ${NUCLEI_DAST:-true} != true ]]; then
            _print_msg WARN "NUCLEI_DAST is forced enabled when VULNS_GENERAL=true (e.g. -a)."
        fi
        dast_enabled=true
    fi

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ "$dast_enabled" == true ]]; then
        if [[ $AXIOM != true ]]; then
            if ! command -v nuclei >/dev/null 2>&1; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei binary not found in PATH - install nuclei first"
                return 0
            fi
            if [[ ! -d "${NUCLEI_TEMPLATES_PATH:-}" ]]; then
                _print_msg WARN "${FUNCNAME[0]}: nuclei templates not found at '${NUCLEI_TEMPLATES_PATH}'"
                return 0
            fi
        fi
        start_func "${FUNCNAME[0]}" "Nuclei DAST Scanner"
        maybe_update_nuclei

        _nuclei_dast_collect_targets
        if [[ ! -s ".tmp/nuclei_dast_targets.txt" ]]; then
            end_func "No DAST targets available from webs/url/gf inputs." "${FUNCNAME[0]}" "SKIP_NOINPUT"
            return 0
        fi

        local url_count
        url_count=$(wc -l <".tmp/nuclei_dast_targets.txt" 2>/dev/null || echo 0)
        if [[ $DEEP != true ]] && [[ "$url_count" -gt "${DEEP_LIMIT2:-1500}" ]]; then
            end_func "Skipping Nuclei DAST: too many targets (${url_count}), use --deep." "${FUNCNAME[0]}"
            return 0
        fi

        local dast_templates="${NUCLEI_DAST_TEMPLATE_PATH:-${NUCLEI_TEMPLATES_PATH}/dast}"
        if [[ $AXIOM != true ]]; then
            # shellcheck disable=SC2086  # Intentionally allow user-provided nuclei args
            run_command nuclei -l ".tmp/nuclei_dast_targets.txt" -dast -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 $NUCLEI_EXTRA_ARGS $NUCLEI_DAST_EXTRA_ARGS -t "$dast_templates" -j -o ".tmp/nuclei_dast_json_raw.txt" 2>>"$LOGFILE" >/dev/null
        else
            # shellcheck disable=SC2086  # Intentionally allow user-provided nuclei args
            run_command axiom-scan ".tmp/nuclei_dast_targets.txt" -m nuclei -dast -nh -rl "$NUCLEI_RATELIMIT" -silent -retries 2 $NUCLEI_EXTRA_ARGS $NUCLEI_DAST_EXTRA_ARGS -t "$dast_templates" -j -o ".tmp/nuclei_dast_json_raw.txt" $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
        fi

        if [[ -s ".tmp/nuclei_dast_json_raw.txt" ]]; then
            jq -c '. + {scan_scope:"dast"}' ".tmp/nuclei_dast_json_raw.txt" 2>/dev/null >"nuclei_output/dast_json.txt"
            jq -r '["[" + .["template-id"] + (if .["matcher-name"] != null then ":" + .["matcher-name"] else "" end) + "] [" + .["type"] + "] [" + .info.severity + "] " + (.["matched-at"] // .host)] | .[]' \
                "nuclei_output/dast_json.txt" 2>/dev/null | anew -q "vulns/nuclei_dast.txt"
        else
            : >"nuclei_output/dast_json.txt"
        fi

        if [[ $FARADAY == true ]] && [[ -s "nuclei_output/dast_json.txt" ]]; then
            if faraday-cli status 2>>"$LOGFILE" >/dev/null; then
                faraday-cli tool report -w "$FARADAY_WORKSPACE" --plugin-id nuclei "nuclei_output/dast_json.txt" 2>>"$LOGFILE" >/dev/null
            fi
        fi

        end_func "Results are saved in nuclei_output/dast_json.txt and vulns/nuclei_dast.txt" "${FUNCNAME[0]}"
    else
        if [[ "$dast_enabled" == false ]]; then
            skip_notification "disabled"
        else
            skip_notification "processed"
        fi
    fi
}

# Normalize a nuclei/cms URL to a WordPress site root (scheme + host[:port]).
_wp_brute_base_url() {
    local raw="${1:-}"
    raw="${raw//$'\r'/}"
    raw="${raw#"${raw%%[![:space:]]*}"}"
    raw="${raw%"${raw##*[![:space:]]}"}"
    [[ -z "$raw" ]] && return 1

    if [[ ! "$raw" =~ ^https?:// ]]; then
        raw="https://${raw}"
    fi

    raw=$(echo "$raw" | sed -E 's|^([a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]+).*|\1|')
    raw=$(echo "$raw" | sed -E 's|:443$||; s|:80$||')
    [[ -n "$raw" ]] && printf '%s\n' "$raw"
}

# Collect WordPress spray targets from nuclei (wp-user-enum / login / xmlrpc only).
# Excludes wordpress-eol and other weak tech-detect hits on non-WP stacks (e.g. Laravel).
_wp_brute_collect_targets() {
    : >".tmp/wp_brute_targets.txt"

    local json_file
    if [[ ! -d nuclei_output ]]; then
        return 0
    fi

    for json_file in nuclei_output/*_json.txt nuclei_output/dast_json.txt; do
        [[ -f "$json_file" && -s "$json_file" ]] || continue
        jq -r '
            select((."template-id" // "" | test("(?i)(wp-user|wordpress.*user|wp-login|xmlrpc)"))) |
            (.["matched-at"] // .host // empty)
        ' "$json_file" 2>/dev/null | while IFS= read -r line; do
            _wp_brute_base_url "$line" | anew -q ".tmp/wp_brute_targets.txt"
        done
    done

    sort -u ".tmp/wp_brute_targets.txt" -o ".tmp/wp_brute_targets.txt" 2>/dev/null || true
}

# Map nuclei WordPress user-enum extracted usernames per base URL (built once per wp_brute_pro run).
_wp_brute_collect_nuclei_users() {
    : >".tmp/wp_brute_nuclei_users.tsv"

    local json_file
    if [[ ! -d nuclei_output ]]; then
        return 0
    fi

    for json_file in nuclei_output/*_json.txt nuclei_output/dast_json.txt; do
        [[ -s "$json_file" ]] || continue
        jq -r '
            select((."template-id" // "" | test("(?i)(wp-user|wordpress.*user)"))) |
            (.["matched-at"] // .host // empty) as $m |
            (.["extracted-results"] // [])[]? |
            select(. != null and (. | tostring | length) > 0) |
            [$m, (. | tostring)] | @tsv
        ' "$json_file" 2>/dev/null | while IFS=$'\t' read -r matched user; do
            [[ -z "$matched" || -z "$user" ]] && continue
            base=$(_wp_brute_base_url "$matched") || continue
            printf '%s\t%s\n' "$base" "$user"
        done >>".tmp/wp_brute_nuclei_users.tsv"
    done

    # Some nuclei templates (for example wordpress-rdf-user-enum) may only be
    # present in the text output. Convert display names into common login forms.
    if command -v python3 >/dev/null 2>&1; then
        python3 - <<'PY' >>".tmp/wp_brute_nuclei_users.tsv" 2>/dev/null
import ast
import glob
import re
import unicodedata
from urllib.parse import urlsplit


def base_url(raw):
    raw = (raw or "").strip()
    if not raw:
        return ""
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parts = urlsplit(raw)
    if not parts.scheme or not parts.netloc:
        return ""
    host = parts.netloc
    if parts.scheme == "https" and host.endswith(":443"):
        host = host[:-4]
    if parts.scheme == "http" and host.endswith(":80"):
        host = host[:-3]
    return f"{parts.scheme}://{host}"


def ascii_word(value):
    value = unicodedata.normalize("NFKD", value)
    value = value.encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^A-Za-z0-9._-]+", "", value)


def candidates(name):
    cleaned = re.sub(r"\s+", " ", (name or "").strip())
    if not cleaned:
        return []
    parts = [ascii_word(p).lower() for p in cleaned.replace("-", " ").split()]
    parts = [p for p in parts if p]
    joined = ascii_word(cleaned).lower()
    dashed = ascii_word(cleaned.replace(" ", "-")).lower()
    dotted = ".".join(parts)
    underscored = "_".join(parts)
    out = [joined, dashed, dotted, underscored, *parts]
    seen = set()
    return [u for u in out if u and not (u in seen or seen.add(u))]


line_re = re.compile(r"^\[(?P<tid>[^\]]+)\]\s+\[[^\]]+\]\s+\[[^\]]+\]\s+(?P<url>\S+)\s+(?P<values>\[.*\])\s*$")
for path in glob.glob("nuclei_output/*.txt") + glob.glob("nuclei_output/dast.txt"):
    if path.endswith("_json.txt"):
        continue
    try:
        fh = open(path, "r", encoding="utf-8", errors="ignore")
    except OSError:
        continue
    with fh:
        for line in fh:
            m = line_re.match(line.strip())
            if not m or not re.search(r"(wp-user|wordpress.*user)", m.group("tid"), re.I):
                continue
            base = base_url(m.group("url"))
            if not base:
                continue
            try:
                values = ast.literal_eval(m.group("values"))
            except Exception:
                values = []
            for value in values:
                for user in candidates(str(value)):
                    print(f"{base}\t{user}")
PY
    fi

    sort -u ".tmp/wp_brute_nuclei_users.tsv" -o ".tmp/wp_brute_nuclei_users.tsv" 2>/dev/null || true
}

_wp_brute_nuclei_users_csv() {
    local target_url="$1"
    local base_url

    base_url=$(_wp_brute_base_url "$target_url")
    [[ -n "$base_url" && -s ".tmp/wp_brute_nuclei_users.tsv" ]] || return 1

    awk -F'\t' -v base="$base_url" '
    function norm(u) {
        sub(/\r$/, "", u)
        sub(/\/$/, "", u)
        sub(/:443$/, "", u)
        sub(/:80$/, "", u)
        return tolower(u)
    }
    norm($1) == norm(base) {
        user = $2
        gsub(/[^a-zA-Z0-9._-]/, "", user)
        if (user != "") print user
    }' ".tmp/wp_brute_nuclei_users.tsv" | sort -u | paste -sd, -
}

# Log which nuclei template(s) put this URL on the wp_brute target list.
_wp_brute_log_nuclei_provenance() {
    local target_url="$1"
    local base_url json_file tid

    base_url=$(_wp_brute_base_url "$target_url")
    [[ -n "$base_url" && -d nuclei_output ]] || return 0

    for json_file in nuclei_output/*_json.txt nuclei_output/dast_json.txt; do
        [[ -s "$json_file" ]] || continue
        while IFS= read -r tid; do
            [[ -n "$tid" ]] || continue
            log_note "wp_brute_pro: nuclei template ${tid} matched ${target_url}" "${FUNCNAME[0]}" "${LINENO}"
        done < <(jq -r --arg base "$base_url" '
            def norm: gsub("\\r$"; "") | sub("/$"; "") | sub(":443$"; "") | sub(":80$"; "") | ascii_downcase;
            select((."template-id" // "" | test("(?i)(wp-user|wp-login|xmlrpc)"))) |
            ((.["matched-at"] // .host // "") | norm) as $m |
            ($base | norm) as $b |
            select($m == $b) | ."template-id"
        ' "$json_file" 2>/dev/null)
    done
}

_wp_brute_scan_is_wordpress() {
    local scan_json="$1"
    [[ -s "$scan_json" ]] || return 1

    local xmlrpc login wpv
    xmlrpc=$(jq -r '.xmlrpc_active // false' "$scan_json" 2>/dev/null)
    login=$(jq -r '.login_url // empty' "$scan_json" 2>/dev/null)
    wpv=$(jq -r '.wp_version // empty' "$scan_json" 2>/dev/null)

    [[ "$xmlrpc" == "true" ]] && return 0
    [[ -n "$login" && "$login" != "null" ]] && return 0
    [[ -n "$wpv" && "$wpv" != "null" ]] && return 0
    return 1
}

_wp_brute_safe_dirname() {
    echo "$1" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:|_|g' -e 's/[^a-zA-Z0-9._-]/_/g'
}

# Parse osint/passwords.txt (LeakSearch table: user@domain password) -> password list only.
# Usage: _wp_brute_parse_osint_leaks <passwords_out>
_wp_brute_parse_osint_leaks() {
    local passwords_out="$1"
    local osint_file="osint/passwords.txt"

    [[ ${WP_BRUTE_USE_OSINT_PASSWORDS:-true} == true ]] || return 1
    [[ -s "$osint_file" ]] || return 1

    awk -v domain="$domain" '
    function domain_match(email,   d) {
        d = tolower(domain)
        return (tolower(email) ~ ("@" d "$"))
    }
    /^[[:space:]]*$/ { next }
    /^[-=]+[[:space:]]*[-=]+/ { next }
    /^Username@Domain/ { next }
    /^Password/ { next }
    {
        email = $1
        pwd = $2
        if (email !~ /@/ || pwd == "" || pwd ~ /^-+$/ ) next
        if (domain != "" && !domain_match(email)) next
        print pwd
    }' "$osint_file" >"${passwords_out}.raw" 2>/dev/null || return 1

    [[ ! -s "${passwords_out}.raw" ]] && return 1

    awk 'NF { print $1 }' "${passwords_out}.raw" | grep -aE '.+' | anew -q "$passwords_out"
    rm -f "${passwords_out}.raw"
    [[ -s "$passwords_out" ]]
}

# Merge short wordlist + optional osint leak passwords for wp-brute-pro spray.
# Usage: _wp_brute_build_attack_wordlist <dest_file>
_wp_brute_build_attack_wordlist() {
    local dest="$1"
    local base_list="${WP_BRUTE_WORDLIST:-${SCRIPTPATH}/data/wordlists/wp_brute_short.txt}"

    : >"$dest"
    [[ -s "$base_list" ]] && cat "$base_list" | sed 's/\r$//' | anew -q "$dest"

    if _wp_brute_parse_osint_leaks ".tmp/wp_brute_osint_passwords.txt"; then
        cat ".tmp/wp_brute_osint_passwords.txt" | anew -q "$dest"
        _print_msg INFO "Merged $(wc -l <".tmp/wp_brute_osint_passwords.txt" | tr -d ' ') password(s) from osint/passwords.txt"
    fi

    sort -u "$dest" -o "$dest" 2>/dev/null || true
    [[ -s "$dest" ]]
}

# High-hit username suffixes only (not 1..123456 — too large for priority spray).
_wp_brute_add_username_passwords() {
    local dest="$1"
    local users_csv="$2"
    local user lower cap upper variant pwd suf
    local -a suffixes=(
        1 12 123 '123!' '123@' 1234 '1234$' 12345 123456 '123#'
        '1!' '12!' 2024 2025 2026
    )

    [[ -n "$users_csv" && -n "$dest" ]] || return 0

    local -a user_arr=() variants=() seen_variants=()
    IFS=',' read -ra user_arr <<<"$users_csv"
    for user in "${user_arr[@]}"; do
        user="${user#"${user%%[![:space:]]*}"}"
        user="${user%"${user##*[![:space:]]}"}"
        [[ -z "$user" ]] && continue
        (( ${#user} >= 3 && ${#user} <= 64 )) || continue

        variants=("$user")
        lower=$(printf '%s' "$user" | tr '[:upper:]' '[:lower:]')
        [[ "$lower" != "$user" ]] && variants+=("$lower")
        cap="${lower^}"
        [[ "$cap" != "$user" && "$cap" != "$lower" ]] && variants+=("$cap")
        upper=$(printf '%s' "$user" | tr '[:lower:]' '[:upper:]')
        [[ "$upper" != "$user" && "$upper" != "$lower" && "$upper" != "$cap" ]] && variants+=("$upper")

        seen_variants=()
        for variant in "${variants[@]}"; do
            [[ -z "$variant" ]] && continue
            [[ " ${seen_variants[*]} " == *" $variant "* ]] && continue
            seen_variants+=("$variant")
            printf '%s\n' "$variant" >>"$dest"
            for suf in "${suffixes[@]}"; do
                pwd="${variant}${suf}"
                (( ${#pwd} <= 64 )) && printf '%s\n' "$pwd" >>"$dest"
            done
        done
    done
}

# Priority list per target: username-as-password variants first, then short list + osint leaks.
# Usage: _wp_brute_build_priority_wordlist <dest> <base_wordlist> <users_csv> [user_pw_tmp]
_wp_brute_build_priority_wordlist() {
    local dest="$1"
    local base_wordlist="$2"
    local users_csv="$3"
    local tmp_users="${4:-.tmp/wp_brute_user_passwords.txt}"

    [[ -s "$base_wordlist" ]] || return 1

    : >"$tmp_users"
    _wp_brute_add_username_passwords "$tmp_users" "$users_csv"

    : >"$dest"
    [[ -s "$tmp_users" ]] && cat "$tmp_users" >>"$dest"
    cat "$base_wordlist" >>"$dest"
    awk 'NF && !seen[$0]++' "$dest" >"${dest}.tmp" 2>/dev/null && mv "${dest}.tmp" "$dest"
    [[ -s "$dest" ]]
}

# Recon only (phase 1) for one target URL.
_wp_brute_recon_one_target() {
    local target_url="$1"
    local host_key out_dir

    [[ -n "$target_url" ]] || return 0

    host_key=$(_wp_brute_safe_dirname "$target_url")
    out_dir="${dir}/vulns/wp_brute/${host_key}"
    mkdir -p "$out_dir"

    _wp_brute_run_recon "$target_url" "$out_dir" || true
}

# Parallel recon pass (used when nuclei found more WP targets than WP_BRUTE_MAX_TARGETS).
_wp_brute_recon_all_parallel() {
    local max_jobs="${WP_BRUTE_PARALLEL:-3}"
    local target_url running

    [[ "$max_jobs" =~ ^[0-9]+$ ]] || max_jobs=3
    ((max_jobs < 1)) && max_jobs=1

    _print_msg INFO "wp_brute_pro: parallel recon on $(wc -l <".tmp/wp_brute_targets_all.txt" | tr -d ' ') target(s) (xmlrpc triage)"

    while IFS= read -r target_url; do
        [[ -z "$target_url" ]] && continue
        while true; do
            running=$(jobs -rp 2>/dev/null | wc -l | tr -d ' ')
            [[ -z "$running" ]] && running=0
            ((running < max_jobs)) && break
            sleep 2
        done
        _wp_brute_recon_one_target "$target_url" &
    done <".tmp/wp_brute_targets_all.txt"

    wait 2>/dev/null || true
}

# Keep only targets whose recon scan.json reports xmlrpc_active.
_wp_brute_collect_xmlrpc_active_targets() {
    local target_url host_key scan_json

    : >".tmp/wp_brute_targets_xmlrpc.txt"

    while IFS= read -r target_url; do
        [[ -z "$target_url" ]] && continue
        host_key=$(_wp_brute_safe_dirname "$target_url")
        scan_json="vulns/wp_brute/${host_key}/scan.json"
        [[ -s "$scan_json" ]] || continue
        [[ $(jq -r '.xmlrpc_active // false' "$scan_json" 2>/dev/null) == "true" ]] \
            || continue
        printf '%s\n' "$target_url" | anew -q ".tmp/wp_brute_targets_xmlrpc.txt" || true
    done <".tmp/wp_brute_targets_all.txt"

    sort -u ".tmp/wp_brute_targets_xmlrpc.txt" -o ".tmp/wp_brute_targets_xmlrpc.txt" 2>/dev/null || true
}

# Recon + spray for one nuclei WordPress target (safe to run in parallel per URL).
_wp_brute_process_one_target() {
    local target_url="$1"
    local attack_wordlist="$2"
    local company_name="$3"
    local summary_file="$4"

    local users_csv host_key out_dir scan_json_rel priority_wordlist user_pw_tmp target_log
    local wordlist_count user_pw_count nuclei_users_csv wp_version xmlrpc_status waf_name

    [[ -n "$target_url" && -s "$attack_wordlist" ]] || return 0

    host_key=$(_wp_brute_safe_dirname "$target_url")
    out_dir="${dir}/vulns/wp_brute/${host_key}"
    scan_json_rel="vulns/wp_brute/${host_key}/scan.json"
    user_pw_tmp=".tmp/wp_brute_user_passwords_${host_key}.txt"
    target_log=".tmp/wp_brute_logs/${host_key}.log"
    mkdir -p "$out_dir" ".tmp/wp_brute_logs"

    {
        _wp_brute_log_nuclei_provenance "$target_url"

        if [[ ! -s "$scan_json_rel" ]]; then
            _print_msg INFO "Running: wp-brute-pro recon on ${target_url}"
            if ! _wp_brute_run_recon "$target_url" "$out_dir"; then
                log_note "wp_brute_pro: recon failed for ${target_url}" "wp_brute_pro" "${LINENO}"
                return 0
            fi
        fi

        if ! _wp_brute_scan_is_wordpress "$scan_json_rel"; then
            log_note "wp_brute_pro: skipping ${target_url} (recon: not WordPress — no xmlrpc/login/wp version)" "wp_brute_pro" "${LINENO}"
            return 0
        fi

        users_csv=$(jq -r '[.users[]?.slug // empty] | join(",")' "$scan_json_rel" 2>/dev/null)
        nuclei_users_csv=""
        if [[ -z "$users_csv" && ${WP_BRUTE_NUCLEI_USERS_FALLBACK:-true} == true ]]; then
            nuclei_users_csv=$(_wp_brute_nuclei_users_csv "$target_url" 2>/dev/null || true)
            if [[ -n "$nuclei_users_csv" ]]; then
                users_csv="$nuclei_users_csv"
                _print_msg INFO "wp_brute_pro: using nuclei wp-user-enum usernames for ${target_url}: ${users_csv}"
            fi
        fi
        if [[ -z "$users_csv" ]]; then
            log_note "wp_brute_pro: no users (Scanner + nuclei WordPress user-enum) for ${target_url}" "wp_brute_pro" "${LINENO}"
            return 0
        fi

        wp_version=$(jq -r '.wp_version // "unknown"' "$scan_json_rel" 2>/dev/null)
        xmlrpc_status=$([[ $(jq -r '.xmlrpc_active // false' "$scan_json_rel" 2>/dev/null) == "true" ]] && echo active || echo disabled)
        waf_name=$(jq -r '.waf_name // "none"' "$scan_json_rel" 2>/dev/null)
        printf '%s | users=%s | wp=%s | xmlrpc=%s | waf=%s\n' \
            "$target_url" "$users_csv" "$wp_version" "$xmlrpc_status" "$waf_name" \
            | anew -q "$summary_file"

        priority_wordlist=".tmp/wp_brute_priority_${host_key}.txt"
        if ! _wp_brute_build_priority_wordlist "$priority_wordlist" "$attack_wordlist" "$users_csv" "$user_pw_tmp"; then
            priority_wordlist="$attack_wordlist"
        fi
        wordlist_count=$(wc -l <"$priority_wordlist" | tr -d ' ')
        user_pw_count=$(wc -l <"$user_pw_tmp" 2>/dev/null | tr -d ' ')
        [[ -z "$user_pw_count" ]] && user_pw_count=0
        _print_msg INFO "Running: wp-brute hybrid spray on ${target_url} (${wordlist_count} priority passwords incl. ${user_pw_count} username-as-pass variants, + smart generation, users: ${users_csv})"
        _wp_brute_run_hybrid_spray "$target_url" "$out_dir" "$priority_wordlist" "$company_name" "$users_csv" || true

        if [[ -s "${out_dir}/found.txt" ]]; then
            cat "${out_dir}/found.txt" | anew -q "vulns/wp_brute/found.txt"
        fi
    } >>"$target_log" 2>&1

    cat "$target_log" >>"$LOGFILE" 2>/dev/null || true
}

# Run wp_brute target workers with a concurrency cap (default 3).
_wp_brute_run_targets_parallel() {
    local attack_wordlist="$1"
    local company_name="$2"
    local summary_file="$3"
    local max_jobs="${WP_BRUTE_PARALLEL:-3}"
    local target_url running

    [[ "$max_jobs" =~ ^[0-9]+$ ]] || max_jobs=3
    ((max_jobs < 1)) && max_jobs=1

    _print_msg INFO "wp_brute_pro: spraying up to ${max_jobs} WordPress target(s) in parallel"

    while IFS= read -r target_url; do
        [[ -z "$target_url" ]] && continue
        while true; do
            running=$(jobs -rp 2>/dev/null | wc -l | tr -d ' ')
            [[ -z "$running" ]] && running=0
            ((running < max_jobs)) && break
            sleep 2
        done
        _wp_brute_process_one_target "$target_url" "$attack_wordlist" "$company_name" "$summary_file" &
    done <".tmp/wp_brute_targets.txt"

    wait 2>/dev/null || true
}

# Spray: merged short+osint passwords first, then wp-brute-pro smart wordlist generation.
_wp_brute_run_hybrid_spray() {
    local target_url="$1"
    local out_dir="$2"
    local attack_wordlist="$3"
    local company_name="$4"
    local users_csv="${5:-}"
    local scan_json_rel="vulns/wp_brute/$(_wp_brute_safe_dirname "$target_url")/scan.json"
    local py_bin="${tools}/wp-brute-pro/venv/bin/python3"
    local tool_root="${tools}/wp-brute-pro"
    local spray_script="${SCRIPTPATH}/lib/wp_brute_hybrid_spray.py"

    [[ -x "$py_bin" && -f "$spray_script" && -s "$attack_wordlist" && -s "$scan_json_rel" ]] || return 1

    local -a spray_cmd=(
        "$py_bin" "$spray_script"
        -u "$target_url"
        -U "$users_csv"
        --priority-wordlist "$attack_wordlist"
        --scan-json "$scan_json_rel"
        --method "${WP_BRUTE_METHOD:-auto}"
        --batch-size "${WP_BRUTE_BATCH_SIZE:-50}"
        --delay "${WP_BRUTE_DELAY:-3}"
        --max-passwords "${WP_BRUTE_MAX_PASSWORDS:-0}"
        --output "$out_dir"
        --tool-root "$tool_root"
        --export-json "${out_dir}/reconftw_export.json"
        --no-scan
        --lang "${WP_BRUTE_LANG:-en}"
        -v
    )
    [[ -n "$company_name" ]] && spray_cmd+=(--company "$company_name")
    [[ ${WP_BRUTE_CRAWL:-true} == true ]] && spray_cmd+=(--crawl)
    [[ -n "${WP_BRUTE_PROXY_LIST:-}" && -s "${WP_BRUTE_PROXY_LIST}" ]] && spray_cmd+=(--proxy-list "${WP_BRUTE_PROXY_LIST}")

    WP_BRUTE_TOOL_ROOT="$tool_root" run_command "${spray_cmd[@]}"
}

# Run wp-brute-pro scanner only (phase 1) and write JSON.
_wp_brute_run_recon() {
    local target_url="$1"
    local out_dir="$2"
    local py_bin="${tools}/wp-brute-pro/venv/bin/python3"
    local tool_root="${tools}/wp-brute-pro"

    [[ -x "$py_bin" && -f "${tool_root}/core/scanner.py" ]] || return 1
    mkdir -p "$out_dir"

    WP_BRUTE_TARGET_URL="$target_url" WP_BRUTE_TOOL_ROOT="$tool_root" run_command \
        "$py_bin" - <<'PY' >"${out_dir}/scan.json" 2>>"$LOGFILE"
import json, os, sys
root = os.environ.get("WP_BRUTE_TOOL_ROOT", ".")
sys.path.insert(0, root)
from core.scanner import Scanner
url = os.environ.get("WP_BRUTE_TARGET_URL", "").rstrip("/")
if not url:
    sys.exit(2)
info = Scanner(url).scan()
print(json.dumps(info, indent=2, ensure_ascii=False))
PY
}

function wp_brute_pro() {

    if ! ensure_dirs .tmp vulns/wp_brute nuclei_output; then return 1; fi

    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ ${WP_BRUTE:-true} == true ]] \
        && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        local py_bin="${tools}/wp-brute-pro/venv/bin/python3"
        local tool_root="${tools}/wp-brute-pro"
        if [[ ! -x "$py_bin" ]] || [[ ! -f "${tool_root}/wp_brute.py" ]]; then
            _print_msg WARN "${FUNCNAME[0]}: wp-brute-pro not installed (${tool_root})"
            skip_notification "noinput"
            return 0
        fi

        _wp_brute_collect_targets
        if [[ ! -s ".tmp/wp_brute_targets.txt" ]]; then
            skip_notification "noinput"
            return 0
        fi

        cp ".tmp/wp_brute_targets.txt" ".tmp/wp_brute_targets_all.txt" 2>/dev/null || true

        local target_count xmlrpc_count
        target_count=$(wc -l <".tmp/wp_brute_targets_all.txt" | tr -d ' ')
        if [[ $DEEP != true ]] && [[ "$target_count" -gt "${WP_BRUTE_MAX_TARGETS:-5}" ]]; then
            _wp_brute_recon_all_parallel
            _wp_brute_collect_xmlrpc_active_targets
            xmlrpc_count=$(wc -l <".tmp/wp_brute_targets_xmlrpc.txt" 2>/dev/null | tr -d ' ')
            [[ -z "$xmlrpc_count" ]] && xmlrpc_count=0
            if ((xmlrpc_count == 0)); then
                end_func "Skipping wp_brute_pro: ${target_count} nuclei WP targets, none with xmlrpc active (use --deep for all)." "${FUNCNAME[0]}"
                return 0
            fi
            cp ".tmp/wp_brute_targets_xmlrpc.txt" ".tmp/wp_brute_targets.txt"
            _print_msg INFO "wp_brute_pro: ${xmlrpc_count} xmlrpc-active target(s) selected (WP_BRUTE_MAX_TARGETS bypass, was ${target_count})"
        fi

        start_func "${FUNCNAME[0]}" "WordPress recon/brute (wp-brute-pro)"

        local target_url users_csv company_name host_key out_dir summary_file attack_wordlist scan_json_rel
        : >"vulns/wp_brute/summary.txt"
        summary_file="vulns/wp_brute/summary.txt"

        if ! _wp_brute_build_attack_wordlist ".tmp/wp_brute_attack_wordlist.txt"; then
            end_func "No spray wordlist (short list + osint/passwords.txt empty)." "${FUNCNAME[0]}" "SKIP_NOINPUT"
            return 0
        fi
        attack_wordlist=".tmp/wp_brute_attack_wordlist.txt"

        company_name="${domain%%.*}"
        _wp_brute_collect_nuclei_users

        _wp_brute_run_targets_parallel "$attack_wordlist" "$company_name" "$summary_file"

        end_func "Results are saved in vulns/wp_brute/ (summary.txt, scan.json, found.txt)" "${FUNCNAME[0]}"
    else
        if [[ ${WP_BRUTE:-true} == false ]]; then
            skip_notification "disabled"
        elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            return
        else
            skip_notification "processed"
        fi
    fi
}
