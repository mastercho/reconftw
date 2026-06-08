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
# qsreplace -a emits FUZZ per parameter; fall back to raw parameterized URLs if needed.
# Usage: _vulns_build_qsreplace_fuzz_list <source_gf_file> <dest_tmp_file>
_vulns_build_qsreplace_fuzz_list() {
    local src="$1"
    local dest="$2"

    : >"$dest"
    [[ ! -s "$src" ]] && return 1

    if command -v qsreplace >/dev/null 2>&1; then
        qsreplace -a "FUZZ" <"$src" 2>>"$LOGFILE" | grep -a 'FUZZ' | sed 's/\r$//' | anew -q "$dest"
    fi

    if [[ ! -s "$dest" ]]; then
        grep -aE '^https?://[^[:space:]]*\?[^[:space:]]*=' "$src" 2>/dev/null \
            | sed 's/\r$//' | anew -q "$dest"
    fi

    [[ -s "$dest" ]]
}

# Pull confirmed SQLi lines from merged ghauri output into vulns/ghauri.txt (only when hits exist).
_vulns_collect_ghauri_findings() {
    local log="vulns/ghauri_log.txt"
    local out="vulns/ghauri.txt"

    [[ -s "$log" ]] || return 1

    awk '
    function remember(line,    m) {
        if (match(line, /https?:\/\/[^[:space:]'"'"'"]+/)) {
            url = substr(line, RSTART, RLENGTH)
            sub(/['"'"'"].*$/, "", url)
        }
    }
    /^=== TARGET: / {
        url = $0
        sub(/^=== TARGET: /, "", url)
        next
    }
    /\[INFO\].*testing|testing connection to the target URL|target URL/ {
        remember($0)
        next
    }
    /^https?:\/\// {
        url = $0
        sub(/[[:space:]].*$/, "", url)
        next
    }
    /[Pp]arameter.+is vulnerable|identified the following injection|is vulnerable to SQL injection/ {
        line = $0
        sub(/\r$/, "", line)
        sub(/\. Do you want.*$/, ".", line)
        sub(/ is vulnerable\..*$/, " is vulnerable.", line)
        if (url != "") print url " | " line
        else print line
    }
    ' "$log" 2>/dev/null | anew -q "$out"

    [[ -s "$out" ]]
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
            interactsh-client &>.tmp/ssrf_callback.txt &
            INTERACTSH_PID=$!
            # Ensure interactsh is killed on function exit (prevents orphan processes)
            trap 'kill "$INTERACTSH_PID" 2>/dev/null; trap - RETURN' RETURN
            sleep 2

            # Extract FFUFHASH from interactsh_callback.txt
            COLLAB_SERVER_FIX="FFUFHASH.$(tail -n1 .tmp/ssrf_callback.txt | cut -c 16-)"
            COLLAB_SERVER_URL="http://$COLLAB_SERVER_FIX"
            INTERACT=true
        else
            COLLAB_SERVER_FIX="FFUFHASH.$(echo "$COLLAB_SERVER" | sed -r "s|https?://||")"
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
                        | grep "URL" | sed 's/| URL | //' | anew -q "vulns/ssrf_alt_protocols.txt"
                fi
            fi

            # Allow time for callbacks to be received.
            sleep 5

            # Process SSRF callback results if INTERACT is enabled.
            if [[ $INTERACT == true ]] && [[ -s ".tmp/ssrf_callback.txt" ]]; then
                tail -n +11 .tmp/ssrf_callback.txt | anew -q "vulns/ssrf_callback.txt"
                if ! NUMOFLINES=$(tail -n +12 .tmp/ssrf_callback.txt | sed '/^$/d' | wc -l); then
                    NUMOFLINES=0
                fi
                notification "SSRF: ${NUMOFLINES} callbacks received" info
            fi

            end_func "Results are saved in vulns/ssrf_* (including alternate protocols)" "${FUNCNAME[0]}"
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
                    | grep "URL" | sed 's/| URL | //' | anew -q "vulns/lfi.txt"

                end_func "Results are saved in vulns/lfi.txt" "${FUNCNAME[0]}"
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

function sqli() {

    # Create necessary directories
    if ! ensure_dirs .tmp gf vulns; then return 1; fi

    # Check if the function should run
    if { [[ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ]] || [[ $DIFF == true ]]; } && [[ $SQLI == true ]] \
        && [[ -s "gf/sqli.txt" ]] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then

        start_func "${FUNCNAME[0]}" "SQLi Checks"

        # Ensure gf/sqli.txt is not empty
        if [[ -s "gf/sqli.txt" ]]; then
            _print_msg INFO "Running: SQLi Payload Generation"

            # Process sqli.txt with qsreplace and filter lines containing 'FUZZ'
            if ! _vulns_build_qsreplace_fuzz_list "gf/sqli.txt" ".tmp/tmp_sqli.txt"; then
                end_func "SQLi: no injectable query parameters in gf/sqli.txt after FUZZ prep (need URLs with ?param=)." "${FUNCNAME[0]}" "SKIP_NOINPUT"
                return 0
            fi

            # Determine whether to proceed based on DEEP flag or number of URLs
            URL_COUNT=$(wc -l <".tmp/tmp_sqli.txt")
            if [[ $DEEP == true ]] || [[ $URL_COUNT -le $DEEP_LIMIT ]]; then

                    # Check if SQLMAP is enabled and run SQLMap
                    if [[ $SQLMAP == true ]]; then
                        _print_msg INFO "Running: SQLMap for SQLi Checks"
                        run_command python3 "${tools}/sqlmap/sqlmap.py" -m ".tmp/tmp_sqli.txt" -b -o --smart \
                            --batch --disable-coloring --random-agent --level=5 --risk=3 \
                            --output-dir="vulns/sqlmap" 2>>"$LOGFILE" >/dev/null
                    fi
                                # Check if GHAURI is enabled and run Ghauri
                if [[ $GHAURI == true ]]; then
                    _print_msg INFO "Running: Ghauri for SQLi Checks"
                    mkdir -p .tmp/ghauri_parts vulns
                    rm -rf .tmp/ghauri_parts/*
                    # Quote _target_: URLs with & (e.g. ?a=FUZZ&b=FUZZ) break the shell if unquoted.
                    run_command interlace -tL ".tmp/tmp_sqli.txt" -threads "$INTERLACE_THREADS" -c "printf '%s\n' '=== TARGET: _target_ ===' >> .tmp/ghauri_parts/_cleantarget_.txt; ghauri -u \"_target_\" --batch --dbs -H \"${HEADER}\" --force-ssl >> .tmp/ghauri_parts/_cleantarget_.txt 2>&1" 2>>"$LOGFILE" >/dev/null
                    # One log file per sqli run (not appended across scans) so TARGET lines stay with findings
                    : >vulns/ghauri_log.txt
                    cat .tmp/ghauri_parts/*.txt 2>/dev/null >>vulns/ghauri_log.txt || true
                    _vulns_collect_ghauri_findings || true
                    rm -rf .tmp/ghauri_parts
                fi

                end_func "Results are saved in vulns/sqlmap folder" "${FUNCNAME[0]}"
            else
                end_func "Skipping SQLi: Too many URLs to test, try with --deep flag." "${FUNCNAME[0]}" "SKIP"
            fi
        else
            end_func "No gf/sqli.txt file found, SQLi Checks skipped." "${FUNCNAME[0]}"
            return
        fi
    else
        if [[ $SQLI == false ]]; then
            skip_notification "disabled"
        elif [[ ! -s "gf/sqli.txt" ]]; then
            skip_notification "noinput"
        else
            skip_notification "processed"
        fi
    fi

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
        run_command commix --batch -m ".tmp/tmp_rce.txt" --output-dir "vulns/command_injection" 2>>"$LOGFILE" >/dev/null
    fi

                # Additional tools can be integrated here (e.g., Ghauri, sqlmap)

                end_func "Results are saved in vulns/command_injection folder" "${FUNCNAME[0]}"
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
            select((."template-id" // "" | test("(?i)(wp-user|wp-login|xmlrpc)"))) |
            (.["matched-at"] // .host // empty)
        ' "$json_file" 2>/dev/null | while IFS= read -r line; do
            _wp_brute_base_url "$line" | anew -q ".tmp/wp_brute_targets.txt"
        done
    done

    sort -u ".tmp/wp_brute_targets.txt" -o ".tmp/wp_brute_targets.txt" 2>/dev/null || true
}

# Map nuclei wp-user-enum extracted usernames per base URL (built once per wp_brute_pro run).
_wp_brute_collect_nuclei_users() {
    : >".tmp/wp_brute_nuclei_users.tsv"

    local json_file
    if [[ ! -d nuclei_output ]]; then
        return 0
    fi

    for json_file in nuclei_output/*_json.txt nuclei_output/dast_json.txt; do
        [[ -s "$json_file" ]] || continue
        jq -r '
            select((."template-id" // "" | test("(?i)wp-user"))) |
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
# Usage: _wp_brute_build_priority_wordlist <dest> <base_wordlist> <users_csv>
_wp_brute_build_priority_wordlist() {
    local dest="$1"
    local base_wordlist="$2"
    local users_csv="$3"
    local tmp_users=".tmp/wp_brute_user_passwords.txt"

    [[ -s "$base_wordlist" ]] || return 1

    : >"$tmp_users"
    _wp_brute_add_username_passwords "$tmp_users" "$users_csv"

    : >"$dest"
    [[ -s "$tmp_users" ]] && cat "$tmp_users" >>"$dest"
    cat "$base_wordlist" >>"$dest"
    awk 'NF && !seen[$0]++' "$dest" >"${dest}.tmp" 2>/dev/null && mv "${dest}.tmp" "$dest"
    [[ -s "$dest" ]]
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

        local target_count
        target_count=$(wc -l <".tmp/wp_brute_targets.txt" | tr -d ' ')
        if [[ $DEEP != true ]] && [[ "$target_count" -gt "${WP_BRUTE_MAX_TARGETS:-5}" ]]; then
            end_func "Skipping wp_brute_pro: ${target_count} WordPress nuclei targets (limit ${WP_BRUTE_MAX_TARGETS:-5}, use --deep)." "${FUNCNAME[0]}"
            return 0
        fi

        start_func "${FUNCNAME[0]}" "WordPress recon/brute (wp-brute-pro)"

        local target_url users_csv company_name host_key out_dir summary_file attack_wordlist priority_wordlist scan_json_rel
        : >"vulns/wp_brute/summary.txt"
        summary_file="vulns/wp_brute/summary.txt"

        if ! _wp_brute_build_attack_wordlist ".tmp/wp_brute_attack_wordlist.txt"; then
            end_func "No spray wordlist (short list + osint/passwords.txt empty)." "${FUNCNAME[0]}" "SKIP_NOINPUT"
            return 0
        fi
        attack_wordlist=".tmp/wp_brute_attack_wordlist.txt"

        company_name="${domain%%.*}"
        _wp_brute_collect_nuclei_users

        while IFS= read -r target_url; do
            [[ -z "$target_url" ]] && continue
            host_key=$(_wp_brute_safe_dirname "$target_url")
            out_dir="${dir}/vulns/wp_brute/${host_key}"
            scan_json_rel="vulns/wp_brute/${host_key}/scan.json"
            mkdir -p "$out_dir"

            _wp_brute_log_nuclei_provenance "$target_url"

            _print_msg INFO "Running: wp-brute-pro recon on ${target_url}"
            if ! _wp_brute_run_recon "$target_url" "$out_dir"; then
                log_note "wp_brute_pro: recon failed for ${target_url}" "${FUNCNAME[0]}" "${LINENO}"
                continue
            fi

            if ! _wp_brute_scan_is_wordpress "$scan_json_rel"; then
                log_note "wp_brute_pro: skipping ${target_url} (recon: not WordPress — no xmlrpc/login/wp version)" "${FUNCNAME[0]}" "${LINENO}"
                continue
            fi

            users_csv=$(jq -r '[.users[]?.slug // empty] | join(",")' "$scan_json_rel" 2>/dev/null)
            local nuclei_users_csv=""
            if [[ -z "$users_csv" && ${WP_BRUTE_NUCLEI_USERS_FALLBACK:-true} == true ]]; then
                nuclei_users_csv=$(_wp_brute_nuclei_users_csv "$target_url" 2>/dev/null || true)
                if [[ -n "$nuclei_users_csv" ]]; then
                    users_csv="$nuclei_users_csv"
                    _print_msg INFO "wp_brute_pro: using nuclei wp-user-enum usernames for ${target_url}: ${users_csv}"
                fi
            fi
            if [[ -z "$users_csv" ]]; then
                log_note "wp_brute_pro: no users (Scanner + nuclei wp-user-enum) for ${target_url}" "${FUNCNAME[0]}" "${LINENO}"
                continue
            fi
            local wp_version xmlrpc_status waf_name
            wp_version=$(jq -r '.wp_version // "unknown"' "$scan_json_rel" 2>/dev/null)
            xmlrpc_status=$([[ $(jq -r '.xmlrpc_active // false' "$scan_json_rel" 2>/dev/null) == "true" ]] && echo active || echo disabled)
            waf_name=$(jq -r '.waf_name // "none"' "$scan_json_rel" 2>/dev/null)
            printf '%s | users=%s | wp=%s | xmlrpc=%s | waf=%s\n' \
                "$target_url" "$users_csv" "$wp_version" "$xmlrpc_status" "$waf_name" \
                | anew -q "$summary_file"

            local wordlist_count user_pw_count
            priority_wordlist=".tmp/wp_brute_priority_${host_key}.txt"
            if ! _wp_brute_build_priority_wordlist "$priority_wordlist" "$attack_wordlist" "$users_csv"; then
                priority_wordlist="$attack_wordlist"
            fi
            wordlist_count=$(wc -l <"$priority_wordlist" | tr -d ' ')
            user_pw_count=$(wc -l <".tmp/wp_brute_user_passwords.txt" 2>/dev/null | tr -d ' ')
            [[ -z "$user_pw_count" ]] && user_pw_count=0
            _print_msg INFO "Running: wp-brute hybrid spray on ${target_url} (${wordlist_count} priority passwords incl. ${user_pw_count} username-as-pass variants, + smart generation, users: ${users_csv})"
            _wp_brute_run_hybrid_spray "$target_url" "$out_dir" "$priority_wordlist" "$company_name" "$users_csv" >>"$LOGFILE" 2>&1 || true

            if [[ -s "${out_dir}/found.txt" ]]; then
                cat "${out_dir}/found.txt" | anew -q "vulns/wp_brute/found.txt"
            fi
        done <".tmp/wp_brute_targets.txt"

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
