#!/usr/bin/env bats

setup() {
  local project_root
  project_root="$(cd "$(dirname "$BATS_TEST_FILENAME")/../.." && pwd)"
  export SCRIPTPATH="$project_root"
  export LOGFILE="/dev/null"
  export bred='' bblue='' bgreen='' byellow='' yellow='' reset=''

  export TEST_DIR="$BATS_TEST_TMPDIR/reconftw_portscan_feed"
  mkdir -p "$TEST_DIR"
  export dir="$TEST_DIR/target.example.com"
  export called_fn_dir="$dir/.called_fn"
  mkdir -p "$called_fn_dir" "$dir/hosts"
  cd "$dir"

  export MOCK_BIN="$TEST_DIR/mockbin"
  mkdir -p "$MOCK_BIN"
  cat > "$MOCK_BIN/anew" <<'SH'
#!/usr/bin/env bash
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  grep -qxF "$line" "$1" 2>/dev/null || echo "$line" >> "$1"
done
SH
  chmod +x "$MOCK_BIN/anew"
  export PATH="$MOCK_BIN:$PATH"

  source "$project_root/reconftw.sh" --source-only
  export domain="target.example.com"
}

teardown() {
  [[ -d "$TEST_DIR" ]] && rm -rf "$TEST_DIR"
}

@test "passive nmap text output produces ip:port URLs in hosts/webs.txt" {
  cat > hosts/portscan_passive.txt <<'EOF'
Nmap scan report for forum.idcgames.com (176.31.241.118)
Host is up.

PORT     STATE SERVICE  VERSION
80/tcp   open  http     Node.js
3000/tcp open  hbci?

Nmap scan report for web1-ovh.idcgames.com (148.113.152.139)
Host is up.

PORT    STATE SERVICE  VERSION
443/tcp open  https?
EOF

  : > hosts/webs.txt
  _feed_port_discovery_urls

  grep -q 'http://176.31.241.118' hosts/webs.txt
  grep -q 'http://176.31.241.118:3000' hosts/webs.txt
  grep -q 'https://148.113.152.139:443' hosts/webs.txt
  ! grep -q 'forum.idcgames.com' hosts/webs.txt
}

@test "gnmap with hostname extracts ip from parentheses" {
  cat > hosts/portscan_active.gnmap <<'EOF'
Host: forum.idcgames.com (176.31.241.118) Status: Up
Ports: 80/open/tcp//http///, 3000/open/tcp/////
EOF

  : > hosts/webs.txt
  _append_gnmap_open_ports_as_urls hosts/portscan_active.gnmap

  grep -q 'http://176.31.241.118' hosts/webs.txt
  grep -q 'http://176.31.241.118:3000' hosts/webs.txt
}

@test "sqli fuzz list builder keeps parameterized gf URLs" {
  mkdir -p gf .tmp
  cat > gf/sqli.txt <<'EOF'
https://target.example.com/item?id=1&sort=asc
https://target.example.com/search?q=test
EOF

  cat > "$MOCK_BIN/qsreplace" <<'SH'
#!/usr/bin/env bash
while IFS= read -r line; do
  echo "${line//=/=FUZZ}"
  echo "${line}?injected=FUZZ"
done
SH
  chmod +x "$MOCK_BIN/qsreplace"

  run _vulns_build_qsreplace_fuzz_list gf/sqli.txt .tmp/tmp_sqli.txt
  [ "$status" -eq 0 ]
  [ -s .tmp/tmp_sqli.txt ]
  grep -q 'FUZZ' .tmp/tmp_sqli.txt
}
