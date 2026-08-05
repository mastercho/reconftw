#!/usr/bin/env python3
"""
Manual WordPress password spray (reconftw wp-brute-pro wrapper).

Uses the same spray path as wp_brute_pro: lib/wp_brute_hybrid_spray.py
Default wordlist: data/wordlists/wp_brute_short.txt

Examples:
  ./lib/wp_brute_spray_manual.py -u https://www.example.com -U admin,editor
  ./lib/wp_brute_spray_manual.py -u https://www.example.com --short-only --dry-run
  ./lib/wp_brute_spray_manual.py -u https://www.example.com --scan-json ./scan.json --no-scan
  ./lib/wp_brute_spray_manual.py --recon-only -u https://www.example.com
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


def looks_like_reconftw_root(path: Path) -> bool:
    return (
        (path / "reconftw.sh").is_file()
        and (path / "lib" / "wp_brute_hybrid_spray.py").is_file()
        and (path / "data" / "wordlists" / "wp_brute_short.txt").is_file()
    )


def reconftw_root() -> Path:
    """Find reconftw even when this helper is copied into wp-brute-pro."""
    env_root = os.environ.get("RECONFTW_ROOT") or os.environ.get("RECONFTW")
    candidates = []
    if env_root:
        candidates.append(Path(env_root).expanduser())

    script_path = Path(__file__).resolve()
    candidates.extend(script_path.parents)
    candidates.extend([
        Path.cwd(),
        Path("/home/reconftw"),
        Path("/root/reconftw"),
        Path.home() / "reconftw",
    ])

    for candidate in candidates:
        try:
            candidate = candidate.resolve()
        except OSError:
            continue
        if looks_like_reconftw_root(candidate):
            return candidate

    # Last resort keeps the old behavior for local development.
    return script_path.parent.parent


def default_tool_root() -> Path:
    home = Path.home()
    for candidate in (
        os.environ.get("WP_BRUTE_TOOL_ROOT"),
        os.environ.get("TOOLS", str(home / "Tools")) + "/wp-brute-pro",
        str(home / "Tools" / "wp-brute-pro"),
    ):
        if candidate and Path(candidate).is_dir():
            return Path(candidate)
    return home / "Tools" / "wp-brute-pro"


def host_key(url: str) -> str:
    host = urlparse(url).netloc or url
    host = host.split("/")[0]
    return re.sub(r"[^a-zA-Z0-9._-]", "_", host.replace(":", "_"))


def target_host(url: str) -> str:
    host = urlparse(url).hostname or urlparse(f"https://{url}").hostname or url
    return host.split("/")[0].lower()


def infer_recon_domain(url: str, root: Path) -> str:
    cwd_parts = Path.cwd().parts
    if "Recon" in cwd_parts:
        idx = cwd_parts.index("Recon")
        if len(cwd_parts) > idx + 1:
            return cwd_parts[idx + 1]

    host = target_host(url)
    labels = [part for part in host.split(".") if part]
    if len(labels) <= 2:
        return host

    second_level_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au",
        "co.nz", "com.br", "com.tr", "com.cn",
    }
    suffix = ".".join(labels[-2:])
    if suffix in second_level_suffixes and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def default_output_dir(url: str) -> Path:
    root = reconftw_root()
    return root / "Recon" / infer_recon_domain(url, root) / "vulns" / "wp_brute" / host_key(url)


def count_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for line in handle if line.strip())


def load_users_from_scan(scan_path: Path) -> str:
    with scan_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    users = []
    for entry in data.get("users", []):
        if isinstance(entry, dict):
            slug = (entry.get("slug") or "").strip()
        else:
            slug = str(entry).strip()
        if slug:
            users.append(slug)
    return ",".join(users)


def run_recon_only(url: str, tool_root: Path, scan_json: Path) -> int:
    py = tool_root / "venv" / "bin" / "python3"
    if not py.is_file():
        print(f"error: wp-brute-pro python not found: {py}", file=sys.stderr)
        return 2

    scan_json.parent.mkdir(parents=True, exist_ok=True)
    code = f"""
import json, os, sys
root = {str(tool_root)!r}
sys.path.insert(0, root)
from core.scanner import Scanner
url = {url.rstrip('/')!r}
info = Scanner(url).scan()
print(json.dumps(info, indent=2, ensure_ascii=False))
"""
    proc = subprocess.run(
        [str(py), "-c", code],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stderr or proc.stdout, file=sys.stderr)
        return proc.returncode or 1

    scan_json.write_text(proc.stdout, encoding="utf-8")
    print(f"recon saved: {scan_json}")
    try:
        data = json.loads(proc.stdout)
        slugs = [u.get("slug") for u in data.get("users", []) if isinstance(u, dict)]
        print(f"users: {', '.join(slugs) or '(none)'}")
        print(
            f"xmlrpc_active={data.get('xmlrpc_active')} "
            f"wp_version={data.get('wp_version')} "
            f"login_url={data.get('login_url')}"
        )
    except json.JSONDecodeError:
        pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    root = reconftw_root()
    p = argparse.ArgumentParser(
        description="Manual wp-brute spray (reconftw short wordlist + wp-brute-pro)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("-u", "--url", help="Target WordPress base URL (https://host)")
    p.add_argument("-U", "--users", default="", help="Usernames (comma-separated)")
    p.add_argument(
        "-w",
        "--wordlist",
        type=Path,
        default=root / "data" / "wordlists" / "wp_brute_short.txt",
        help="Priority wordlist (default: wp_brute_short.txt)",
    )
    p.add_argument("-o", "--output", type=Path, help="Output directory")
    p.add_argument("--scan-json", type=Path, help="Recon JSON path (default: <output>/scan.json)")
    p.add_argument("--tool-root", type=Path, default=None, help="wp-brute-pro install dir")
    p.add_argument(
        "--method",
        default="auto",
        choices=["auto", "xmlrpc", "wplogin", "restapi"],
    )
    p.add_argument("--batch-size", type=int, default=50)
    p.add_argument("--delay", type=float, default=3.0)
    p.add_argument("--max-passwords", type=int, default=None, help="0 = unlimited")
    p.add_argument("--company", help="Company keyword for smart generation")
    p.add_argument("--proxy-list", type=Path, help="Proxy list file")
    p.add_argument("--lang", default="en")
    p.add_argument("--resume", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="Build wordlists only, no spray")
    p.add_argument("--no-scan", action="store_true", help="Require existing --scan-json")
    p.add_argument("--recon-only", action="store_true", help="Run scanner only, then exit")
    p.add_argument(
        "--short-only",
        action="store_true",
        help="Spray priority wordlist only (no crawl/smart generation)",
    )
    p.add_argument(
        "--full",
        action="store_true",
        help="Like reconftw wp_brute_pro: crawl + company + unlimited passwords",
    )
    p.add_argument("-v", "--verbose", action="store_true", default=True)
    p.add_argument("-q", "--quiet", action="store_true", help="Less output from spray TUI")
    return p


def main() -> int:
    args = build_parser().parse_args()
    if not args.url:
        print("error: -u / --url is required", file=sys.stderr)
        return 2

    url = args.url.rstrip("/")
    tool_root = Path(args.tool_root) if args.tool_root else default_tool_root()
    py = tool_root / "venv" / "bin" / "python3"
    spray_script = reconftw_root() / "lib" / "wp_brute_hybrid_spray.py"
    wordlist = Path(args.wordlist)

    if not py.is_file():
        print(f"error: {py} not found (install wp-brute-pro or set --tool-root)", file=sys.stderr)
        return 2
    if not spray_script.is_file():
        print(f"error: {spray_script} not found", file=sys.stderr)
        return 2
    if not wordlist.is_file():
        print(f"error: wordlist not found: {wordlist}", file=sys.stderr)
        return 2

    out_dir = Path(args.output) if args.output else default_output_dir(url)
    scan_json = Path(args.scan_json) if args.scan_json else out_dir / "scan.json"

    if args.recon_only:
        return run_recon_only(url, tool_root, scan_json)

    if args.no_scan and not scan_json.is_file():
        print(f"error: --no-scan set but missing {scan_json}", file=sys.stderr)
        return 2

    users = args.users.strip()
    if not users and scan_json.is_file():
        users = load_users_from_scan(scan_json)
    if not users and args.no_scan and not args.dry_run:
        print(
            "error: no users available with --no-scan (pass -U or use a scan.json with users)",
            file=sys.stderr,
        )
        return 2

    if not args.resume and (out_dir / "state.json").is_file():
        args.resume = True
        print(f"info: existing state found, resuming: {out_dir / 'state.json'}")

    crawl = False
    company = args.company
    max_passwords = args.max_passwords

    if args.full:
        crawl = True
        if not company:
            host = urlparse(url).hostname or ""
            company = host.split(".")[0] if host else None
        if max_passwords is None:
            max_passwords = 0
    elif args.short_only:
        crawl = False
        company = None
        if max_passwords is None:
            max_passwords = count_lines(wordlist) or 40
    else:
        # Balanced default: short list first, small smart expansion like reconftw without --full
        crawl = False
        if max_passwords is None:
            max_passwords = 0

    cmd = [
        str(py),
        str(spray_script),
        "-u",
        url,
        "-U",
        users,
        "--priority-wordlist",
        str(wordlist.resolve()),
        "--scan-json",
        str(scan_json.resolve()),
        "--method",
        args.method,
        "--batch-size",
        str(args.batch_size),
        "--delay",
        str(args.delay),
        "--max-passwords",
        str(max_passwords if max_passwords is not None else 0),
        "--output",
        str(out_dir.resolve()),
        "--tool-root",
        str(tool_root.resolve()),
        "--export-json",
        str((out_dir / "reconftw_export.json").resolve()),
        "--lang",
        args.lang,
    ]

    if args.no_scan:
        cmd.append("--no-scan")
    if company:
        cmd.extend(["--company", company])
    if crawl:
        cmd.append("--crawl")
    if args.proxy_list and args.proxy_list.is_file():
        cmd.extend(["--proxy-list", str(args.proxy_list.resolve())])
    if args.resume:
        cmd.append("--resume")
    if args.dry_run:
        cmd.append("--dry-run")
    if args.verbose and not args.quiet:
        cmd.append("-v")

    out_dir.mkdir(parents=True, exist_ok=True)

    print("command:")
    print(" \\\n  ".join(cmd))
    print()

    proc = subprocess.run(cmd)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
