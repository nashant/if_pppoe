"""Builds the pkg repo registration files for the plugin's signed repo
(plugin/build/'s output, served from the lab host): the repo .conf and the
fingerprint UCL file. Format verified against freebsd/pkg's
libpkg/pkg_repo.c (pkg_repo_load_fingerprints: a base fingerprints dir with
`trusted/`(required)/`revoked/`(optional) subdirs, each file a UCL object
with `function` + `fingerprint` keys, `sha256` the only supported function
at the time that source was read).

Published repos are one per FreeBSD ABI (<base>/<ABI>/); a client registers
`repo_url(base)`, i.e. `<base>/${ABI}` with pkg's own ${ABI} variable left
literal (pkg.conf(5): "ABI: Expands to the ABI string (e.g.
FreeBSD:14:amd64)"), so the same registration keeps resolving across OPNsense
25.7 -> 26.1 (same ABI) and -> 26.7 (FreeBSD:15:amd64). The lab round trip
serves a flat repo and passes its own URL (IFPPPOE_REPO_URL) instead.
"""
from __future__ import annotations

import hashlib


ABI_VAR = "${ABI}"


def repo_url(base: str) -> str:
    """Client repo URL for a per-ABI published repo: `<base>/${ABI}`.

    `${ABI}` stays literal for pkg to expand on the box; no series suffix is
    ever added (the repo is shared by every series of an ABI).
    """
    base = base.rstrip("/")
    if not base:
        raise ValueError("repo base URL is empty")
    if base.endswith("/" + ABI_VAR):
        raise ValueError(f"base already ends in {ABI_VAR}: {base}")
    return f"{base}/{ABI_VAR}"


def repo_conf(name: str, url: str, fingerprints_dir: str, mirror_type: str | None = None) -> str:
    # No mirror_type by default: pkg's "http" mirror_type fetches the repo
    # URL as a MIRROR LIST (libpkg/fetch_libfetch.c gethttpmirrors), which is
    # wrong against the lab host's plain static directory -- there's only
    # ever one server, not a list to pick from. Omitting the key (or "none")
    # is pkg.conf(5)'s single-server default.
    mirror_line = f'  mirror_type: "{mirror_type}",\n' if mirror_type else ""
    return (
        f"{name}: {{\n"
        f'  url: "{url}",\n'
        f"{mirror_line}"
        f'  signature_type: "fingerprints",\n'
        f'  fingerprints: "{fingerprints_dir}",\n'
        f"  enabled: yes\n"
        f"}}\n"
    )


def fingerprint_ucl(pubkey_der_or_pem: bytes) -> str:
    digest = hashlib.sha256(pubkey_der_or_pem).hexdigest()
    return f'function: "sha256"\nfingerprint: "{digest}"\n'
