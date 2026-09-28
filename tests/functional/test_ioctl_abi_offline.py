"""p3-ctl-abi: offline (no VM, no root) invariant checks on the SPPP*/PPPOE*
ioctl ABI and the pppoectl(8) hardening fixes.

Pure Python, source-level (regex/text) checks against this checkout's own
files -- conftest.py exempts this file from the off-lab collection gate
(pytest_ignore_collect), same as test_client_seam.py, so it runs on any
host including a bare `pytest tests/functional` with no lab.

Why source-level and not a real compile: this checkout has no FreeBSD
toolchain/headers (see docs/PORTING-sppp.md and this branch's notes), so a
real build-time proof only exists as tests/ioctl-abi/check_ioctl_group.c,
compiled on the FreeBSD lab/build VM by the verifier, and as the live
in-kernel sweep in test_sppp_ioctl_live.py. These tests instead pin the
*source* invariants that make that later compile meaningful: no ioctl
macro left on group 'i', no test/tool privately re-encoding the ABI, and
the specific pppoectl.c bugs from the spec are actually fixed.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# These read the driver/tool sources, so they need a full checkout (CI, a
# developer's clone). The lab host only receives tests/functional/ itself,
# where there is nothing to inspect -- skip there rather than fail.
pytestmark = [
    pytest.mark.seam_unit,
    pytest.mark.skipif(
        not (REPO_ROOT / "sys" / "net" / "if_sppp.h").is_file(),
        reason="needs a full source checkout (sys/, sbin/, tools/ beside tests/)",
    ),
]
IF_SPPP_H = REPO_ROOT / "sys" / "net" / "if_sppp.h"
IF_PPPOE_H = REPO_ROOT / "sys" / "net" / "if_pppoe.h"
PPPOECTL_C = REPO_ROOT / "sbin" / "pppoectl" / "pppoectl.c"

TOOL_SOURCES = {
    "spppauth": REPO_ROOT / "tools" / "spppauth" / "spppauth.c",
    "spppioctl": REPO_ROOT / "tools" / "spppioctl" / "spppioctl.c",
    "spppkeepalive": REPO_ROOT / "tools" / "spppkeepalive" / "spppkeepalive.c",
}
TOOL_MAKEFILES = {
    name: p.parent / "Makefile" for name, p in TOOL_SOURCES.items()
}

# The one TRUE collision (full _IOWR/_IOW value: group + number + direction
# + payload size), fetched and reconciled against real FreeBSD 14.3 sources
# this session (docs/PORTING-sppp.md "ioctl number collision"). The other
# same-number pairs at 120-124/135/137-139 differ in direction or struct
# size, so they were never actually colliding values and did not need
# renumbering -- see the doc table for the full reasoning.
OLD_NUMBER = 136
NEW_NUMBER = 200
COLLIDES_WITH = "SIOCGIFGROUP"  # tests/results/pppoectl-t1.txt:25 "IPCP state: unknown"

# Every other SPPP*/PPPOE* ioctl number must be completely unchanged by
# this fix (only SPPPGETIPCPSTATUS's number moves; the group stays 'i').
UNCHANGED_NUMBERS = {
    110, 111, 112,
    120, 121, 122, 123, 124, 125, 126, 127, 128, 129,
    130, 131, 132, 133, 134, 135, 137, 138, 139,
    144, 145, 146,
}

_IOCTL_DEFINE_RE = re.compile(
    r"#define\s+(?P<name>_{0,2}(?:SPPP|PPPOE)\w*)\s+"
    r"_IO[WR]{0,2}\(\s*'(?P<group>.)'\s*,\s*(?P<num>\d+)\s*,"
)


def _parse_ioctl_defines(text: str) -> list[tuple[str, str, int]]:
    return [
        (m.group("name"), m.group("group"), int(m.group("num")))
        for m in _IOCTL_DEFINE_RE.finditer(text)
    ]


def _header_text() -> str:
    return IF_SPPP_H.read_text() + "\n" + IF_PPPOE_H.read_text()


def test_headers_exist():
    for p in (IF_SPPP_H, IF_PPPOE_H, PPPOECTL_C):
        assert p.is_file(), f"missing {p}"


def test_all_sppp_and_pppoe_ioctls_stay_on_group_i():
    """Group 'i' is required, not merely conventional: soo_ioctl()
    (sys/kern/sys_socket.c) routes only IOCGROUP(cmd)=='i' to ifioctl();
    every other group reaches pppoectl(8)'s AF_INET socket's pr_control
    (in_control()) instead, which fails with EADDRNOTAVAIL before this
    driver is ever called (docs/PORTING-sppp.md "ioctl number collision").
    """
    defines = _parse_ioctl_defines(_header_text())
    assert defines, "no SPPP*/PPPOE* ioctl #define found -- regex or path is stale"
    groups = {group for _, group, _ in defines}
    assert groups == {"i"}, (
        f"expected every SPPP*/PPPOE* ioctl to stay on group 'i', got "
        f"groups {groups} -- moving off group 'i' breaks routing to "
        "ifioctl() entirely (see docs/PORTING-sppp.md)"
    )


def test_only_the_true_collision_was_renumbered():
    """The root cause (spec item 1): SPPPGETIPCPSTATUS collided with
    SIOCGIFGROUP -- same full _IOWR value on group 'i' (both 40 bytes on
    amd64) -- so ifhwioctl() answered it before pppoe_ioctl() ever ran
    (tests/results/pppoectl-t1.txt:25 'IPCP state: unknown'). The other
    same-number pairs (120-124/135/137-139) differ in direction or struct
    size and were never true collisions, so only this one number moves.
    """
    defines = {name: num for name, _, num in _parse_ioctl_defines(_header_text())}
    present_numbers = set(defines.values())
    assert OLD_NUMBER not in present_numbers, (
        f"ioctl number {OLD_NUMBER} ({COLLIDES_WITH} collision) is still "
        f"in use -- SPPPGETIPCPSTATUS must be renumbered to {NEW_NUMBER}"
    )
    assert defines.get("SPPPGETIPCPSTATUS") == NEW_NUMBER, (
        f"SPPPGETIPCPSTATUS must be renumbered to {NEW_NUMBER}, got "
        f"{defines.get('SPPPGETIPCPSTATUS')}"
    )
    missing = UNCHANGED_NUMBERS - present_numbers
    assert not missing, (
        f"ioctl number(s) {missing} disappeared -- only SPPPGETIPCPSTATUS's "
        "number should change; the group letter and every other number "
        "must stay exactly as before"
    )


def test_tools_no_longer_privately_redefine_the_sppp_ioctl_abi():
    """Spec item 2: spppauth/spppioctl/spppkeepalive must include the
    vendored header instead of re-declaring the struct/ioctl numbers, so
    a future renumbering can't silently desync them from the driver."""
    for name, path in TOOL_SOURCES.items():
        text = path.read_text()
        assert "#include <net/if_sppp.h>" in text, (
            f"{name}: must include <net/if_sppp.h> (vendored ABI header)"
        )
        assert not re.search(r"_IOWR?\s*\(\s*'i'", text), (
            f"{name}: still privately defines an ioctl number on group 'i'"
        )
        assert "struct spppauthcfg {" not in text, (
            f"{name}: still privately redeclares struct spppauthcfg"
        )


def test_tool_makefiles_add_the_vendored_sys_include_path():
    for name, path in TOOL_MAKEFILES.items():
        text = path.read_text()
        assert "-I${.CURDIR}/../../sys" in text, (
            f"{name}/Makefile: must add the vendored sys/ include path "
            "(same pattern as sbin/pppoectl/Makefile)"
        )


# --- pppoectl.c hardening (spec item 3) -----------------------------------

def _pppoectl_text() -> str:
    return PPPOECTL_C.read_text()


def test_pppoectl_dash_f_missing_file_is_an_error():
    text = _pppoectl_text()
    m = re.search(r"fopen\(configname,[^\n]*\)", text)
    assert m, "could not find the -f config-file fopen(configname) in pppoectl.c"
    window = text[m.start() : m.start() + 200]
    assert re.search(r"==\s*NULL\s*\)\s*\n?\s*err(x)?\s*\(", window), (
        "a failed fopen(configname) on -f must err()/errx(), not fall "
        f"through silently:\n{window}"
    )


def test_pppoectl_has_raw_secret_stdin_flag():
    text = _pppoectl_text()
    getopt_m = re.search(r'getopt\(argc,\s*argv,\s*"([^"]+)"\)', text)
    assert getopt_m, "could not find the getopt() option string"
    assert "S" in getopt_m.group(1), (
        "no -S (raw myauthsecret-from-stdin, one line, unmangled) option"
    )


def test_pppoectl_print_error_receives_errno_not_the_ioctl_return():
    text = _pppoectl_text()
    macro_m = re.search(
        r"#define\s+PPPOECTL_IOCTL.*?while\s*\(0\)", text, re.S
    )
    assert macro_m, "could not find the PPPOECTL_IOCTL macro"
    body = macro_m.group(0)
    # The ioctl() return (-1 on any failure) must never be the value handed
    # to print_error -- it must be errno, captured right after the call.
    assert not re.search(r"print_error\([^,]+,\s*__e\s*,", body), (
        f"PPPOECTL_IOCTL still passes the raw ioctl() return to "
        f"print_error() instead of errno:\n{body}"
    )
    assert "errno" in body, (
        f"PPPOECTL_IOCTL must capture errno for print_error():\n{body}"
    )

    setparms_m = re.search(
        r"e\s*=\s*ioctl\(s,\s*PPPOESETPARMS,\s*&parms\);(?P<rest>.*?)"
        r"print_error\(ifname,\s*(?P<arg>[^,]+),\s*\"PPPOESETPARMS\"\)",
        text,
        re.S,
    )
    assert setparms_m, "could not find the PPPOESETPARMS print_error call site"
    assert setparms_m.group("arg").strip() != "e", (
        "PPPOESETPARMS error path still passes the ioctl() return ('e') to "
        "print_error() instead of errno"
    )


def test_pppoectl_uses_strtonum_not_atoi_for_numeric_options():
    text = _pppoectl_text()
    assert "strtonum(" in text, "no strtonum(3) use found -- atoi() not replaced"
    # atoi/atol must not remain on the numeric option-parsing lines this
    # spec item names (max-noreceive=, max-alive-missed=, alive-interval=,
    # lcp-timeout=, max-auth-failure=, query-dns=).
    for field in (
        "max-noreceive=",
        "max-alive-missed=",
        "alive-interval=",
        "lcp-timeout=",
        "max-auth-failure=",
        "query-dns=",
    ):
        m = re.search(
            r'startswith\(arg,\s*"' + re.escape(field) + r'"\).*?\n(?:.*\n){0,3}',
            text,
        )
        assert m, f"could not find the {field!r} arm in pppoectl_argument()"
        assert "atoi(" not in m.group(0), (
            f"{field!r} arm still uses atoi(): {m.group(0)!r}"
        )


def test_pppoectl_ifname_copies_use_strlcpy_with_a_length_check():
    text = _pppoectl_text()
    assert not re.search(r"strncpy\([^;]*ifname", text), (
        "pppoectl.c still has a strncpy(...ifname...) call -- strncpy does "
        "not guarantee NUL-termination when the source is >= the "
        "destination size; use strlcpy() and check its return"
    )
    assert "strlcpy(" in text and "ifname" in text


def test_pppoectl_c_header_notes_the_hardening_deltas():
    """R005 'byte-identical to NetBSD' no longer holds verbatim once these
    fixes land; the port notice must say so and point at the delta list
    (spec item 3: 'Keep the NetBSD-verbatim nature documented in
    docs/PORTING-sppp.md (list deltas)')."""
    header = _pppoectl_text().split("__RCSID")[0]
    assert "PORTING-sppp.md" in header and "hardening delta" in header, (
        "pppoectl.c's port-notice comment must point at docs/PORTING-sppp.md "
        "for the list of local hardening deltas from the NetBSD pin"
    )


def test_pppoectl_dash_s_rejects_dash_e_and_dash_f_dev_stdin_conflicts():
    """Review finding: -S used to be silently ignored under -e and raced
    -f /dev/stdin for the same stdin. Both must now be a hard error."""
    text = _pppoectl_text()
    assert re.search(r"secret_from_stdin\s*&&\s*eth_if_name", text), (
        "no check rejecting -S combined with -e"
    )
    assert re.search(r"secret_from_stdin.*?/dev/stdin", text, re.S), (
        "no check rejecting -S combined with -f /dev/stdin"
    )


def test_pppoectl_dash_s_secret_cannot_be_silently_overridden():
    """Review finding: a later myauthsecret=/myauthkey= (from -f or argv)
    used to silently override an already-set -S secret."""
    text = _pppoectl_text()
    m = re.search(
        r'startswith\(arg,\s*"myauthsecret="\).*?\n(?:.*\n){0,3}', text
    )
    assert m, "could not find the myauthsecret=/myauthkey= arm"
    assert "secret_from_stdin" in m.group(0), (
        "myauthsecret=/myauthkey= must reject an already-set -S secret, "
        f"not silently override it: {m.group(0)!r}"
    )


def test_pppoectl_dash_s_secret_is_scrubbed_on_exit():
    """Review finding: the -S secret buffer was never zeroed or freed."""
    text = _pppoectl_text()
    assert "explicit_bzero(" in text, (
        "the -S secret buffer must be explicit_bzero()'d before exit"
    )
    assert re.search(r"atexit\(\s*scrub_stdin_secret\s*\)", text), (
        "the -S secret scrub must be registered with atexit() so every "
        "err()/errx() exit path is covered, not just the normal return"
    )


def test_pppoectl_dash_s_strips_trailing_cr_too():
    """Review finding: only '\\n' was stripped, leaving a trailing '\\r'
    (CRLF input) as part of the secret."""
    text = _pppoectl_text()
    assert "stdin_secret[slen - 1] == '\\r'" in text, (
        "no '\\r' strip found alongside the existing '\\n' strip"
    )


def test_porting_doc_lists_the_ioctl_group_and_pppoectl_deltas():
    doc = (REPO_ROOT / "docs" / "PORTING-sppp.md").read_text()
    assert re.search(r"must be kept", doc) and "'i'" in doc, (
        "docs/PORTING-sppp.md must document that group 'i' is kept "
        "(not moved) and why"
    )
    assert "200" in doc and "SIOCGIFGROUP" in doc, (
        "docs/PORTING-sppp.md must document the SPPPGETIPCPSTATUS "
        "renumbering (136 -> 200) and its SIOCGIFGROUP collision"
    )
    for needle in ("pppoectl.c", "-S", "/dev/stdin"):
        assert needle in doc, (
            f"docs/PORTING-sppp.md must document the pppoectl.c delta {needle!r}"
        )


def _strip_c_comments(src: str) -> str:
    """Remove C comments the way the C preprocessor does: a block comment
    ends at the FIRST "*/", wherever it falls. String and character
    literals are skipped so a "/*" inside one does not open a comment."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if src.startswith("/*", i):
            end = src.find("*/", i + 2)
            if end < 0:
                raise AssertionError("unterminated /* comment")
            out.append("\n" * src.count("\n", i, end) + " ")
            i = end + 2
        elif src.startswith("//", i):
            end = src.find("\n", i)
            i = n if end < 0 else end
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


_C_SOURCES_WITH_COMMENT_BLOCKS = [
    IF_SPPP_H,
    IF_PPPOE_H,
    PPPOECTL_C,
    REPO_ROOT / "tests" / "ioctl-abi" / "check_ioctl_group.c",
]


@pytest.mark.parametrize(
    "path", _C_SOURCES_WITH_COMMENT_BLOCKS, ids=lambda p: p.name
)
def test_no_block_comment_closes_early(path):
    """Lab finding: prose like "SPPP*/PPPOE*" inside a /* */ block ends the
    comment at the embedded "*/", turning the rest of the block into live
    C ("unknown type name 'PPPOE'") and breaking if_pppoe.ko and
    pppoectl(8). After real comment stripping no " * ..." comment-body
    line may survive."""
    stripped = _strip_c_comments(path.read_text())
    leaked = [
        (lineno, line)
        for lineno, line in enumerate(stripped.splitlines(), 1)
        if re.match(r"^\s*\*(\s|$)", line)
    ]
    assert not leaked, (
        f"{path.relative_to(REPO_ROOT)}: comment text leaked into code "
        f"(an embedded '*/' closed a block comment early) at {leaked[:3]}"
    )
