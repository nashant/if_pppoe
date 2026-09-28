"""Normalize two config.xml snapshots for the round-trip test's "config is
identical after install -> enable -> disable -> uninstall" assertion.

A byte-for-byte compare is wrong: OPNsense stamps a fresh <revision><time>/
<username>/<description> on every write_config() call (verified:
Api/BackupController.php backupsAction reads exactly those three fields off
each backup's <revision> node). This module strips exactly the fields that
are KNOWN to legitimately change on every config write, plus the
<OPNsense><IfPppoe> subtree the plugin itself owns (see VOLATILE_SUBTREES),
and diffs everything else structurally.

<OPNsense><IfPppoe> is excluded by contract, not oversight: removing the pkg
does not prune the plugin's model data from config.xml (no core path does
this on `pkg remove` -- ifpppoe_set_settings() writes it via write_config()
same as any other model, and uninstall is a plain pkg delete), so it is
EXPECTED to still be present after uninstall even though it was absent
before install. The round-trip test's job is to prove nothing else changed.

Element order is preserved (not sorted) when comparing: <filter><rule>
order changes pf's evaluation order, so a reordering there is a REAL
difference, not noise -- see test_config_diff.py's ordering test.
"""
from __future__ import annotations

try:
    # Prefer defusedxml (not a hard dependency: this module's input is
    # config.xml downloaded over an authenticated API call to our own test
    # DUT, not third-party input -- but XXE/entity-expansion hardening is
    # cheap and the DUT's config is not otherwise trust-boundaried here).
    import defusedxml.ElementTree as ET
except ImportError:  # pragma: no cover
    import xml.etree.ElementTree as ET

# Only <revision>'s own children -- never a same-named element elsewhere in
# the tree (there is exactly one <revision> node at config.xml's top level).
VOLATILE_REVISION_FIELDS = {"time", "description", "username"}

# (parent tag, child tag) pairs to drop wholesale before comparing -- see
# module docstring for why <OPNsense><IfPppoe> specifically is expected to
# differ (present after, absent before) and is not a real mismatch.
VOLATILE_SUBTREES = {("OPNsense", "IfPppoe")}


def _strip_volatile(root: ET.Element) -> None:
    revision = root.find("revision")
    if revision is not None:
        for field in list(revision):
            if field.tag in VOLATILE_REVISION_FIELDS:
                revision.remove(field)
    # parent_tag (e.g. "OPNsense") is always a direct child of the document
    # root in config.xml's own shape -- not searched recursively.
    for parent_tag, child_tag in VOLATILE_SUBTREES:
        parent = root.find(parent_tag)
        if parent is None:
            continue
        for child in list(parent):
            if child.tag == child_tag:
                parent.remove(child)
        # If stripping left the wrapper with nothing else in it, drop the
        # wrapper too -- otherwise "OPNsense never existed before install"
        # vs. "OPNsense now exists but empty" would itself register as a
        # mismatch, defeating the whole point of ignoring this subtree.
        if len(parent) == 0 and not (parent.text or "").strip():
            root.remove(parent)


def _canonicalize(elem: ET.Element) -> tuple:
    """A hashable tree shape: (tag, sorted(attrib.items()), text.strip() or
    '', children in DOCUMENT ORDER). Children are NOT sorted: order is
    semantically meaningful for at least <filter><rule> (pf evaluates rules
    in list order), so preserving it everywhere is the safe default -- a
    reorder inside a section that genuinely doesn't care about order would
    show up as a false-positive "differs", which is a much smaller cost than
    silently accepting a real rule-order change."""
    children = tuple(_canonicalize(c) for c in elem)
    text = (elem.text or "").strip()
    return (elem.tag, tuple(sorted(elem.attrib.items())), text, children)


def normalize(xml_text: str) -> tuple:
    root = ET.fromstring(xml_text)
    _strip_volatile(root)
    return _canonicalize(root)


def diff(xml_before: str, xml_after: str) -> list[str]:
    """Returns a list of human-readable differences (empty == identical
    after normalization). Not a full tree-diff -- good enough to point a
    human at what changed, not to auto-merge anything."""
    before = ET.fromstring(xml_before)
    after = ET.fromstring(xml_after)
    _strip_volatile(before)
    _strip_volatile(after)

    if _canonicalize(before) == _canonicalize(after):
        return []

    # Fall back to a coarse top-level-section comparison for a useful
    # message (full recursive diff is unnecessary for what this harness
    # needs: proof the mismatch is real, not where every byte moved).
    before_sections = {c.tag: _canonicalize(c) for c in before}
    after_sections = {c.tag: _canonicalize(c) for c in after}
    diffs = []
    for tag in sorted(set(before_sections) | set(after_sections)):
        b, a = before_sections.get(tag), after_sections.get(tag)
        if b != a:
            if b is None:
                diffs.append(f"+{tag} (present after, absent before)")
            elif a is None:
                diffs.append(f"-{tag} (present before, absent after)")
            else:
                diffs.append(f"~{tag} (differs)")
    return diffs


def is_identical(xml_before: str, xml_after: str) -> bool:
    return diff(xml_before, xml_after) == []
