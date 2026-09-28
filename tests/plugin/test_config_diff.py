"""Local-only unit tests for config_diff.py -- no DUT, no network."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from config_diff import diff, is_identical

BASE = """<?xml version="1.0"?>
<opnsense>
  <revision>
    <time>{time}</time>
    <description>{descr}</description>
    <username>root@192.168.90.1</username>
  </revision>
  <system>
    <hostname>dut</hostname>
  </system>
</opnsense>
"""


def test_identical_ignoring_revision_stamp():
    before = BASE.format(time="1000000000", descr="before install")
    after = BASE.format(time="1000009999", descr="after uninstall")
    assert is_identical(before, after)
    assert diff(before, after) == []


def test_detects_a_real_change():
    before = BASE.format(time="1000000000", descr="x")
    after = before.replace("<hostname>dut</hostname>", "<hostname>dut2</hostname>")
    d = diff(before, after)
    assert d == ["~system (differs)"]


def test_detects_added_section_other_than_ifpppoe():
    before = BASE.format(time="1", descr="x")
    after = before.replace("</opnsense>", "<OPNsense><AcmeClient/></OPNsense></opnsense>")
    d = diff(before, after)
    assert d == ["+OPNsense (present after, absent before)"]


def test_ifpppoe_subtree_appearing_is_not_a_mismatch():
    # Contract: pkg install writes <OPNsense><IfPppoe> via write_config();
    # pkg remove does not prune it. Its appearance across the round trip is
    # expected, not a real config change -- see config_diff.py's docstring.
    before = BASE.format(time="1", descr="x")
    after = before.replace(
        "</opnsense>",
        "<OPNsense><IfPppoe><general><enabled>1</enabled></general></IfPppoe></OPNsense></opnsense>",
    )
    assert is_identical(before, after)


def test_ifpppoe_changing_is_ignored_but_a_sibling_module_is_not():
    # Only OPNsense/IfPppoe is stripped -- a sibling module under the same
    # <OPNsense> wrapper must still be caught if it changes.
    before = BASE.format(time="1", descr="x").replace(
        "</opnsense>",
        "<OPNsense><IfPppoe><general><enabled>0</enabled></general></IfPppoe>"
        "<AcmeClient><general><enabled>0</enabled></general></AcmeClient></OPNsense></opnsense>",
    )
    ifpppoe_only_changed = before.replace(
        "<IfPppoe><general><enabled>0</enabled>", "<IfPppoe><general><enabled>1</enabled>"
    )
    assert is_identical(before, ifpppoe_only_changed)

    sibling_changed = before.replace(
        "<AcmeClient><general><enabled>0</enabled>", "<AcmeClient><general><enabled>1</enabled>"
    )
    assert not is_identical(before, sibling_changed)


def test_element_reordering_within_a_section_is_detected():
    # Order is preserved, not sorted: <filter><rule> order changes pf's
    # evaluation order, so a reorder anywhere is treated as a real
    # difference rather than risk hiding a rule-order change elsewhere.
    before = """<opnsense><a><x>1</x><y>2</y></a></opnsense>"""
    after = """<opnsense><a><y>2</y><x>1</x></a></opnsense>"""
    assert not is_identical(before, after)
    assert diff(before, after) == ["~a (differs)"]


def test_missing_revision_node_is_handled():
    # a config.xml with no <revision> at all (e.g. never write_config()'d)
    # must not crash the volatile-field stripping.
    before = "<opnsense><system><hostname>dut</hostname></system></opnsense>"
    after = before
    assert is_identical(before, after)
