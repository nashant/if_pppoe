"""Local-only unit tests for repo_registration.py -- no DUT, no network."""
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pytest

from repo_registration import fingerprint_ucl, repo_conf, repo_url


def test_repo_conf_has_required_pkg_repo_keys():
    text = repo_conf("IfPppoe", "http://lab-host.example:8080/if-pppoe", "/usr/local/etc/pkg/fingerprints/IfPppoe")
    for key in ("url:", "signature_type:", "fingerprints:", "enabled:"):
        assert key in text
    assert '"fingerprints"' in text  # signature_type value
    assert text.startswith("IfPppoe: {")


def test_repo_conf_omits_mirror_type_by_default():
    # A single static HTTP directory, not a mirror list -- mirror_type:
    # "http" is wrong here (see repo_conf's docstring/comment).
    text = repo_conf("IfPppoe", "http://lab-host.example:8080/if-pppoe", "/usr/local/etc/pkg/fingerprints/IfPppoe")
    assert "mirror_type" not in text


def test_repo_conf_mirror_type_explicit_override():
    text = repo_conf("IfPppoe", "http://lab-host.example:8080/if-pppoe",
                      "/usr/local/etc/pkg/fingerprints/IfPppoe", mirror_type="none")
    assert 'mirror_type: "none"' in text


def test_fingerprint_ucl_matches_sha256_of_key_bytes():
    key_bytes = b"not a real key, just test bytes"
    text = fingerprint_ucl(key_bytes)
    assert 'function: "sha256"' in text
    assert hashlib.sha256(key_bytes).hexdigest() in text


def test_repo_url_keeps_literal_abi_and_adds_no_series():
    url = repo_url("https://example.invalid/if_pppoe/")
    assert url == "https://example.invalid/if_pppoe/${ABI}"
    # No series segment: 25.7 and 26.1 share the FreeBSD:14:amd64 repo.
    for series in ("25.7", "26.1", "26.7"):
        assert series not in url


def test_repo_url_survives_into_repo_conf():
    text = repo_conf("IfPppoe", repo_url("https://example.invalid/r"),
                     "/usr/local/etc/pkg/fingerprints/IfPppoe")
    assert 'url: "https://example.invalid/r/${ABI}",' in text


@pytest.mark.parametrize("bad", ["", "/", "https://example.invalid/r/${ABI}"])
def test_repo_url_rejects_empty_or_doubled_abi(bad):
    with pytest.raises(ValueError):
        repo_url(bad)
