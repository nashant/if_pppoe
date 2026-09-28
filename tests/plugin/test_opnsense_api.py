"""OpnsenseApiClient request plumbing, no DUT needed."""
from __future__ import annotations

from unittest import mock

import pytest

requests = pytest.importorskip("requests")
import opnsense_api  # noqa: E402  (after the importorskip above)


def _client():
    return opnsense_api.OpnsenseApiClient(host="dut.invalid", api_key="k", api_secret="s")


def test_per_call_timeout_overrides_the_default():
    # wait_until_(un)reachable pass timeout=; it must not collide with the default.
    with mock.patch.object(opnsense_api.requests, "request") as req:
        req.return_value.json.return_value = {}
        _client().get("/api/core/firmware/running", timeout=3.0)
        assert req.call_args.kwargs["timeout"] == 3.0
        _client().get("/api/core/firmware/running")
        assert req.call_args.kwargs["timeout"] == _client().timeout
