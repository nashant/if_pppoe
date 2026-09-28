"""A small OPNsense MVC API client, for tests/plugin/'s round-trip harness.

URL shape and the install/reboot/backup-download/health-check action names
are verified against opnsense/core 25.7.11
(41587bb2d45af01811f580438dd758b8d45c9541):
  - `/api/<module>/<controller>/<action>` -- e.g. AcmeClient's
    accounts.volt calls `/api/acmeclient/accounts/search`
    (plugins/security/acme-client, same tag). IfPppoe -> `/api/ifpppoe/...`.
  - Firmware install/remove/reboot/health are async-over-configd: POST
    returns {status, msg_uuid}; poll GET .../upgradestatus, whose `log`
    contains `***DONE***`/`***REBOOT***` (Api/FirmwareController.php
    installAction/upgradestatusAction).
  - `/api/core/backup/download/<host>` returns the newest /conf/backup/
    config-*.xml for `host` (Api/BackupController.php downloadAction);
    `this` is this box's own key by convention used elsewhere in core's
    backup-provider list (not independently re-verified for "this" specifically
    -- confirm against a live box's /api/core/backup/providers first).
  - `/api/core/firmware/health` == `pkg check -sa`-driven audit
    (Api/FirmwareController.php healthAction -> auditHelper('health'); see
    docs/plugin/interfaces-inc-hook.md S3.2's citation of firmware/health.sh).

IfPppoe's own settings/service action names (`get`/`set`, `status`/
`reconfigure`) follow the `ApiMutableModelControllerBase` /
`ApiMutableServiceControllerBase` convention other simple plugins use
(security/clamav's GeneralController, same tag) -- NOT independently
confirmed against the actual IfPppoe module (built in parallel, branch
p4-hook/p4-engine); update IFPPPOE_* below if those land with different
action names.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import requests

IFPPPOE_SETTINGS_GET = "/api/ifpppoe/settings/get"
IFPPPOE_SETTINGS_SET = "/api/ifpppoe/settings/set"
IFPPPOE_SERVICE_STATUS = "/api/ifpppoe/service/status"
IFPPPOE_SERVICE_RECONFIGURE = "/api/ifpppoe/service/reconfigure"
# Api\SettingsController::$internalModelName: the top-level key of settings/get and settings/set
IFPPPOE_MODEL_NAME = "ifpppoe"


class ApiError(RuntimeError):
    pass


@dataclass
class OpnsenseApiClient:
    host: str
    # repr=False: a pytest failure report showing this client (e.g. with
    # --showlocals) must never print the run's API credentials.
    api_key: str = field(repr=False)
    api_secret: str = field(repr=False)
    verify_tls: bool = False  # lab CA is typically self-signed; the round-trip
                              # test should pin the DUT's actual cert instead
                              # of disabling verification wholesale -- see
                              # tests/plugin/README.md's "TLS" note.
    timeout: float = 30.0

    def _url(self, path: str) -> str:
        return f"https://{self.host}{path}"

    def _request(self, method: str, path: str, **kwargs) -> dict:
        # A per-call timeout= (the reachability waits) overrides the default.
        kwargs.setdefault("timeout", self.timeout)
        resp = requests.request(
            method, self._url(path),
            auth=(self.api_key, self.api_secret),
            verify=self.verify_tls, **kwargs,
        )
        resp.raise_for_status()
        return resp.json()

    def get(self, path: str, **kwargs) -> dict:
        return self._request("GET", path, **kwargs)

    def post(self, path: str, json: dict | None = None, **kwargs) -> dict:
        return self._request("POST", path, json=json or {}, **kwargs)

    # -- firmware -----------------------------------------------------
    def register_repo(self, conf_text: str, fingerprint_ucl: str, repo_name: str = "IfPppoe") -> None:
        """Not an API call: pkg repo registration is a filesystem operation
        on the DUT (/usr/local/etc/pkg/repos/<repo>.conf +
        /usr/local/etc/pkg/fingerprints/<repo>/trusted/<key>). Left as a
        documented step for whichever transport the caller has (ssh in the
        lab; see test_roundtrip.py) rather than faked through the API,
        since there is no OPNsense API surface for pkg repo registration
        (grep of Api/FirmwareController.php found none)."""
        raise NotImplementedError("write conf_text/fingerprint_ucl over ssh -- see test_roundtrip.py")

    def firmware_install(self, pkg_name: str, poll_interval: float = 5.0, overall_timeout: float = 900.0) -> str:
        return self._run_firmware_action(f"/api/core/firmware/install/{pkg_name}", poll_interval, overall_timeout)

    def firmware_remove(self, pkg_name: str, poll_interval: float = 5.0, overall_timeout: float = 300.0) -> str:
        return self._run_firmware_action(f"/api/core/firmware/remove/{pkg_name}", poll_interval, overall_timeout)

    def _run_firmware_action(self, post_path: str, poll_interval: float, overall_timeout: float,
                              start_timeout: float = 30.0) -> str:
        """POST a firmware action and poll it to completion, guarding against
        the stale-log race: install/remove/health all run through `daemon -f
        .../launcher.sh` (actions_firmware.conf), so the POST returns before
        the job actually starts, and launcher.sh's `flock -n` means a job
        posted while another already holds the lock exits SILENTLY -- in
        both cases /api/core/firmware/upgradestatus can still be serving the
        PREVIOUS job's log, ending in its own ***DONE***, and a caller that
        just checks for ***DONE*** or a substring can pass without this job
        having run at all.

        Fix: wait for `running` to go idle before posting (refuse to start
        over a job that's still in flight), record the log as it stands
        then, and after posting require EITHER `running` to report busy OR
        the log to have visibly changed before trusting _poll_firmware's
        result -- if neither happens within start_timeout, the action never
        actually started (most likely the flock case) and this raises
        instead of returning a stale log as if it were fresh.
        """
        self._wait_idle(start_timeout)
        prior_log = self.get("/api/core/firmware/upgradestatus").get("log", "")

        self.post(post_path)

        start_deadline = time.monotonic() + start_timeout
        while True:
            running = self.get("/api/core/firmware/running")
            cur = self.get("/api/core/firmware/upgradestatus")
            if running.get("running") or cur.get("log", "") != prior_log:
                break
            if time.monotonic() >= start_deadline:
                raise ApiError(
                    f"firmware action at {post_path!r} did not appear to start within "
                    f"{start_timeout}s (running=false, log unchanged -- likely rejected by "
                    "launcher.sh's flock because another action was already in flight)"
                )
            time.sleep(0.5)

        return self._poll_firmware(poll_interval, overall_timeout)

    def _wait_idle(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.get("/api/core/firmware/running").get("running"):
                return
            time.sleep(1.0)
        raise ApiError(f"firmware is still running another action after {timeout}s; refusing to start a new one")

    def _poll_firmware(self, poll_interval: float, overall_timeout: float) -> str:
        deadline = time.monotonic() + overall_timeout
        while time.monotonic() < deadline:
            result = self.get("/api/core/firmware/upgradestatus")
            status = result.get("status")
            if status in ("done", "reboot"):
                return result.get("log", "")
            if status == "error":
                raise ApiError(f"firmware action errored: {result}")
            time.sleep(poll_interval)
        raise ApiError(f"firmware action did not finish within {overall_timeout}s")

    def firmware_health(self) -> dict:
        log = self._run_firmware_action("/api/core/firmware/health", 3.0, 120.0)
        # UNVERIFIED exact section-header text (this session has no source
        # citation for health.sh's own output format) -- "pkg" is the
        # weakest assertion that still fails on a genuinely empty/stale log,
        # which is the actual bug this guards against; tighten once the
        # real output is seen from a live run.
        if "pkg" not in log:
            raise ApiError(f"firmware/health log doesn't look like a pkg check run: {log!r}")
        return {"log": log}

    def reboot(self) -> None:
        self.post("/api/core/firmware/reboot")

    def wait_until_unreachable(self, timeout: float = 60.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                self.get("/api/core/firmware/running", timeout=3.0)
            except requests.RequestException:
                return
            time.sleep(1.0)
        raise ApiError(f"DUT still reachable {timeout}s after reboot request")

    def wait_until_reachable(self, timeout: float = 300.0, poll_interval: float = 3.0) -> None:
        deadline = time.monotonic() + timeout
        last_exc: Exception | None = None
        while time.monotonic() < deadline:
            try:
                self.get("/api/core/firmware/running", timeout=5.0)
                return
            except requests.RequestException as e:
                last_exc = e
                time.sleep(poll_interval)
        raise ApiError(f"DUT not reachable within {timeout}s: {last_exc}")

    # -- config backup ---------------------------------------------------
    # NOTE: NOT used for the round-trip's "config identical" assertion --
    # this returns the newest /conf/backup/config-*.xml (Api/BackupController.php
    # downloadAction), a snapshot from whenever the last backup was taken,
    # not the live config -- see conftest.py's dut_live_config (reads
    # /conf/config.xml over ssh instead). Kept here for callers that
    # genuinely want the backup history, not the current state.
    def download_config_backup(self, host: str = "this") -> str:
        resp = requests.get(
            self._url(f"/api/core/backup/download/{host}"),
            auth=(self.api_key, self.api_secret), verify=self.verify_tls, timeout=self.timeout,
        )
        resp.raise_for_status()
        return resp.text

    # -- gateways ----------------------------------------------------------
    def gateway_status(self) -> dict:
        # UNVERIFIED exact path/shape this session (no source fetch for
        # RoutesController this time) -- OPNsense's gateway status API is
        # conventionally /api/routes/gateway/status, returning an
        # {items: [...]} list with a 'name' and 'status' per gateway; kept
        # loose (callers grep the raw dict) until confirmed against a live box.
        return self.get("/api/routes/gateway/status")

    # -- IfPppoe plugin -------------------------------------------------
    def ifpppoe_get_settings(self) -> dict:
        return self.get(IFPPPOE_SETTINGS_GET)

    def ifpppoe_set_settings(self, enabled: bool, exclude: list[str] | None = None) -> dict:
        # ApiMutableModelControllerBase::setAction() reads $_POST[internalModelName]
        # (core 25.7.11 ApiMutableModelControllerBase.php:380); IfPppoe's is 'ifpppoe'
        payload = {IFPPPOE_MODEL_NAME: {"general": {"enabled": "1" if enabled else "0", "exclude": ",".join(exclude or [])}}}
        return self.post(IFPPPOE_SETTINGS_SET, json=payload)

    def ifpppoe_status(self) -> dict:
        return self.get(IFPPPOE_SERVICE_STATUS)

    def ifpppoe_reconfigure(self) -> dict:
        return self.post(IFPPPOE_SERVICE_RECONFIGURE)
