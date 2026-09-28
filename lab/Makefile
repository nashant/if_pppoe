# if_pppoe test lab
#
# lab-up/lab-down deploy lab/isp-netns to $(VMHOST):$(LAB_DIR)/isp-netns (it
# only runs there); lab/vm/run.sh is already ssh-driven from anywhere.
# VMHOST/PERF_*: no default host -- set in gitignored lab/local.env (copy
# lab/local.env.example) or pass on the command line.

-include local.env

CLIENT ?= mpd5
SERVER ?= accel
BACKEND ?= if_pppoe
VMHOST ?= $(error VMHOST not set -- create lab/local.env from lab/local.env.example, or pass VMHOST=<host> on the command line)
LAB_DIR ?= if_pppoe-lab
KERNCONF ?= SMP
PERF_SERVER ?= $(error PERF_SERVER not set -- create lab/local.env from lab/local.env.example, or pass PERF_SERVER=<host> on the command line)
PERF_CLIENT ?= $(error PERF_CLIENT not set -- create lab/local.env from lab/local.env.example, or pass PERF_CLIENT=<host> on the command line)
PERF_DUT ?= $(error PERF_DUT not set -- create lab/local.env from lab/local.env.example, or pass PERF_DUT=<host> on the command line)
PERF_ARGS ?=
# LAB_SLOT: which lab slot's client/isp/mpdsrv VMs to use (lab/vm/README.md
# "Slots and leases"). Slot 1 keeps the historical remote dir/log names.
LAB_SLOT ?= 1
PYTEST_ARGS ?=
# PYTEST_SEL: explicit node/dir selection, replacing $(TESTS_DIR) instead of
# adding to it. Kept separate from PYTEST_ARGS (pure flags) so a flag's value
# is never mistaken for a selection.
PYTEST_SEL ?=
REV ?=
BUILD_CHECK_ARGS ?=
ifeq ($(LAB_SLOT),1)
SLOT_SFX :=
else
SLOT_SFX := -slot$(LAB_SLOT)
endif
TESTS_DIR := tests-functional$(SLOT_SFX)
FUNC_LOG = last-func$(SLOT_SFX)-$(SERVER).log
LOST_LOG = last-func$(SLOT_SFX)-$(SERVER)-ssh-lost.log
SLOT_ENV := LAB_SLOT=$(LAB_SLOT)
export LAB_SLOT
PERF_FWD_FLOWS ?= 1,4,16
PERF_FWD_DURATION ?= 60
PERF_FWD_SAMPLE_DURATION ?= 10
PERF_FWD_LOCKSTAT ?= max-flows

.PHONY: help lab-up lab-down vm-build-setup vm-build-start vm-build-status vm-build-collect build-check test-func test-teardown test-hardening test-perf test-perf-fwd test-perf-fwd-ratio test-perf-fwd-sample baseline

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "%-12s %s\n", $$1, $$2}'

lab-up: ## Bring up LAB_SLOT's lab VMs (slot 1 also: the isp netns on $(VMHOST))
ifeq ($(LAB_SLOT),1)
	rsync -a --delete ./isp-netns/ $(VMHOST):$(LAB_DIR)/isp-netns/
	ssh $(VMHOST) '$(LAB_DIR)/isp-netns/up.sh'
endif
	for n in build client mpdsrv; do ./vm/run.sh $$n up; done
	./vm/run.sh isp up && ./vm/provision-isp.sh

lab-down: ## Tear down LAB_SLOT's lab VMs (slot 1: also build + the isp netns)
ifeq ($(LAB_SLOT),1)
	for n in mpdsrv client build; do ./vm/run.sh $$n down; done
	rsync -a --delete ./isp-netns/ $(VMHOST):$(LAB_DIR)/isp-netns/
	ssh $(VMHOST) '$(LAB_DIR)/isp-netns/down.sh'
else
	for n in mpdsrv client isp; do ./vm/run.sh $$n down; done
endif

vm-build-setup: ## Clone opnsense/src @25.7.11 and fetch/author the KERNCONF kernel config on the build VM (var: KERNCONF, default SMP; SMPW authors the debug variant)
	KERNCONF=$(KERNCONF) ./vm/build-kernel.sh setup

vm-build-start: ## Start `make buildkernel KERNCONF=$(KERNCONF)` in the background on the build VM
	KERNCONF=$(KERNCONF) ./vm/build-kernel.sh start

vm-build-status: ## Poll the background buildkernel; re-run until it prints DONE
	KERNCONF=$(KERNCONF) ./vm/build-kernel.sh status

vm-build-collect: ## Copy the finished $(KERNCONF) kernel to $(VMHOST):$(LAB_DIR)/kernel/$(KERNCONF)
	KERNCONF=$(KERNCONF) ./vm/build-kernel.sh collect

build-check: ## Fast compile-only lane (no lab slot): kmod SMP+SMPW(+reflect), pppoectl, tools/*; vars: REV (commit-ish or worktree path, default: this worktree), BUILD_CHECK_ARGS (e.g. --clean)
	./vm/build-check.sh $(BUILD_CHECK_ARGS) $(REV)

test-func: ## Run the functional test suite (pytest + scapy) on $(VMHOST), vars: CLIENT, SERVER, LAB_SLOT, PYTEST_ARGS, PYTEST_SEL
	# --exclude __pycache__: pytest (run remotely as root, for scapy) leaves
	# root-owned .pyc files that --delete then can't unlink as this user.
	# The remote pytest run writes its full output to last-func-$(SERVER).log
	# on $(VMHOST) and only the tail is echoed back: a mid-run ssh transport
	# death (rc 255) must never waste the run -- the verdict survives on the
	# VM and this target recovers it via scp before failing.
	rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' ../tests/functional/ $(VMHOST):$(LAB_DIR)/$(TESTS_DIR)/
	# The vendored net/if_sppp.h + net/if_pppoe.h alongside the test files:
	# test_sppp_ioctl_live.py/test_sppp_ctl_robustness.py push these to the
	# client VM so their embedded C probes #include the real ABI instead of
	# a private, driftable copy (see lab.py's push_vendored_sppp_headers()).
	ssh $(VMHOST) 'mkdir -p $(LAB_DIR)/$(TESTS_DIR)/vendor-headers/net'
	rsync -a ../sys/net/if_sppp.h ../sys/net/if_pppoe.h $(VMHOST):$(LAB_DIR)/$(TESTS_DIR)/vendor-headers/net/
	# Same reasoning, for test_ctl_contract.py's ctl-contract fixtures + replay
	# script (see lab.py's push_ctl_contract()/_ctl_contract_source_dir_and_replay()).
	ssh $(VMHOST) 'mkdir -p $(LAB_DIR)/$(TESTS_DIR)/vendor-ctl-contract/fixtures'
	rsync -a --delete ../plugin/net/if-pppoe/tests/fixtures/ctl-contract/ $(VMHOST):$(LAB_DIR)/$(TESTS_DIR)/vendor-ctl-contract/fixtures/
	rsync -a ../plugin/net/if-pppoe/tests/engine/ctl-contract-replay.sh $(VMHOST):$(LAB_DIR)/$(TESTS_DIR)/vendor-ctl-contract/ctl-contract-replay.sh
	# -tt: an interrupted local ssh kills the remote pytest.
	# PYTEST_ARGS is a pass-through, appended last (e.g. -m wins over "not
	# soak"); use PYTEST_SEL for a node/dir selection, which replaces the
	# default $(TESTS_DIR) instead of adding to it.
	ssh -tt $(VMHOST) '\
		cd $(LAB_DIR) && \
		test -x venv/bin/python3 || (python3 -m venv venv && venv/bin/pip install -q --upgrade pip && venv/bin/pip install -q pytest scapy) && \
		sudo env $(SLOT_ENV) CLIENT=$(CLIENT) SERVER=$(SERVER) venv/bin/python3 -m pytest $(if $(PYTEST_SEL),$(PYTEST_SEL),$(TESTS_DIR)) -m "not soak" $(PYTEST_ARGS) \
			> $(FUNC_LOG) 2>&1; \
		rc=$$?; \
		echo REMOTE_RC=$$rc; \
		echo "---- $(FUNC_LOG) tail ----"; \
		grep -E "^(FAILED|ERROR|[=]+ .*(passed|failed))" $(FUNC_LOG) | tail -30; \
		exit $$rc'; \
	rc=$$?; \
	if [ $$rc -eq 255 ]; then \
		echo "test-func: ssh transport died (rc=255); recovering remote run log"; \
		scp -q $(VMHOST):$(LAB_DIR)/$(FUNC_LOG) ./$(LOST_LOG) 2>/dev/null \
			&& { echo "RECOVERED $(VMHOST):$(LAB_DIR)/$(FUNC_LOG) -> $$(pwd)/$(LOST_LOG)"; tail -30 ./$(LOST_LOG); } \
			|| echo "test-func: recovery scp failed (VM unreachable)"; \
	fi; \
	exit $$rc

test-teardown: ## Run the operational kldunload probe (10x live-session unloads + loud-path jail smoke) on $(VMHOST), vars: CLIENT, SERVER
	# Same rsync exclusions as test-func; the probe is a standalone script, not
	# a pytest test (suite count is pinned at 63 passed / 2 deselected /
	# 0 xfailed through M002 S05 T4 -- see docs/TESTING.md's result matrix).
	rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' ../tests/functional/ $(VMHOST):$(LAB_DIR)/$(TESTS_DIR)/
	ssh $(VMHOST) '\
		cd $(LAB_DIR) && \
		test -x venv/bin/python3 || (python3 -m venv venv && venv/bin/pip install -q --upgrade pip && venv/bin/pip install -q pytest scapy) && \
		sudo env $(SLOT_ENV) CLIENT=$(CLIENT) SERVER=$(SERVER) venv/bin/python3 $(TESTS_DIR)/unload_probe.py --iterations 10'

test-hardening: CLIENT := if_pppoe
test-hardening: ## Run the S02 hardening probe (10x traffic-under-unload + 5 vnet jail cycles + M_PPPOE accounting) on $(VMHOST), vars: CLIENT (default if_pppoe), SERVER
	# Same rsync exclusions as test-func; the probe is a standalone script,
	# not a pytest test (suite count pinned -- see docs/TESTING.md's result
	# matrix). CLIENT defaults to if_pppoe here (target-local assignment:
	# command-line CLIENT= still overrides) because the probe kldunload's
	# the if_pppoe module, which the mpd5 backend cannot drive.
	rsync -a --delete --exclude='__pycache__' --exclude='*.pyc' ../tests/functional/ $(VMHOST):$(LAB_DIR)/$(TESTS_DIR)/
	ssh $(VMHOST) '\
		cd $(LAB_DIR) && \
		test -x venv/bin/python3 || (python3 -m venv venv && venv/bin/pip install -q --upgrade pip && venv/bin/pip install -q pytest scapy) && \
		sudo env $(SLOT_ENV) CLIENT=$(CLIENT) SERVER=$(SERVER) venv/bin/python3 $(TESTS_DIR)/hardening_probe.py'

test-perf: ## Run the performance matrix against BACKEND (mpd5|mpd5-tuned|if_pppoe|plain), vars: PERF_SERVER, PERF_CLIENT, PERF_DUT, PERF_ARGS (e.g. PERF_ARGS=--dry-run)
	python3 ../tests/perf/run_matrix.py --backend $(BACKEND) --server $(PERF_SERVER) --client $(PERF_CLIENT) --dut $(PERF_DUT) $(PERF_ARGS)

baseline: ## Run the performance matrix against the mpd5 baseline
	$(MAKE) test-perf BACKEND=mpd5

test-perf-fwd: ## Forwarded (pf+NAT) perf matrix in LAB_SLOT's VMs (router=client<N>, lan=lan<N>, isp=isp<N>). BACKEND=if_pppoe|mpd5|raw (default if_pppoe); vars: LAB_SLOT, PERF_FWD_FLOWS (1,4,16), PERF_FWD_DURATION (60), PERF_FWD_LOCKSTAT (max-flows|all|none), PERF_ARGS. See docs/PERF-FWD-DESIGN.md.
	set -eu; \
	case "$(BACKEND)" in \
		if_pppoe|mpd5) wan=pppoe0 ;; \
		raw) wan=raw ;; \
		*) echo "test-perf-fwd: BACKEND must be if_pppoe, mpd5, or raw (got '$(BACKEND)')" >&2; exit 1 ;; \
	esac; \
	./vm/perf-backend.sh $(BACKEND); \
	./vm/router-mode.sh enable "$$wan"; \
	if [ "$(BACKEND)" = raw ]; then ./vm/provision-isp-raw.sh; fi; \
	target=$$(./vm/perf-target.sh $(BACKEND)); \
	cfg=$$(mktemp /tmp/if_pppoe-lab-ssh-config.XXXXXX); \
	trap 'rm -f "$$cfg"' EXIT; \
	./vm/ssh-config.sh > "$$cfg"; \
	sha=$$(git rev-parse --short HEAD 2>/dev/null || echo nogit); \
	outdir="../tests/results/perf/$$(date -u +%Y%m%dT%H%M%SZ)-$(BACKEND)-$$sha$(SLOT_SFX)"; \
	mkdir -p "$$outdir"; \
	python3 ../tests/perf/run_matrix.py --backend $(BACKEND) \
		--server "$$target" --client lab-lan --dut lab-client --ssh-config "$$cfg" \
		--flows $(PERF_FWD_FLOWS) --duration $(PERF_FWD_DURATION) --skip-udp64 \
		--irq-prefix virtio --root-cmd 'echo | su -m root -c {}' --lockstat $(PERF_FWD_LOCKSTAT) \
		--out "$$outdir/matrix.json" $(PERF_ARGS); \
	python3 ../tests/perf/split_runs.py "$$outdir/matrix.json" --outdir "$$outdir"; \
	python3 ../tests/perf/summarize.py "$$outdir/matrix.json" | tee "$$outdir/summary.txt"; \
	echo "test-perf-fwd: wrote $$outdir"

test-perf-fwd-ratio: ## Print a ratio-to-raw table from two already-run test-perf-fwd result dirs, vars: FWD_DIR (the backend under test), FWD_RAW_DIR (the raw baseline)
	test -n "$(FWD_DIR)" && test -n "$(FWD_RAW_DIR)" || { echo "usage: make test-perf-fwd-ratio FWD_DIR=<dir> FWD_RAW_DIR=<dir>" >&2; exit 1; }
	python3 ../tests/perf/summarize.py --ratio-baseline raw "$(FWD_RAW_DIR)/matrix.json" "$(FWD_DIR)/matrix.json"

test-perf-fwd-sample: ## Optional, root-requiring: one lockstat/pmcstat availability + sample pass against the router VM, vars: PERF_FWD_SAMPLE_DURATION (10)
	set -eu; \
	cfg=$$(mktemp /tmp/if_pppoe-lab-ssh-config.XXXXXX); \
	trap 'rm -f "$$cfg"' EXIT; \
	./vm/ssh-config.sh > "$$cfg"; \
	python3 ../tests/perf/sample_lockstat.py --dut lab-client --duration $(PERF_FWD_SAMPLE_DURATION) --ssh-config "$$cfg" --root-cmd 'echo | su -m root -c {}'
