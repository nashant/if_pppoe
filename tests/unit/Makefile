# Host-runnable unit tests and libFuzzer targets for sys/net/*.c.
#
#   make -C tests/unit check                 build (ASan+UBSan) and run
#   make -C tests/unit fuzz FUZZ_SECONDS=60  every fuzzer for N seconds
#   make -C tests/unit fuzz-regress          replay seed corpora + crash repros
#   make -C tests/unit fuzz-docker ...       the fuzz targets via a clang image
#
# See docs/UNIT-TESTS.md.

CC		?= cc
ifeq ($(origin CC),default)
CC		:= $(shell command -v clang >/dev/null 2>&1 && echo clang || echo cc)
endif
FUZZ_CC		?= clang
FUZZ_SECONDS	?= 60
FUZZ_JOBS	?= 1
FUZZ_IMAGE	?= silkeh/clang:19

B		:= build
SYS		:= ../../sys
SAN		:= -fsanitize=address,undefined -fno-sanitize-recover=undefined \
		   -fno-omit-frame-pointer
WARN		:= -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare \
		   -Wno-pointer-sign -Wno-address-of-packed-member \
		   -Wno-missing-field-initializers -Wno-unused-function \
		   -Wno-sizeof-pointer-memaccess -Wno-format-truncation \
		   -Wno-unused-variable
CPPFLAGS	:= -include kshim/kern.h -Iinclude -I$(SYS) -Ikshim -Irunner -I.
CFLAGS		?= -g -O1
CFLAGS		+= -std=gnu11 $(WARN)
TSAN		:= $(SAN)

# One TU per kernel source: tu/<x>.c #includes sys/net/<x>.c and its tests.
TUS		:= sppp pppoe disc netisr
KSRC_sppp	:= $(SYS)/net/if_spppsubr.c
KSRC_pppoe	:= $(SYS)/net/if_pppoe.c
KSRC_disc	:= $(SYS)/net/if_pppoe_disc.c
KSRC_netisr	:= $(SYS)/net/if_pppoe_netisr.c
HDRS		:= $(wildcard kshim/*.h runner/*.h *.h t/*.h $(SYS)/net/*.h)

UNIT_OBJS	:= $(B)/kshim.o $(B)/main.o $(TUS:%=$(B)/tu_%.o)

.SECONDARY:
.PHONY: all check list clean fuzz fuzz-build fuzz-regress fuzz-known fuzz-docker seeds

all: $(B)/unit

$(B):
	@mkdir -p $(B) $(B)/fuzz

$(B)/kshim.o: kshim/kshim.c $(HDRS) | $(B)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TSAN) -c $< -o $@
$(B)/main.o: runner/main.c $(HDRS) | $(B)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TSAN) -c $< -o $@
.SECONDEXPANSION:
$(B)/tu_%.o: tu/%.c $$(KSRC_$$*) $$(wildcard t/$$*_*.c) $(wildcard t/*.c) $(HDRS) | $(B)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(TSAN) -c $< -o $@

$(B)/unit: $(UNIT_OBJS)
	$(CC) $(CFLAGS) $(TSAN) $^ -o $@

check: $(B)/unit
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:strict_string_checks=1 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1 \
	./$(B)/unit $(TESTS)

list: $(B)/unit
	./$(B)/unit -l

# ---------------------------------------------------------------- fuzzing
FUZZERS		:= lcp_confreq ipcp_confreq ipv6cp_confreq pppoe_input \
		   sppp_input
FSAN		:= -fsanitize=fuzzer-no-link,address,undefined \
		   -fno-sanitize-recover=undefined -fno-omit-frame-pointer
FOBJS		:= $(B)/fuzz/kshim.o $(TUS:%=$(B)/fuzz/tu_%.o)

$(B)/fuzz/kshim.o: kshim/kshim.c $(HDRS) | $(B)
	$(FUZZ_CC) $(CPPFLAGS) $(CFLAGS) $(FSAN) -c $< -o $@
$(B)/fuzz/tu_%.o: tu/%.c $$(KSRC_$$*) $(wildcard t/*.c) $(HDRS) | $(B)
	$(FUZZ_CC) $(CPPFLAGS) $(CFLAGS) $(FSAN) -DKTEST_NO_TESTS -c $< -o $@
$(B)/fuzz/fz_%_confreq.o: fuzz/fz_confreq.c $(HDRS) | $(B)
	$(FUZZ_CC) $(CPPFLAGS) $(CFLAGS) $(FSAN) -DFZ_CP=FX_IDX_$(shell echo $* | tr a-z A-Z) -c $< -o $@
$(B)/fuzz/fz_%.o: fuzz/fz_%.c $(HDRS) | $(B)
	$(FUZZ_CC) $(CPPFLAGS) $(CFLAGS) $(FSAN) -c $< -o $@
$(B)/fuzz/fz_%: $(B)/fuzz/fz_%.o $(FOBJS)
	$(FUZZ_CC) $(CFLAGS) -fsanitize=fuzzer,address,undefined $^ -o $@

fuzz-build: $(FUZZERS:%=$(B)/fuzz/fz_%)

# Seeds stay read-only in corpus/<name>; new inputs land in build/.
fuzz: fuzz-build
	@set -e; for f in $(FUZZERS); do \
		mkdir -p $(B)/corpus/$$f $(B)/artifacts/$$f; \
		echo "== fz_$$f ($(FUZZ_SECONDS)s)"; \
		./$(B)/fuzz/fz_$$f -max_total_time=$(FUZZ_SECONDS) \
		    -jobs=$(FUZZ_JOBS) -workers=$(FUZZ_JOBS) \
		    -print_final_stats=1 \
		    -artifact_prefix=$(B)/artifacts/$$f/ \
		    $(B)/corpus/$$f corpus/$$f; \
	done

# Every seed and every FIXED crash reproducer (crashes/), once each.  Open
# findings live under known-crashes/ and are replayed by fuzz-known instead,
# which is expected to fail until the bug is fixed (do not run it in CI).
fuzz-regress: fuzz-build
	@set -e; for f in $(FUZZERS); do \
		echo "== fz_$$f (regress)"; \
		./$(B)/fuzz/fz_$$f -runs=0 corpus/$$f \
		    $$(test -d crashes/$$f && echo crashes/$$f); \
	done

# Replay the open-bug reproducers; each is expected to still crash.
fuzz-known: fuzz-build
	@for f in $(FUZZERS); do \
		test -d known-crashes/$$f || continue; \
		echo "== fz_$$f (known-crash)"; \
		./$(B)/fuzz/fz_$$f -runs=0 known-crashes/$$f || true; \
	done

# No local clang: run the fuzz goal in a clang container on this tree.
fuzz-docker:
	docker run --rm -u $$(id -u):$$(id -g) -v $(abspath ../..):/src \
	    -w /src/tests/unit $(FUZZ_IMAGE) \
	    make B=build/docker $(or $(FUZZ_GOAL),fuzz) \
	    FUZZ_SECONDS=$(FUZZ_SECONDS) FUZZ_JOBS=$(FUZZ_JOBS)

seeds:
	python3 corpus/gen_seeds.py corpus

clean:
	rm -rf $(B)
