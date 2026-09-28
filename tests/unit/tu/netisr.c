/* Unit-test TU for sys/net/if_pppoe_netisr.c (inner hash, m2cpuid). */
#include <net/if_pppoe_netisr.c>

#include "fx.h"

/* The fuzz build links the fixtures above but not the tests. */
#ifndef KTEST_NO_TESTS
#include "../t/netisr_hash.c"
#endif
