/* Unit-test TU for sys/net/if_pppoe_disc.c (discovery FSM + tag walk). */
#include <net/if_pppoe_disc.c>

#include "fx.h"

/* The fuzz build links the fixtures above but not the tests. */
#ifndef KTEST_NO_TESTS
#include "../t/disc_input.c"
#endif
