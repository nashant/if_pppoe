/*
 * spppkeepalive - set/get the sppp LCP keepalive settings
 * (SPPPSETKEEPALIVE/SPPPGETKEEPALIVE) on an if_pppoe clone.  Stopgap for
 * pppoectl(8) (plan 2, S05): it drives the keepalive ioctls the same way
 * pppoectl's list/set modes will, so the live keepalive recipes (M002/S03
 * T2) have a pppoectl-equivalent ioctl path.
 *
 *   spppkeepalive -g pppoe0                 # get + print (default units)
 *   spppkeepalive -m 3 -r 15 -i 1 pppoe0    # set maxalive=3,
 *                                            #   max_noreceive=15s,
 *                                            #   alive_interval=1
 *
 * The unit names follow the kernel struct field semantics:
 *   -m maxalive       max LCP echo requests with no reply before timeout
 *   -r max_noreceive  seconds of peer silence before echo requests start
 *   -i alive_interval keepalive ticks between echo requests (0 disables
 *                     the echo requests entirely)
 * The GET dump prints the same field labels (never any secret material).
 *
 * The struct and ioctl numbers come from the vendored sys/net/if_sppp.h
 * (ABI constraint R005) via -I${.CURDIR}/../../sys (see Makefile): a
 * private copy here could silently desync from the driver across a
 * renumbering (it did once -- the group-letter fix in if_sppp.h).
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_sppp.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{
	errx(1, "usage: spppkeepalive [-g] [-m maxalive] [-r max_noreceive] "
	    "[-i alive_interval] ifname\n"
	    "       (-g dumps; units: count/seconds/ticks)");
}

int
main(int argc, char **argv)
{
	struct spppkeepalivesettings ks;
	int c, get = 0, s, have_set = 0;

	memset(&ks, 0, sizeof(ks));

	while ((c = getopt(argc, argv, "gm:r:i:")) != -1) {
		switch (c) {
		case 'g': get = 1; break;
		case 'm': ks.maxalive = (u_int)strtoul(optarg, NULL, 0);
			  have_set = 1; break;
		case 'r': ks.max_noreceive = (long)strtoul(optarg, NULL, 0);
			  have_set = 1; break;
		case 'i': ks.alive_interval = (u_int)strtoul(optarg, NULL, 0);
			  have_set = 1; break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();
	if (!get && !have_set)
		errx(1, "nothing to do: give -g or at least one of -m/-r/-i");

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	strlcpy(ks.ifname, argv[0], sizeof(ks.ifname));

	if (get) {
		if (ioctl(s, SPPPGETKEEPALIVE, &ks) < 0)
			err(1, "SPPPGETKEEPALIVE");
		printf("if=%s maxalive=%u max_noreceive=%ld "
		    "alive_interval=%u\n", ks.ifname, ks.maxalive,
		    ks.max_noreceive, ks.alive_interval);
		return (0);
	}

	if (ioctl(s, SPPPSETKEEPALIVE, &ks) < 0)
		err(1, "SPPPSETKEEPALIVE");
	printf("SPPPSETKEEPALIVE ok on %s (maxalive=%u max_noreceive=%ld "
	    "alive_interval=%u)\n", ks.ifname, ks.maxalive,
	    ks.max_noreceive, ks.alive_interval);
	return (0);
}