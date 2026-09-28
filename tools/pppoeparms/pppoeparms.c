/*
 * pppoeparms - minimal PPPOESETPARMS/PPPOEGETPARMS/PPPOEGETSESSION tool.
 * Superseded by pppoectl(8) in plan 2; used by the `datapath` tests only.
 *
 *   pppoeparms -e vtnet1 [-s service] [-a acname] pppoe0   # set
 *   pppoeparms -d pppoe0                                   # dump
 */
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_pppoe.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	struct pppoediscparms parms;
	struct pppoeconnectionstate state;
	char acbuf[256], svbuf[256];
	const char *eth = NULL, *service = NULL, *acname = NULL;
	int c, dump = 0, s;

	while ((c = getopt(argc, argv, "de:s:a:")) != -1) {
		switch (c) {
		case 'd': dump = 1; break;
		case 'e': eth = optarg; break;
		case 's': service = optarg; break;
		case 'a': acname = optarg; break;
		default:
			errx(1, "usage: pppoeparms [-d] [-e iface] "
			    "[-s service] [-a acname] ifname");
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		errx(1, "exactly one interface name is required");

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	if (dump) {
		memset(&parms, 0, sizeof(parms));
		memset(acbuf, 0, sizeof(acbuf));
		memset(svbuf, 0, sizeof(svbuf));
		strlcpy(parms.ifname, argv[0], sizeof(parms.ifname));
		parms.ac_name = acbuf;
		parms.ac_name_len = sizeof(acbuf);
		parms.service_name = svbuf;
		parms.service_name_len = sizeof(svbuf);
		if (ioctl(s, PPPOEGETPARMS, &parms) < 0)
			err(1, "PPPOEGETPARMS");
		memset(&state, 0, sizeof(state));
		strlcpy(state.ifname, argv[0], sizeof(state.ifname));
		if (ioctl(s, PPPOEGETSESSION, &state) < 0)
			err(1, "PPPOEGETSESSION");
		printf("parent=%s service=%s acname=%s\n",
		    parms.eth_ifname, svbuf, acbuf);
		printf("state=%u session=%u padi_retries=%u padr_retries=%u\n",
		    state.state, state.session_id, state.padi_retry_no,
		    state.padr_retry_no);
		return (0);
	}

	memset(&parms, 0, sizeof(parms));
	strlcpy(parms.ifname, argv[0], sizeof(parms.ifname));
	if (eth != NULL)
		strlcpy(parms.eth_ifname, eth, sizeof(parms.eth_ifname));
	/*
	 * On PPPOESETPARMS *_name_len is strlen(), NOT a buffer size -- the
	 * NetBSD pppoectl(8) convention the kernel side implements.  (On
	 * PPPOEGETPARMS above it IS the caller's buffer size.)
	 */
	if (service != NULL) {
		parms.service_name = service;
		parms.service_name_len = strlen(service);
	}
	if (acname != NULL) {
		parms.ac_name = acname;
		parms.ac_name_len = strlen(acname);
	}
	if (ioctl(s, PPPOESETPARMS, &parms) < 0)
		err(1, "PPPOESETPARMS");
	return (0);
}
