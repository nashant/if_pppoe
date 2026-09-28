/*
 * spppauth - set/get the sppp auth config (SPPPSETAUTHCFG/SPPPGETAUTHCFG)
 * on an if_pppoe clone.  Stopgap for pppoectl(8) (plan 2, S05): it drives
 * the SPPP* auth ioctls the same way pppoectl's auth modes will, so the
 * live PAP/CHAP dials (S02 T2/T3) have a pppoectl-equivalent ioctl path.
 *
 *   printf '%s\n' SECRET | spppauth -m PAP -n USER -S pppoe0
 *                                               # set myauth (PAP); the
 *                                               # secret is one line on
 *                                               # stdin, never on argv
 *   spppauth -g pppoe0                          # get + print (name only,
 *                                                # NEVER the secret)
 *
 * Use -S (secret read from stdin, like pppoectl -S) so the secret never
 * appears in argv where ps/procstat can see it; the buffer is
 * explicit_bzero'd after the ioctl.  -s SECRET is kept only for manual
 * use and cannot be combined with -S.  Secrets are NEVER printed: the -g
 * dump prints myauth/hisauth protocols, flags and names only.
 * R011: no diagnostic message in this file contains a secret value.
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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
parse_proto(const char *s)
{
	if (s == NULL)
		return SPPP_AUTHPROTO_NOCHG;
	if (strcasecmp(s, "pap") == 0)
		return SPPP_AUTHPROTO_PAP;
	if (strcasecmp(s, "chap") == 0)
		return SPPP_AUTHPROTO_CHAP;
	if (strcasecmp(s, "none") == 0)
		return SPPP_AUTHPROTO_NONE;
	if (strcasecmp(s, "nochg") == 0)
		return SPPP_AUTHPROTO_NOCHG;
	errx(1, "unknown auth proto '%s' (pap|chap|none|nochg)", s);
}

static void
print_proto(const char *tag, u_int proto)
{
	switch (proto) {
	case SPPP_AUTHPROTO_PAP: printf("%s=pap", tag); break;
	case SPPP_AUTHPROTO_CHAP: printf("%s=chap", tag); break;
	case SPPP_AUTHPROTO_NONE: printf("%s=none", tag); break;
	case SPPP_AUTHPROTO_NOCHG: printf("%s=nochg", tag); break;
	default: printf("%s=<proto %u>", tag, proto); break;
	}
}

static void
usage(void)
{
	errx(1, "usage: spppauth [-g] [-m proto] [-n name] [-S | -s secret] "
	    "[-p proto] ifname\n"
	    "       (proto: pap|chap|none|nochg; -S reads the secret from "
	    "stdin;\n"
	    "        -g dumps, never the secret)");
}

int
main(int argc, char **argv)
{
	struct spppauthcfg cfg;
	char namebuf[64], hisnamebuf[64];
	const char *myproto_s = NULL, *myname = NULL, *mysecret = NULL;
	const char *hisproto_s = NULL;
	char *stdin_secret = NULL;
	bool secret_from_stdin = false;
	int c, get = 0, s, rc;

	while ((c = getopt(argc, argv, "gm:n:s:Sp:")) != -1) {
		switch (c) {
		case 'g': get = 1; break;
		case 'm': myproto_s = optarg; break;
		case 'n': myname = optarg; break;
		case 's': mysecret = optarg; break;
		case 'S': secret_from_stdin = true; break;
		case 'p': hisproto_s = optarg; break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();
	if (secret_from_stdin && mysecret != NULL)
		errx(1, "-S and -s are mutually exclusive");
	if (secret_from_stdin && get)
		errx(1, "-S and -g are mutually exclusive");

	/* -S: one line from stdin, trailing newline (and CR) stripped. */
	if (secret_from_stdin) {
		size_t n = 0;
		ssize_t slen = getline(&stdin_secret, &n, stdin);
		if (slen < 0)
			errx(1, "-S: no secret on stdin");
		if (slen > 0 && stdin_secret[slen - 1] == '\n')
			stdin_secret[--slen] = '\0';
		if (slen > 0 && stdin_secret[slen - 1] == '\r')
			stdin_secret[--slen] = '\0';
		mysecret = stdin_secret;
	}

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		err(1, "socket");

	memset(&cfg, 0, sizeof(cfg));
	strlcpy(cfg.ifname, argv[0], sizeof(cfg.ifname));

	if (get) {
		memset(namebuf, 0, sizeof(namebuf));
		memset(hisnamebuf, 0, sizeof(hisnamebuf));
		cfg.myname = namebuf;
		cfg.myname_length = sizeof(namebuf);
		cfg.hisname = hisnamebuf;
		cfg.hisname_length = sizeof(hisnamebuf);
		if (ioctl(s, SPPPGETAUTHCFG, &cfg) < 0)
			err(1, "SPPPGETAUTHCFG");
		printf("if=%s ", cfg.ifname);
		print_proto("myauth", cfg.myauth);
		printf(" myauthflags=0x%x myname=%s", cfg.myauthflags,
		    cfg.myname_length ? namebuf : "");
		printf(" ");
		print_proto("hisauth", cfg.hisauth);
		printf(" hisauthflags=0x%x hisname=%s\n", cfg.hisauthflags,
		    cfg.hisname_length ? hisnamebuf : "");
		return (0);
	}

	cfg.myauth = (u_int)parse_proto(myproto_s);
	cfg.hisauth = (u_int)parse_proto(hisproto_s);
	cfg.myname = (char *)myname;
	cfg.mysecret = (char *)mysecret;
	if (myname != NULL)
		cfg.myname_length = strlen(myname) + 1;
	if (mysecret != NULL)
		cfg.mysecret_length = strlen(mysecret) + 1;

	rc = ioctl(s, SPPPSETAUTHCFG, &cfg);
	if (stdin_secret != NULL) {
		explicit_bzero(stdin_secret, strlen(stdin_secret));
		free(stdin_secret);
		stdin_secret = NULL;
	}
	if (rc < 0)
		err(1, "SPPPSETAUTHCFG");
	printf("SPPPSETAUTHCFG ok on %s (secret not echoed)\n", argv[0]);
	return (0);
}