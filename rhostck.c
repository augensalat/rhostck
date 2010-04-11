#include "case.h"
#include "env.h"
#include "pathexec.h"
#include "str.h"
#include "strerr.h"

#define FATAL "rhostck: fatal: "

const char * const fishy[15] = {
    "adsl",
    "dsl",
    "dynamicip",
    "dynamic",
    "dyn",
    "pppoe",
    "ppp",
    "dialin",
    "dialup",
    "dial",
    "pool",
    "pools",
    "dhcp",
    "cable",
    "cust",
};

/*
 * Check the given character. Return 0 if character is between 'A' and 'Z'
 * or 'a' and 'z' or '0' and '9'. Return 1 otherwise.
 */
unsigned int not_alphanumeric(unsigned char c)
{
    register unsigned char x;

    x = c - 'A';
    if (x <= 'Z' - 'A') return 0;
    x = c - 'a';
    if (x <= 'z' - 'a') return 0;
    x = c - '0';
    if (x <= '9' - '0') return 0;
    return 1;
}

/*
 * Check TCPREMOTEHOST environment variable.
 * Return 0 if we consider this host's name a untrustfull source.
 */
int check_remotehost(const char *tcpremotehost)
{
    int unsigned f;
    const char *t, *start, *dot1, *dot2;
    char c;
    int unsigned i;
    
    if (tcpremotehost == 0 || *tcpremotehost == 0)  return 0;

    /*
     * find dots in TCPREMOTEHOST
     * no dots: "localhost" -> block
     * one dot only: "name.tld" -> pass
     * two or more dots: "host.name.tld" -> find position of second last dot
     */
    t = tcpremotehost;
    dot1 = dot2 = start = 0;
    for (;;) {
	if (!*t) break;
	if (*t == '.') {
	    start = dot1;
	    dot1 = dot2;
	    dot2 = t;
	}
	++t;
    }
    if (!dot2) return 0;	/* no dots */
    if (!dot1) return 1;	/* one dot only */
    if (!start) start = tcpremotehost;

    /*
     * look at part in front of second last dot (dot1):
     * 47-11-23.dialup.name.tld
     */
    for (f = 0; f < 15; ++f) {
	if (case_starts(start, fishy[f]) && not_alphanumeric(start[str_len(fishy[f])]))
	    return 0;
    }

    return 1;
}

int main(int argc, char* argv[])
{
    char *tcpremotehost;

    if (argc < 2)
	strerr_die2x(111, FATAL, "usage: rhostck program [arguments]");

    if (check_remotehost(env_get("TCPREMOTEHOST")) == 0)
        pathexec_env(
	    "RBLSMTPD",
	    "Suspicious hostname - I don't accept mails from hosts on dynamic IP addresses."
	);

    pathexec(argv + 1);

    strerr_die4sys(111, FATAL, "unable to start ", argv + 1, ": ");
}
