#include <sys/types.h>
#include <sys/stat.h>
#include "buffer.h"
#include "case.h"
#include "env.h"
#include "pathexec.h"
#include "str.h"
#include "strerr.h"
#include "version.h"

#define FATAL "rhostck: fatal: "
#define DENYMSG "-Suspicious hostname - I don't accept mails from hosts on dynamic IP addresses."

const char version[] = "rhostck " VERSION;

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
 * Compare all tokens of denyparts with the begining of start.
 * Return 1 if any of the tokens equals start and the next character
 * of start is not alphanumeric.
 */
unsigned int find_deny_token(const char *denyparts, const char *start)
{
    size_t i = 0, len = 0;
    const char *token = denyparts;

    for (;;) {
	if (!token[i])
	    len = i;
	else if (token[i] == ' ') {
	    len = i;
	    do { ++i; } while (token[i] == ' ');
	}
	else {
	    ++i;
	}
	if (len) {
	    if (case_diffb(start, len, token) == 0 && not_alphanumeric(start[len]))
		return 1;
	    token += i;
	    i = len = 0;
	}
	if (!*token) break;
    }

    return 0;
}

/*
 * Check TCPREMOTEHOST environment variable.
 * Return 1 if we consider this host's name an untrustfull source.
 */
int fishy_remotehost(const char *tcpremotehost)
{
    const char *t, *start, *dot1, *dot2, *denyparts;
    
    /* always block hosts w/o a hostname */
    if (tcpremotehost == 0 || *tcpremotehost == 0)  return 1;

    denyparts = env_get("RHOSTCK_DENYPARTS");

    if (!denyparts)
	return 0;

    /*
     * find dots in TCPREMOTEHOST
     * no dots: "localhost" -> block
     * one dot only: "name.tld" -> pass
     * two or more dots: "host.name.tld"
     *   -> check the part before the current first dot;
     *      if this is clean, search for more dots
     */

    t = tcpremotehost;
    start = tcpremotehost;
    dot1 = dot2 = 0;
    for (;;) {
	if (!*t) break;
	if (*t == '.') {
	    if (dot1)
		start = dot1 + 1;
	    dot1 = dot2;
	    dot2 = t;

	    /*
	     * look at part in front of first dot (dot1):
	     * 47-11-23.dialup.name.tld
	     */
	    if (dot1 && find_deny_token(denyparts, start))
		return 1;
	}
	++t;
    }

    if (!dot2) return 1;	// no dots -> bad name

    return 0;	// one dot only or no suspicious hostname parts detected
}

int main(int argc, char** argv)
{
    char *tcpremotehost;

    if (argc < 2)
	strerr_die2x(111, FATAL, "usage: rhostck program");

    if (fishy_remotehost(env_get("TCPREMOTEHOST"))) {
	char *rblmsg = env_get("RHOSTCK_DENYMSG");

	if (!rblmsg || !*rblmsg)
	    rblmsg = DENYMSG;

        pathexec_env("RBLSMTPD", rblmsg);
    }

    pathexec(argv + 1);

    strerr_die4sys(111, FATAL, "unable to start ", argv[1], ": ");
}
