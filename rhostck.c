#include <sys/types.h>
#include <sys/stat.h>
#include "buffer.h"
#include "case.h"
#include "env.h"
#include "fmt.h"
#include "hasinline.h"
#include "ip4.h"
#include "pathexec.h"
#include "str.h"
#include "stralloc.h"
#include "strerr.h"
#include "version.h"

#define FATAL "rhostck: fatal: "
#define DENYMSG "-Suspicious hostname - I don't accept mails from hosts on dynamic IP addresses."

const char version[] = "rhostck " VERSION;

char *tcpremoteip;
char *tcpremotehost;
char ip[4] = { 0, 0, 0, 0 };
char strnum[FMT_ULONG];
static stralloc relevant_hostname_part;
char ip_permuted[IP4_FMT];

void nomem(void)
{
    strerr_die2x(111, FATAL, "out of memory");
}

static inline char tohex(char c) {
    return c >= 10 ? c-10 + 'a' : c + '0';
}

/*
 * Check the given character.
 * Return 0 if character is between '0' and '9', else return 1.
 */
int not_numeric(unsigned char c)
{
    register unsigned char x = c - '0';

    return (x > '9' - '0');
}

/*
 * Check the given character. Return 0 if character is between 'A' and 'Z'
 * or 'a' and 'z' or '0' and '9'. Return 1 otherwise.
 */
int not_alphanumeric(unsigned char c)
{
    register unsigned char x;

    x = c - 'A';
    if (x <= 'Z' - 'A') return 0;
    x = c - 'a';
    if (x <= 'z' - 'a') return 0;

    return not_numeric(c);
}

/*
 * Check the given character. Return 0 if character is between 'A' and 'F'
 * or 'a' and 'z' or '0' and '9'. Return 1 otherwise.
 */
int not_hexanumeric(unsigned char c)
{
    register unsigned char x;

    x = c - 'A';
    if (x <= 'F' - 'A') return 0;
    x = c - 'a';
    if (x <= 'f' - 'a') return 0;

    return not_numeric(c);
}

/*
 * ip_start returns 1 if 2nd argument is a prefix of the first, 0 otherwise.
 * Characters '.' and '-' are treated as equal!
 */
int ip_start(register const char *s,register const char *t)
{
  register char x;
  register char y;

  for (;;) {
    x = *t++; if (!x) return 1; y = *s++; if (y == '-') y = '.'; if (x != y) return 0;
    x = *t++; if (!x) return 1; y = *s++; if (y == '-') y = '.'; if (x != y) return 0;
  }
}
/*
 */
int find_ip(const char *name, const char *ip, int (*not_chartype)(unsigned char))
{
    char c = *ip;
    size_t p, pp;
    size_t iplen = str_len(ip);

#if 0
buffer_puts(buffer_1,"hostname part: ");
buffer_puts(buffer_1,name);
buffer_puts(buffer_1,"\n");
buffer_puts(buffer_1,"ip part: ");
buffer_puts(buffer_1,ip);
buffer_putsflush(buffer_1,"\n");
#endif

    for (p = 0; name[p]; ++p) {
	pp = str_chr(name + p, c);
	p += pp;
	if (!name[p]) break;
	if (ip_start(name + p, ip)) {
	    if ((!p || (*not_chartype)(name[p-1])) && (*not_chartype)(name[p + iplen]))
		return 1;
	}
    }
    return 0;
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
int fishy_remotehost(void)
{
    const char *t, *denyparts;
    int start;

    denyparts = env_get("RHOSTCK_DENYPARTS");
    if (!denyparts) return 0;

    while (*denyparts == ' ') ++denyparts;	// skip leading spaces

    /*
     * Split relevant part of remote hostname at dots and compare
     * beginning of each part with all tokens in $RHOSTCK_DENYPARTS.
     * Return true if any part begins with any token, else false.
     */

    for (start = 1, t = relevant_hostname_part.s; *t; ++t)
	if (*t == '.')
	    start = 1;
	else
	    if (start) {
		if (find_deny_token(denyparts, t))
		    return 1;
		start = 0;
	    }

    return 0;	// one dot only or no suspicious hostname parts detected
}

/*
 */
int ip_in_hostname(void)
{
    const char *tuples;
    char *s;
    unsigned long n;	// 2, 3 or 4
    size_t pos;
    unsigned long numlen;
    unsigned int i;
    const char *name = relevant_hostname_part.s;
    unsigned char c;

    s = env_get("RHOSTCK_IPHOSTNAME");

    if (!s)
	return 0;

    if (!scan_ulong(s, &n) || n < 2 || n > 4)
	return 0;

    // try to find the verbatim IP address (part) in hostname
    s = tcpremoteip;
    for (i = 4; i > n; --i)
	s += str_chr(s, '.') + 1;

    if (find_ip(name, s, not_numeric)) return 1;

    tuples = ip + (4 - n);

    // reverse ip
    s = ip_permuted;
    i = n - 1;
    for (;;) {
	s += fmt_ulong(s, (unsigned long)(unsigned char)tuples[i]);
	if (!i--) break;
	*s++ = '.';
    }
    *s++ = 0;

    if (find_ip(name, ip_permuted, not_numeric)) return 1;

    // ip with each number pre-padded with 0s to 3 bytes w/o stop bytes
    s = ip_permuted;
    for (i = 0; i < n; ++i) {
	c = tuples[i];
	pos = 3 - fmt_ulong(0, (unsigned long)c);
	while (pos--) *s++ = '0';
	s += fmt_ulong(s, (unsigned long)c);
    }
    *s = 0;

    if (find_ip(name, ip_permuted, not_numeric)) return 1;

    // ip with each number pre-padded with 0s to 3 bytes w/o stop bytes reversed
    s = ip_permuted;
    i = n - 1;
    do {
	c = tuples[i];
	pos = 3 - fmt_ulong(0, (unsigned long)c);
	while (pos--) *s++ = '0';
	s += fmt_ulong(s, (unsigned long)c);
    } while (i--);
    *s = 0;

    if (find_ip(name, ip_permuted, not_numeric)) return 1;

    // hex ip
    s = ip_permuted;
    for (i = 0; i < n; ++i) {
	c = tuples[i];
	*s++ = tohex(c >> 4);
	*s++ = tohex(c & 15);
    }
    *s = 0;

    if (find_ip(name, ip_permuted, not_hexanumeric)) return 1;

    // hex ip reversed
    s = ip_permuted;
    i = n - 1;
    do {
	c = tuples[i];
	*s++ = tohex(c >> 4);
	*s++ = tohex(c & 15);
    } while (i--);
    *s = 0;

    if (find_ip(name, ip_permuted, not_hexanumeric)) return 1;

    // hex ip with dots/dashes
    s = ip_permuted;
    i = 0;
    for (;;) {
	c = tuples[i];
	*s++ = tohex(c >> 4);
	*s++ = tohex(c & 15);
	if (++i >= n) break;
	*s++ = '.';
    }
    *s = 0;

    if (find_ip(name, ip_permuted, not_hexanumeric)) return 1;

    // hex ip reversed with dots/dashes
    s = ip_permuted;
    i = n - 1;
    for (;;) {
	c = tuples[i];
	*s++ = tohex(c >> 4);
	*s++ = tohex(c & 15);
	if (!i--) break;
	*s++ = '.';
    }
    *s = 0;

    if (find_ip(name, ip_permuted, not_hexanumeric)) return 1;

    return 0;
}

int main(int argc, char** argv)
{
    const char *t, *dot1, *dot2;

    if (argc < 2)
	strerr_die1x(100, "rhostck: usage: rhostck program");

    tcpremoteip = env_get("TCPREMOTEIP");
    if (!tcpremoteip) tcpremoteip = "";

    if (!ip4_scan(tcpremoteip, ip))
	strerr_die2x(111, FATAL, "TCPREMOTEIP not set or not an IPv4 address");

    tcpremotehost = env_get("TCPREMOTEHOST");
    if (!tcpremotehost) tcpremotehost = "";

    // find dots in TCPREMOTEHOST
    // no dots: "localhost" -> block
    // one dot only: "name.tld" -> pass
    // two or more dots: "host.name.tld"
     
    t = tcpremotehost;
    dot1 = dot2 = 0;
    for (;;) {
	if (!*t) break;
	if (*t == '.') {
	    dot1 = dot2;
	    dot2 = t;
	}
	++t;
    }

    if (dot1) {
	// save string in front of penultimate dot.
	if (!stralloc_copyb(&relevant_hostname_part, tcpremotehost, (dot1 - tcpremotehost)))
	    nomem();
	if (!stralloc_0(&relevant_hostname_part)) nomem();
    }


    // !dot2 means: no dot exists in remote hostname -> bad hostname
    // dot1 means: at least two dots in gostname
    if (!dot2 || (dot1 && (fishy_remotehost() || ip_in_hostname()))) {
	char *rblmsg = env_get("RHOSTCK_DENYMSG");

	if (!rblmsg || !*rblmsg)
	    rblmsg = DENYMSG;

        pathexec_env("RBLSMTPD", rblmsg);
    }

    pathexec(argv + 1);

    strerr_die4sys(111, FATAL, "unable to start ", argv[1], ": ");
}
