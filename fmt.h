#ifndef FMT_H
#define FMT_H

/* for size_t: */
#include <stddef.h>
/* for time_t: */
#include <sys/types.h>

#define FMT_ULONG 40 /* enough space to hold 2^128 - 1 in decimal, plus \0 */
#define FMT_LEN ((char *) 0) /* convenient abbreviation */

extern size_t fmt_uint(char *,unsigned int);
extern size_t fmt_uint0(char *,unsigned int,unsigned int);
extern size_t fmt_xint(char *,unsigned int);
extern size_t fmt_nbbint(char *,unsigned int,unsigned int,unsigned int,unsigned int);
extern size_t fmt_ushort(char *,unsigned short);
extern size_t fmt_xshort(char *,unsigned short);
extern size_t fmt_nbbshort(char *,unsigned int,unsigned int,unsigned int,unsigned short);
extern size_t fmt_ulong(char *,unsigned long);
extern size_t fmt_xlong(char *,unsigned long);
extern size_t fmt_nbblong(char *,unsigned int,unsigned int,unsigned int,unsigned long);

extern size_t fmt_plusminus(char *,int);
extern size_t fmt_minus(char *,int);
extern size_t fmt_0x(char *,int);

extern size_t fmt_str(char *,char *);
extern size_t fmt_strn(char *,char *,unsigned int);

#endif
