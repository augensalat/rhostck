# Don't edit Makefile! Use conf-* for configuration.

SHELL=/bin/sh

default: it

alloc.o: \
compile alloc.c alloc.h error.h
	./compile alloc.c

alloc_re.o: \
compile alloc_re.c alloc.h byte.h
	./compile alloc_re.c

auto-str: \
load auto-str.o unix.a byte.a
	./load auto-str unix.a byte.a 

auto-str.o: \
compile auto-str.c buffer.h readwrite.h exit.h
	./compile auto-str.c

auto_home.c: \
auto-str conf-home
	./auto-str auto_home `head -1 conf-home` > auto_home.c

auto_home.o: \
compile auto_home.c
	./compile auto_home.c

buffer.o: \
compile buffer.c buffer.h
	./compile buffer.c

buffer_0.o: \
compile buffer_0.c readwrite.h buffer.h
	./compile buffer_0.c

buffer_1.o: \
compile buffer_1.c readwrite.h buffer.h
	./compile buffer_1.c

buffer_2.o: \
compile buffer_2.c readwrite.h buffer.h
	./compile buffer_2.c

buffer_copy.o: \
compile buffer_copy.c buffer.h
	./compile buffer_copy.c

buffer_get.o: \
compile buffer_get.c buffer.h byte.h error.h
	./compile buffer_get.c

buffer_put.o: \
compile buffer_put.c buffer.h str.h byte.h error.h
	./compile buffer_put.c

byte.a: \
makelib byte_chr.o byte_copy.o byte_cr.o byte_diff.o byte_rchr.o \
case_diffb.o fmt_ulong.o ip4_fmt.o \
ip4_scan.o scan_ulong.o str_chr.o str_diff.o str_len.o str_start.o \
uint16_pack.o uint16_unpack.o uint32_pack.o uint32_unpack.o
	./makelib byte.a byte_chr.o byte_copy.o byte_cr.o \
	byte_diff.o byte_rchr.o case_diffb.o \
	fmt_ulong.o ip4_fmt.o ip4_scan.o scan_ulong.o \
	str_chr.o str_diff.o str_len.o str_start.o uint16_pack.o \
	uint16_unpack.o uint32_pack.o uint32_unpack.o

byte_chr.o: \
compile byte_chr.c byte.h
	./compile byte_chr.c

byte_copy.o: \
compile byte_copy.c byte.h
	./compile byte_copy.c

byte_cr.o: \
compile byte_cr.c byte.h
	./compile byte_cr.c

byte_diff.o: \
compile byte_diff.c byte.h
	./compile byte_diff.c

byte_rchr.o: \
compile byte_rchr.c byte.h
	./compile byte_rchr.c

case_diffb.o: \
compile case_diffb.c case.h
	./compile case_diffb.c

choose: \
warn-auto.sh choose.sh conf-home
	cat warn-auto.sh choose.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> choose
	chmod 755 choose

clean:
	rm -f rhostck auto-str compile install load makelib \
	*.a *.o auto_home.c systype uint32.h version.h core *.core

commands.o: \
compile commands.c buffer.h stralloc.h gen_alloc.h str.h case.h \
commands.h
	./compile commands.c

compile: \
warn-auto.sh conf-cc
	( cat warn-auto.sh; \
	echo exec "`head -1 conf-cc`" '-c $${1+"$$@"}' \
	) > compile
	chmod 755 compile

env.o: \
compile env.c str.h env.h
	./compile env.c

error.o: \
compile error.c error.h
	./compile error.c

error_str.o: \
compile error_str.c error.h
	./compile error_str.c

fmt_ulong.o: \
compile fmt_ulong.c fmt.h
	./compile fmt_ulong.c

hier.o: \
compile hier.c auto_home.h
	./compile hier.c

install: \
load install.o hier.o auto_home.o unix.a byte.a
	./load install hier.o auto_home.o unix.a byte.a

install.o: \
compile install.c buffer.h strerr.h error.h open.h readwrite.h exit.h
	./compile install.c

ip4_fmt.o: \
compile ip4_fmt.c fmt.h ip4.h
	./compile ip4_fmt.c

ip4_scan.o: \
compile ip4_scan.c scan.h ip4.h
	./compile ip4_scan.c

it: \
prog install

load: \
warn-auto.sh conf-ld
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo exec "`head -1 conf-ld`" \
	'-o "$$main" "$$main".o $${1+"$$@"}' \
	) > load
	chmod 755 load

makelib: \
warn-auto.sh systype
	( cat warn-auto.sh; \
	echo 'main="$$1"; shift'; \
	echo 'rm -f "$$main"'; \
	echo 'ar cr "$$main" $${1+"$$@"}'; \
	case "`cat systype`" in \
	sunos-5.*) ;; \
	unix_sv*) ;; \
	irix64-*) ;; \
	irix-*) ;; \
	dgux-*) ;; \
	hp-ux-*) ;; \
	sco*) ;; \
	*) echo 'ranlib "$$main"' ;; \
	esac \
	) > makelib
	chmod 755 makelib

open_read.o: \
compile open_read.c open.h
	./compile open_read.c

open_trunc.o: \
compile open_trunc.c open.h
	./compile open_trunc.c

openreadclose.o: \
compile openreadclose.c error.h open.h readclose.h stralloc.h \
gen_alloc.h openreadclose.h stralloc.h
	./compile openreadclose.c

pathexec_env.o: \
compile pathexec_env.c stralloc.h gen_alloc.h alloc.h str.h byte.h \
env.h pathexec.h
	./compile pathexec_env.c

pathexec_run.o: \
compile pathexec_run.c error.h stralloc.h gen_alloc.h str.h env.h \
pathexec.h
	./compile pathexec_run.c

prog: \
rhostck

rhostck: \
load rhostck.o unix.a byte.a
	./load rhostck unix.a byte.a

rhostck.o: \
compile rhostck.c version.h
	./compile rhostck.c

rts: \
warn-auto.sh rts.sh conf-home
	cat warn-auto.sh rts.sh \
	| sed s}HOME}"`head -1 conf-home`"}g \
	> rts
	chmod 755 rts

scan_ulong.o: \
compile scan_ulong.c scan.h
	./compile scan_ulong.c

setup: \
it install
	./install

str_chr.o: \
compile str_chr.c str.h
	./compile str_chr.c

str_diff.o: \
compile str_diff.c str.h
	./compile str_diff.c

str_len.o: \
compile str_len.c str.h
	./compile str_len.c

str_start.o: \
compile str_start.c str.h
	./compile str_start.c

stralloc_cat.o: \
compile stralloc_cat.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_cat.c

stralloc_catb.o: \
compile stralloc_catb.c stralloc.h gen_alloc.h byte.h
	./compile stralloc_catb.c

stralloc_cats.o: \
compile stralloc_cats.c byte.h str.h stralloc.h gen_alloc.h
	./compile stralloc_cats.c

stralloc_copy.o: \
compile stralloc_copy.c byte.h stralloc.h gen_alloc.h
	./compile stralloc_copy.c

stralloc_eady.o: \
compile stralloc_eady.c alloc.h stralloc.h gen_alloc.h \
gen_allocdefs.h
	./compile stralloc_eady.c

stralloc_opyb.o: \
compile stralloc_opyb.c stralloc.h gen_alloc.h byte.h
	./compile stralloc_opyb.c

stralloc_opys.o: \
compile stralloc_opys.c byte.h str.h stralloc.h gen_alloc.h
	./compile stralloc_opys.c

stralloc_pend.o: \
compile stralloc_pend.c alloc.h stralloc.h gen_alloc.h \
gen_allocdefs.h
	./compile stralloc_pend.c

strerr_die.o: \
compile strerr_die.c buffer.h exit.h strerr.h
	./compile strerr_die.c

strerr_sys.o: \
compile strerr_sys.c error.h strerr.h
	./compile strerr_sys.c

systype: \
find-systype.sh conf-cc conf-ld trycpp.c x86cpuid.c
	( cat warn-auto.sh; \
	echo CC=\'`head -1 conf-cc`\'; \
	echo LD=\'`head -1 conf-ld`\'; \
	cat find-systype.sh; \
	) | sh > systype

uint16_pack.o: \
compile uint16_pack.c uint16.h
	./compile uint16_pack.c

uint16_unpack.o: \
compile uint16_unpack.c uint16.h
	./compile uint16_unpack.c

uint32.h: \
tryulong32.c compile load uint32.h1 uint32.h2
	( ( ./compile tryulong32.c && ./load tryulong32 && \
	./tryulong32 ) >/dev/null 2>&1 \
	&& cat uint32.h2 || cat uint32.h1 ) > uint32.h
	rm -f tryulong32.o tryulong32

uint32_pack.o: \
compile uint32_pack.c uint32.h
	./compile uint32_pack.c

uint32_unpack.o: \
compile uint32_unpack.c uint32.h
	./compile uint32_unpack.c

uint64.h: \
choose compile load tryulong64.c uint64.h1 uint64.h2
	./choose clr tryulong64 uint64.h1 uint64.h2 > uint64.h

unix.a: \
makelib alloc.o alloc_re.o buffer.o buffer_0.o buffer_1.o buffer_2.o \
buffer_copy.o buffer_get.o buffer_put.o env.o error.o error_str.o \
open_read.o open_trunc.o openreadclose.o pathexec_env.o \
pathexec_env.o pathexec_run.o \
stralloc_cat.o stralloc_catb.o stralloc_cats.o stralloc_copy.o \
stralloc_eady.o stralloc_opyb.o stralloc_opys.o stralloc_pend.o \
strerr_die.o strerr_sys.o
	./makelib unix.a alloc.o alloc_re.o buffer.o buffer_0.o \
	buffer_1.o buffer_2.o buffer_copy.o buffer_get.o \
	buffer_put.o env.o error.o error_str.o open_read.o \
	open_trunc.o openreadclose.o pathexec_env.o \
	pathexec_env.o pathexec_run.o \
	stralloc_cat.o stralloc_catb.o stralloc_cats.o \
	stralloc_copy.o stralloc_eady.o stralloc_opyb.o \
	stralloc_opys.o stralloc_pend.o strerr_die.o strerr_sys.o

version.h: \
CHANGES
	(head -n 1 CHANGES | sed 's/\([^ \t]*\).*/#define VERSION "\1"/') \
	> version.h
