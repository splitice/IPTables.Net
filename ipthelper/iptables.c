/* Code to take an iptables-style command line and do it. */

/*
 * Author: Paul.Russell@rustcorp.com.au and mneuling@radlogic.com.au
 *
 * (C) 2000-2002 by the netfilter coreteam <coreteam@netfilter.org>:
 * 		    Paul 'Rusty' Russell <rusty@rustcorp.com.au>
 * 		    Marc Boucher <marc+nf@mbsi.ca>
 * 		    James Morris <jmorris@intercode.com.au>
 * 		    Harald Welte <laforge@gnumonks.org>
 * 		    Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program; if not, write to the Free Software
 *	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <getopt.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <unistd.h>
#include <iptables.h>
#include <xtables.h>
#include <fcntl.h>
#include <assert.h>
#ifdef __cplusplus
#include <stdexcept>
#include <string>
#endif
#include "ipthelper.h"
#include "xshared.h"
#include <setjmp.h>

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define FMT_NUMERIC	0x0001
#define FMT_NOCOUNTS	0x0002
#define FMT_KILOMEGAGIGA 0x0004
#define FMT_OPTIONS	0x0008
#define FMT_NOTABLE	0x0010
#define FMT_NOTARGET	0x0020
#define FMT_VIA		0x0040
#define FMT_NONEWLINE	0x0080
#define FMT_LINENUMBERS 0x0100

#define FMT_PRINT_RULE (FMT_NOCOUNTS | FMT_OPTIONS | FMT_VIA \
			| FMT_NUMERIC | FMT_NOTABLE)
#define FMT(tab,notab) ((format) & FMT_NOTABLE ? (notab) : (tab))


#define CMD_NONE		0x0000U
#define CMD_INSERT		0x0001U
#define CMD_DELETE		0x0002U
#define CMD_DELETE_NUM		0x0004U
#define CMD_REPLACE		0x0008U
#define CMD_APPEND		0x0010U
#define CMD_LIST		0x0020U
#define CMD_FLUSH		0x0040U
#define CMD_ZERO		0x0080U
#define CMD_NEW_CHAIN		0x0100U
#define CMD_DELETE_CHAIN	0x0200U
#define CMD_SET_POLICY		0x0400U
#define CMD_RENAME_CHAIN	0x0800U
#define CMD_LIST_RULES		0x1000U
#define CMD_ZERO_NUM		0x2000U
#define CMD_CHECK		0x4000U
#define NUMBER_OF_CMD	16
static const char cmdflags[] = { 'I', 'D', 'D', 'R', 'A', 'L', 'F', 'Z',
				 'Z', 'N', 'X', 'P', 'E', 'S', 'C' };

static const char optflags[]
= { 'n', 's', 'd', 'p', 'j', 'v', 'x', 'i', 'o', '0', 'c', 'f' };

#define NUMBER_OF_OPT	sizeof(optflags)

#define OPT_FRAGMENT    0x00800U

extern jmp_buf buf;
extern char* errbuffer;
#define UPGRADE_MSG "Perhaps iptables or your kernel needs to be upgraded."

void iptables_exit_error(enum xtables_exittype status, const char *msg, ...) __attribute__((noreturn, format(printf, 2, 3)));

static struct option original_opts[] = {
	{ .name = "append", .has_arg = 1, .flag=0, .val = 'A' },
	{ .name = "delete", .has_arg = 1, .flag = 0, .val = 'D' },
	{ .name = "check", .has_arg = 1, .flag = 0, .val = 'C' },
	{ .name = "insert", .has_arg = 1, .flag = 0, .val = 'I' },
	{ .name = "replace", .has_arg = 1, .flag = 0, .val = 'R' },
	{ .name = "list", .has_arg = 2, .flag = 0, .val = 'L' },
	{ .name = "list-rules", .has_arg = 2, .flag = 0, .val = 'S' },
	{ .name = "flush", .has_arg = 2, .flag = 0, .val = 'F' },
	{ .name = "zero", .has_arg = 2, .flag = 0, .val = 'Z' },
	{ .name = "new-chain", .has_arg = 1, .flag = 0, .val = 'N' },
	{ .name = "delete-chain", .has_arg = 2, .flag = 0, .val = 'X' },
	{ .name = "rename-chain", .has_arg = 1, .flag = 0, .val = 'E' },
	{ .name = "policy", .has_arg = 1, .flag = 0, .val = 'P' },
	{ .name = "source", .has_arg = 1, .flag = 0, .val = 's' },
	{ .name = "destination", .has_arg = 1, .flag = 0, .val = 'd' },
	{ .name = "src", .has_arg = 1, .flag = 0, .val = 's' }, /* synonym */
	{ .name = "dst", .has_arg = 1, .flag = 0, .val = 'd' }, /* synonym */
	{ .name = "protocol", .has_arg = 1, .flag = 0, .val = 'p' },
	{ .name = "in-interface", .has_arg = 1, .flag = 0, .val = 'i' },
	{ .name = "jump", .has_arg = 1, .flag = 0, .val = 'j' },
	{ .name = "table", .has_arg = 1, .flag = 0, .val = 't' },
	{ .name = "match", .has_arg = 1, .flag = 0, .val = 'm' },
	{ .name = "numeric", .has_arg = 0, .flag = 0, .val = 'n' },
	{ .name = "out-interface", .has_arg = 1, .flag = 0, .val = 'o' },
	{ .name = "verbose", .has_arg = 0, .flag = 0, .val = 'v' },
	{ .name = "exact", .has_arg = 0, .flag = 0, .val = 'x' },
	{ .name = "fragments", .has_arg = 0, .flag = 0, .val = 'f' },
	{ .name = "version", .has_arg = 0, .flag = 0, .val = 'V' },
	{ .name = "help", .has_arg = 2, .flag = 0, .val = 'h' },
	{ .name = "line-numbers", .has_arg = 0, .flag = 0, .val = '0' },
	{ .name = "modprobe", .has_arg = 1, .flag = 0, .val = 'M' },
	{ .name = "set-counters", .has_arg = 1, .flag = 0, .val = 'c' },
	{ .name = "goto", .has_arg = 1, .flag = 0, .val = 'g' },
	{ .name = "ipv4", .has_arg = 0, .flag = 0, .val = '4' },
	{ .name = "ipv6", .has_arg = 0, .flag = 0, .val = '6' },
	{ NULL },
};

struct xtables_globals iptables_globals = {
	.option_offset = 0,
	.program_name = "IPTables.Net(adapter)",
	.program_version = "1.1.1",
	.orig_opts = original_opts,
	.opts = NULL,
	.exit_err = iptables_exit_error
};

void
iptables_exit_error(enum xtables_exittype status, const char *msg, ...)
{
	va_list args;
	int buffer_length;
	
	if(errbuffer != NULL){
		free(errbuffer);
		errbuffer = NULL;
	}

	va_start(args, msg);
	buffer_length = vsprintf(NULL, msg, args);
	errbuffer = malloc(buffer_length + 100);
	vsprintf(errbuffer, msg, args);
	va_end(args);

	if (status == VERSION_PROBLEM){
		memcpy(errbuffer + buffer_length, UPGRADE_MSG, sizeof(UPGRADE_MSG));
	}
	/* On error paths, make sure that we don't leak memory */
	xtables_free_opts(1);

	longjmp(buf,1);
}

/* Primitive headers... */
/* defined in netinet/in.h */
#if 0
#ifndef IPPROTO_ESP
#define IPPROTO_ESP 50
#endif
#ifndef IPPROTO_AH
#define IPPROTO_AH 51
#endif
#endif

enum {
	IPT_DOTTED_ADDR = 0,
	IPT_DOTTED_MASK
};


/* Table of legal combinations of commands and options.  If any of the
* given commands make an option legal, that option is legal (applies to
* CMD_LIST and CMD_ZERO only).
* Key:
*  +  compulsory
*  x  illegal
*     optional
*/

static const char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] =
/* Well, it's better than "Re: Linux vs FreeBSD" */
{
	/*     -n  -s  -d  -p  -j  -v  -x  -i  -o --line -c -f */
	/*INSERT*/{ 'x', ' ', ' ', ' ', ' ', ' ', 'x', ' ', ' ', 'x', ' ', ' ' },
	/*DELETE*/{ 'x', ' ', ' ', ' ', ' ', ' ', 'x', ' ', ' ', 'x', 'x', ' ' },
	/*DELETE_NUM*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*REPLACE*/{ 'x', ' ', ' ', ' ', ' ', ' ', 'x', ' ', ' ', 'x', ' ', ' ' },
	/*APPEND*/{ 'x', ' ', ' ', ' ', ' ', ' ', 'x', ' ', ' ', 'x', ' ', ' ' },
	/*LIST*/{ ' ', 'x', 'x', 'x', 'x', ' ', ' ', 'x', 'x', ' ', 'x', 'x' },
	/*FLUSH*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*ZERO*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*ZERO_NUM*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*NEW_CHAIN*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*DEL_CHAIN*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*SET_POLICY*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', ' ', 'x' },
	/*RENAME*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*LIST_RULES*/{ 'x', 'x', 'x', 'x', 'x', ' ', 'x', 'x', 'x', 'x', 'x', 'x' },
	/*CHECK*/{ 'x', ' ', ' ', ' ', ' ', ' ', 'x', ' ', ' ', 'x', 'x', ' ' },
};

static const int inverse_for_options[NUMBER_OF_OPT] =
{
	/* -n */ 0,
	/* -s */ IPT_INV_SRCIP,
	/* -d */ IPT_INV_DSTIP,
	/* -p */ XT_INV_PROTO,
	/* -j */ 0,
	/* -v */ 0,
	/* -x */ 0,
	/* -i */ IPT_INV_VIA_IN,
	/* -o */ IPT_INV_VIA_OUT,
	/*--line*/ 0,
	/* -c */ 0,
	/* -f */ IPT_INV_FRAG,
};


static char
opt2char(int option)
{
	const char *ptr;
	for (ptr = optflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static char
cmd2char(int option)
{
	const char *ptr;
	for (ptr = cmdflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static void
set_option(unsigned int *options, unsigned int option, uint8_t *invflg,
int invert)
{
	if (*options & option)
		xtables_error(PARAMETER_PROBLEM, "multiple -%c flags not allowed",
		opt2char(option));
	*options |= option;

	if (invert) {
		unsigned int i;
		for (i = 0; 1 << i != option; i++);

		if (!inverse_for_options[i])
			xtables_error(PARAMETER_PROBLEM,
			"cannot have ! before -%c",
			opt2char(option));
		*invflg |= inverse_for_options[i];
	}
}


static void
generic_opt_check(int command, int options)
{
	int i, j, legal = 0;

	/* Check that commands are valid with options.  Complicated by the
	* fact that if an option is legal with *any* command given, it is
	* legal overall (ie. -z and -l).
	*/
	for (i = 0; i < NUMBER_OF_OPT; i++) {
		legal = 0; /* -1 => illegal, 1 => legal, 0 => undecided. */

		for (j = 0; j < NUMBER_OF_CMD; j++) {
			if (!(command & (1 << j)))
				continue;

			if (!(options & (1 << i))) {
				if (commands_v_options[j][i] == '+')
					xtables_error(PARAMETER_PROBLEM,
					"You need to supply the `-%c' "
					"option for this command\n",
					optflags[i]);
			}
			else {
				if (commands_v_options[j][i] != 'x')
					legal = 1;
				else if (legal == 0)
					legal = -1;
			}
		}
		if (legal == -1)
			xtables_error(PARAMETER_PROBLEM,
			"Illegal option `-%c' with this command\n",
			optflags[i]);
	}
}

static void
add_command(unsigned int *cmd, const int newcmd, const int othercmds, 
	    int invert)
{
	if (invert)
		xtables_error(PARAMETER_PROBLEM, "unexpected ! flag");
	if (*cmd & (~othercmds))
		xtables_error(PARAMETER_PROBLEM, "Cannot use -%c with -%c\n",
			   cmd2char(newcmd), cmd2char(*cmd & (~othercmds)));
	*cmd |= newcmd;
}

/*
 *	All functions starting with "parse" should succeed, otherwise
 *	the program fails.
 *	Most routines return pointers to static data that may change
 *	between calls to the same or other routines with a few exceptions:
 *	"host_to_addr", "parse_hostnetwork", and "parse_hostnetworkmask"
 *	return global static data.
*/

/* Christophe Burki wants `-p 6' to imply `-m tcp'.  */
/* Can't be zero. */
static int
parse_rulenumber(const char *rule)
{
	unsigned int rulenum;

	if (!xtables_strtoui(rule, NULL, &rulenum, 1, INT_MAX))
		xtables_error(PARAMETER_PROBLEM,
			   "Invalid rule number `%s'", rule);

	return rulenum;
}

static const char *
parse_target(const char *targetname)
{
	const char *ptr;

	if (strlen(targetname) < 1)
		xtables_error(PARAMETER_PROBLEM,
			   "Invalid target name (too short)");

	if (strlen(targetname) >= XT_EXTENSION_MAXNAMELEN)
		xtables_error(PARAMETER_PROBLEM,
			   "Invalid target name `%s' (%u chars max)",
			   targetname, XT_EXTENSION_MAXNAMELEN - 1);

	for (ptr = targetname; *ptr; ptr++)
		if (isspace(*ptr))
			xtables_error(PARAMETER_PROBLEM,
				   "Invalid target name `%s'", targetname);
	return targetname;
}

static void
print_num(uint64_t number, unsigned int format)
{
	if (format & FMT_KILOMEGAGIGA) {
		if (number > 99999) {
			number = (number + 500) / 1000;
			if (number > 9999) {
				number = (number + 500) / 1000;
				if (number > 9999) {
					number = (number + 500) / 1000;
					if (number > 9999) {
						number = (number + 500) / 1000;
						printf(FMT("%4lluT ","%lluT "), (unsigned long long)number);
					}
					else printf(FMT("%4lluG ","%lluG "), (unsigned long long)number);
				}
				else printf(FMT("%4lluM ","%lluM "), (unsigned long long)number);
			} else
				printf(FMT("%4lluK ","%lluK "), (unsigned long long)number);
		} else
			printf(FMT("%5llu ","%llu "), (unsigned long long)number);
	} else
		printf(FMT("%8llu ","%llu "), (unsigned long long)number);
}


static void
print_header(unsigned int format, const char *chain, struct xtc_handle *handle)
{
	struct xt_counters counters;
	const char *pol = iptc_get_policy(chain, &counters, handle);
	printf("Chain %s", chain);
	if (pol) {
		printf(" (policy %s", pol);
		if (!(format & FMT_NOCOUNTS)) {
			fputc(' ', stdout);
			print_num(counters.pcnt, (format|FMT_NOTABLE));
			fputs("packets, ", stdout);
			print_num(counters.bcnt, (format|FMT_NOTABLE));
			fputs("bytes", stdout);
		}
		printf(")\n");
	} else {
		unsigned int refs;
		if (!iptc_get_references(&refs, chain, handle))
			printf(" (ERROR obtaining refs)\n");
		else
			printf(" (%u references)\n", refs);
	}

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4s ", "%s "), "num");
	if (!(format & FMT_NOCOUNTS)) {
		if (format & FMT_KILOMEGAGIGA) {
			printf(FMT("%5s ","%s "), "pkts");
			printf(FMT("%5s ","%s "), "bytes");
		} else {
			printf(FMT("%8s ","%s "), "pkts");
			printf(FMT("%10s ","%s "), "bytes");
		}
	}
	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ","%s "), "target");
	fputs(" prot ", stdout);
	if (format & FMT_OPTIONS)
		fputs("opt", stdout);
	if (format & FMT_VIA) {
		printf(FMT(" %-6s ","%s "), "in");
		printf(FMT("%-6s ","%s "), "out");
	}
	printf(FMT(" %-19s ","%s "), "source");
	printf(FMT(" %-19s "," %s "), "destination");
	printf("\n");
}


static int
print_match(const struct xt_entry_match *m,
	    const struct ipt_ip *ip,
	    int numeric)
{
	const struct xtables_match *match =
		xtables_find_match(m->u.user.name, XTF_TRY_LOAD, NULL);

	if (match) {
		if (match->print)
			match->print(ip, m, numeric);
		else
			printf("%s ", match->name);
	} else {
		if (m->u.user.name[0])
			printf("UNKNOWN match `%s' ", m->u.user.name);
	}
	/* Don't stop iterating. */
	return 0;
}

/* e is called `fw' here for historical reasons */
static void
print_firewall(const struct ipt_entry *fw,
	       const char *targname,
	       unsigned int num,
	       unsigned int format,
	       struct xtc_handle *const handle)
{
	const struct xtables_target *target = NULL;
	const struct xt_entry_target *t;
	uint8_t flags;
	char buf[BUFSIZ];

	if (!iptc_is_chain(targname, handle))
		target = xtables_find_target(targname, XTF_TRY_LOAD);
	else
		target = xtables_find_target(XT_STANDARD_TARGET,
		         XTF_LOAD_MUST_SUCCEED);

	t = ipt_get_target((struct ipt_entry *)fw);
	flags = fw->ip.flags;

	if (format & FMT_LINENUMBERS)
		printf(FMT("%-4u ", "%u "), num);

	if (!(format & FMT_NOCOUNTS)) {
		print_num(fw->counters.pcnt, format);
		print_num(fw->counters.bcnt, format);
	}

	if (!(format & FMT_NOTARGET))
		printf(FMT("%-9s ", "%s "), targname);

	fputc(fw->ip.invflags & XT_INV_PROTO ? '!' : ' ', stdout);
	{
		const char *pname = proto_to_name(fw->ip.proto, format&FMT_NUMERIC);
		if (pname)
			printf(FMT("%-5s", "%s "), pname);
		else
			printf(FMT("%-5hu", "%hu "), fw->ip.proto);
	}

	if (format & FMT_OPTIONS) {
		if (format & FMT_NOTABLE)
			fputs("opt ", stdout);
		fputc(fw->ip.invflags & IPT_INV_FRAG ? '!' : '-', stdout);
		fputc(flags & IPT_F_FRAG ? 'f' : '-', stdout);
		fputc(' ', stdout);
	}

	if (format & FMT_VIA) {
		char iface[IFNAMSIZ+2];

		if (fw->ip.invflags & IPT_INV_VIA_IN) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ip.iniface[0] != '\0') {
			strcat(iface, fw->ip.iniface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT(" %-6s ","in %s "), iface);

		if (fw->ip.invflags & IPT_INV_VIA_OUT) {
			iface[0] = '!';
			iface[1] = '\0';
		}
		else iface[0] = '\0';

		if (fw->ip.outiface[0] != '\0') {
			strcat(iface, fw->ip.outiface);
		}
		else if (format & FMT_NUMERIC) strcat(iface, "*");
		else strcat(iface, "any");
		printf(FMT("%-6s ","out %s "), iface);
	}

	fputc(fw->ip.invflags & IPT_INV_SRCIP ? '!' : ' ', stdout);
	if (fw->ip.smsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","%s "), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf, xtables_ipaddr_to_numeric(&fw->ip.src));
		else
			strcpy(buf, xtables_ipaddr_to_anyname(&fw->ip.src));
		strcat(buf, xtables_ipmask_to_numeric(&fw->ip.smsk));
		printf(FMT("%-19s ","%s "), buf);
	}

	fputc(fw->ip.invflags & IPT_INV_DSTIP ? '!' : ' ', stdout);
	if (fw->ip.dmsk.s_addr == 0L && !(format & FMT_NUMERIC))
		printf(FMT("%-19s ","-> %s"), "anywhere");
	else {
		if (format & FMT_NUMERIC)
			strcpy(buf, xtables_ipaddr_to_numeric(&fw->ip.dst));
		else
			strcpy(buf, xtables_ipaddr_to_anyname(&fw->ip.dst));
		strcat(buf, xtables_ipmask_to_numeric(&fw->ip.dmsk));
		printf(FMT("%-19s ","-> %s"), buf);
	}

	if (format & FMT_NOTABLE)
		fputs("  ", stdout);

#ifdef IPT_F_GOTO
	if(fw->ip.flags & IPT_F_GOTO)
		printf("[goto] ");
#endif

	IPT_MATCH_ITERATE(fw, print_match, &fw->ip, format & FMT_NUMERIC);

	if (target) {
		if (target->print)
			/* Print the target information. */
			target->print(&fw->ip, t, format & FMT_NUMERIC);
	} else if (t->u.target_size != sizeof(*t))
		printf("[%u bytes of unknown target data] ",
		       (unsigned int)(t->u.target_size - sizeof(*t)));

	if (!(format & FMT_NONEWLINE))
		fputc('\n', stdout);
}

static void
print_firewall_line(const struct ipt_entry *fw,
		    struct xtc_handle *const h)
{
	struct xt_entry_target *t;

	t = ipt_get_target((struct ipt_entry *)fw);
	print_firewall(fw, t->u.user.name, 0, FMT_PRINT_RULE, h);
}

static int
append_entry(const xt_chainlabel chain,
	     struct ipt_entry *fw,
	     unsigned int nsaddrs,
	     const struct in_addr saddrs[],
	     const struct in_addr smasks[],
	     unsigned int ndaddrs,
	     const struct in_addr daddrs[],
	     const struct in_addr dmasks[],
	     int verbose,
	     struct xtc_handle *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		fw->ip.smsk.s_addr = smasks[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			fw->ip.dmsk.s_addr = dmasks[j].s_addr;
			if (verbose)
				print_firewall_line(fw, handle);
			ret &= iptc_append_entry(chain, fw, handle);
		}
	}

	return ret;
}

static int
replace_entry(const xt_chainlabel chain,
	      struct ipt_entry *fw,
	      unsigned int rulenum,
	      const struct in_addr *saddr, const struct in_addr *smask,
	      const struct in_addr *daddr, const struct in_addr *dmask,
	      int verbose,
	      struct xtc_handle *handle)
{
	fw->ip.src.s_addr = saddr->s_addr;
	fw->ip.dst.s_addr = daddr->s_addr;
	fw->ip.smsk.s_addr = smask->s_addr;
	fw->ip.dmsk.s_addr = dmask->s_addr;

	if (verbose)
		print_firewall_line(fw, handle);
	return iptc_replace_entry(chain, fw, rulenum, handle);
}

static int
insert_entry(const xt_chainlabel chain,
	     struct ipt_entry *fw,
	     unsigned int rulenum,
	     unsigned int nsaddrs,
	     const struct in_addr saddrs[],
	     const struct in_addr smasks[],
	     unsigned int ndaddrs,
	     const struct in_addr daddrs[],
	     const struct in_addr dmasks[],
	     int verbose,
	     struct xtc_handle *handle)
{
	unsigned int i, j;
	int ret = 1;

	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		fw->ip.smsk.s_addr = smasks[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			fw->ip.dmsk.s_addr = dmasks[j].s_addr;
			if (verbose)
				print_firewall_line(fw, handle);
			ret &= iptc_insert_entry(chain, fw, rulenum, handle);
		}
	}

	return ret;
}

static unsigned char *
make_delete_mask(const struct xtables_rule_match *matches,
		 const struct xtables_target *target)
{
	/* Establish mask for comparison */
	unsigned int size;
	const struct xtables_rule_match *matchp;
	unsigned char *mask, *mptr;

	size = sizeof(struct ipt_entry);
	for (matchp = matches; matchp; matchp = matchp->next)
		size += XT_ALIGN(sizeof(struct xt_entry_match)) + matchp->match->size;

	mask = xtables_calloc(1, size
			 + XT_ALIGN(sizeof(struct xt_entry_target))
			 + target->size);

	memset(mask, 0xFF, sizeof(struct ipt_entry));
	mptr = mask + sizeof(struct ipt_entry);

	for (matchp = matches; matchp; matchp = matchp->next) {
		memset(mptr, 0xFF,
		       XT_ALIGN(sizeof(struct xt_entry_match))
		       + matchp->match->userspacesize);
		mptr += XT_ALIGN(sizeof(struct xt_entry_match)) + matchp->match->size;
	}

	memset(mptr, 0xFF,
	       XT_ALIGN(sizeof(struct xt_entry_target))
	       + target->userspacesize);

	return mask;
}

static int
delete_entry(const xt_chainlabel chain,
	     struct ipt_entry *fw,
	     unsigned int nsaddrs,
	     const struct in_addr saddrs[],
	     const struct in_addr smasks[],
	     unsigned int ndaddrs,
	     const struct in_addr daddrs[],
	     const struct in_addr dmasks[],
	     int verbose,
	     struct xtc_handle *handle,
	     struct xtables_rule_match *matches,
	     const struct xtables_target *target)
{
	unsigned int i, j;
	int ret = 1;
	unsigned char *mask;

	mask = make_delete_mask(matches, target);
	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		fw->ip.smsk.s_addr = smasks[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			fw->ip.dmsk.s_addr = dmasks[j].s_addr;
			if (verbose)
				print_firewall_line(fw, handle);
			ret &= iptc_delete_entry(chain, fw, mask, handle);
		}
	}
	free(mask);

	return ret;
}

static int
check_entry(const xt_chainlabel chain, struct ipt_entry *fw,
	    unsigned int nsaddrs, const struct in_addr *saddrs,
	    const struct in_addr *smasks, unsigned int ndaddrs,
	    const struct in_addr *daddrs, const struct in_addr *dmasks,
	    bool verbose, struct xtc_handle *handle,
	    struct xtables_rule_match *matches,
	    const struct xtables_target *target)
{
	unsigned int i, j;
	int ret = 1;
	unsigned char *mask;

	mask = make_delete_mask(matches, target);
	for (i = 0; i < nsaddrs; i++) {
		fw->ip.src.s_addr = saddrs[i].s_addr;
		fw->ip.smsk.s_addr = smasks[i].s_addr;
		for (j = 0; j < ndaddrs; j++) {
			fw->ip.dst.s_addr = daddrs[j].s_addr;
			fw->ip.dmsk.s_addr = dmasks[j].s_addr;
			if (verbose)
				print_firewall_line(fw, handle);
			ret &= iptc_check_entry(chain, fw, mask, handle);
		}
	}

	free(mask);
	return ret;
}

int
for_each_chain4(int (*fn)(const xt_chainlabel, int, struct xtc_handle *),
	       int verbose, int builtinstoo, struct xtc_handle *handle)
{
        int ret = 1;
	const char *chain;
	char *chains;
	unsigned int i, chaincount = 0;

	chain = iptc_first_chain(handle);
	while (chain) {
		chaincount++;
		chain = iptc_next_chain(handle);
        }

	chains = xtables_malloc(sizeof(xt_chainlabel) * chaincount);
	i = 0;
	chain = iptc_first_chain(handle);
	while (chain) {
		strcpy(chains + i*sizeof(xt_chainlabel), chain);
		i++;
		chain = iptc_next_chain(handle);
        }

	for (i = 0; i < chaincount; i++) {
		if (!builtinstoo
		    && iptc_builtin(chains + i*sizeof(xt_chainlabel),
				    handle) == 1)
			continue;
	        ret &= fn(chains + i*sizeof(xt_chainlabel), verbose, handle);
	}

	free(chains);
        return ret;
}

int
flush_entries4(const xt_chainlabel chain, int verbose,
	      struct xtc_handle *handle)
{
	if (!chain)
		return for_each_chain4(flush_entries4, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Flushing chain `%s'\n", chain);
	return iptc_flush_entries(chain, handle);
}

static int
zero_entries(const xt_chainlabel chain, int verbose,
	     struct xtc_handle *handle)
{
	if (!chain)
		return for_each_chain4(zero_entries, verbose, 1, handle);

	if (verbose)
		fprintf(stdout, "Zeroing chain `%s'\n", chain);
	return iptc_zero_entries(chain, handle);
}

int
delete_chain4(const xt_chainlabel chain, int verbose,
	     struct xtc_handle *handle)
{
	if (!chain)
		return for_each_chain4(delete_chain4, verbose, 0, handle);

	if (verbose)
		fprintf(stdout, "Deleting chain `%s'\n", chain);
	return iptc_delete_chain(chain, handle);
}

static struct ipt_entry *
generate_entry(const struct ipt_entry *fw,
	       struct xtables_rule_match *matches,
	       struct xt_entry_target *target)
{
	unsigned int size;
	struct xtables_rule_match *matchp;
	struct ipt_entry *e;

	size = sizeof(struct ipt_entry);
	for (matchp = matches; matchp; matchp = matchp->next)
		size += matchp->match->m->u.match_size;

	e = xtables_malloc(size + target->u.target_size);
	*e = *fw;
	e->target_offset = size;
	e->next_offset = size + target->u.target_size;

	size = 0;
	for (matchp = matches; matchp; matchp = matchp->next) {
		memcpy(e->elems + size, matchp->match->m, matchp->match->m->u.match_size);
		size += matchp->match->m->u.match_size;
	}
	memcpy(e->elems + size, target, target->u.target_size);

	return e;
}

static void clear_rule_matches(struct xtables_rule_match **matches)
{
	struct xtables_rule_match *matchp, *tmp;

	for (matchp = *matches; matchp;) {
		tmp = matchp->next;
		if (matchp->match->m) {
			free(matchp->match->m);
			matchp->match->m = NULL;
		}
		if (matchp->match == matchp->match->next) {
			free(matchp->match);
			matchp->match = NULL;
		}
		free(matchp);
		matchp = tmp;
	}

	*matches = NULL;
}

static void command_jump(struct iptables_command_state *cs)
{
	size_t size;

	set_option(&cs->options, OPT_JUMP, &cs->fw.ip.invflags, cs->invert);
	cs->jumpto = parse_target(optarg);
	/* TRY_LOAD (may be chain name) */
	cs->target = xtables_find_target(cs->jumpto, XTF_TRY_LOAD);

	if (cs->target == NULL)
		return;

	size = XT_ALIGN(sizeof(struct xt_entry_target))
		+ cs->target->size;

	cs->target->t = xtables_calloc(1, size);
	cs->target->t->u.target_size = size;

#ifdef OLD_IPTABLES
	strcpy(cs->target->t->u.user.name, cs->jumpto);
#else
	if (cs->target->real_name == NULL) {
		strcpy(cs->target->t->u.user.name, cs->jumpto);
	}
	else {
		/* Alias support for userspace side */
		strcpy(cs->target->t->u.user.name, cs->target->real_name);
		if (!(cs->target->ext_flags & XTABLES_EXT_ALIAS))
			fprintf(stderr, "Notice: The %s target is converted into %s target "
			"in rule listing and saving.\n",
			cs->jumpto, cs->target->real_name);
	}
#endif
	cs->target->t->u.user.revision = cs->target->revision;
	xs_init_target(cs->target);

	if (cs->target->x6_options != NULL)
		iptables_globals.opts = xtables_options_xfrm(iptables_globals.orig_opts, iptables_globals.opts,
					    cs->target->x6_options,
					    &cs->target->option_offset);
	else
		iptables_globals.opts = xtables_merge_options(iptables_globals.orig_opts, iptables_globals.opts,
					     cs->target->extra_opts,
					     &cs->target->option_offset);
	if (iptables_globals.opts == NULL)
		xtables_error(OTHER_PROBLEM, "can't alloc memory!");
}

static void command_match(struct iptables_command_state *cs)
{
	struct xtables_match *m;
	size_t size;

	if (cs->invert)
		xtables_error(PARAMETER_PROBLEM,
			   "unexpected ! flag before --match");

	m = xtables_find_match(optarg, XTF_LOAD_MUST_SUCCEED, &cs->matches);
	if(m == NULL){
		xtables_error(PARAMETER_PROBLEM,
			   "unable to load match module %s", optarg);
	   return;
	}
	size = XT_ALIGN(sizeof(struct xt_entry_match)) + m->size;
	m->m = xtables_calloc(1, size);
	m->m->u.match_size = size;
	
	//OLD --
#ifdef OLD_IPTABLES
	strcpy(m->m->u.user.name, m->name);
#else
	if (m->real_name == NULL) {
		strcpy(m->m->u.user.name, m->name);
	}
	else {
		strcpy(m->m->u.user.name, m->real_name);
		if (!(m->ext_flags & XTABLES_EXT_ALIAS))
			fprintf(stderr, "Notice: the %s match is converted into %s match "
			"in rule listing and saving.\n", m->name, m->real_name);
	}
#endif
	
	m->m->u.user.revision = m->revision;
	xs_init_match(m);
	if (m == m->next)
		return;
	/* Merge options for non-cloned matches */
	if (m->x6_options != NULL)
		iptables_globals.opts = xtables_options_xfrm(iptables_globals.orig_opts, iptables_globals.opts,
					    m->x6_options, &m->option_offset);
	else if (m->extra_opts != NULL)
		iptables_globals.opts = xtables_merge_options(iptables_globals.orig_opts, iptables_globals.opts,
					     m->extra_opts, &m->option_offset);
	if (iptables_globals.opts == NULL)
		xtables_error(OTHER_PROBLEM, "can't alloc memory!");
}

EXPORT void* init_handle(const char* table){
	void* handle = iptc_init(table);

	/* try to insmod the module if iptc_init failed */
	if (!handle)
	{
		if (xtables_load_ko(xtables_modprobe_program, false) != -1)
		{
			handle = iptc_init(table);
			if (!handle)
			{
				iptables_exit_error(OTHER_PROBLEM, "unable to init module %s after loading", xtables_modprobe_program);
			}
		}
		else
		{
			iptables_exit_error(OTHER_PROBLEM, "unable to load module %s", xtables_modprobe_program);
		}
	}

	return handle;
}

static void
parse_chain(const char *chainname)
{
	const char *ptr;

	if (strlen(chainname) >= XT_EXTENSION_MAXNAMELEN)
		xtables_error(PARAMETER_PROBLEM,
		"chain name `%s' too long (must be under %u chars)",
		chainname, XT_EXTENSION_MAXNAMELEN);

	if (*chainname == '-' || *chainname == '!')
		xtables_error(PARAMETER_PROBLEM,
		"chain name not allowed to start "
		"with `%c'\n", *chainname);

	if (xtables_find_target(chainname, XTF_TRY_LOAD))
		xtables_error(PARAMETER_PROBLEM,
		"chain name may not clash "
		"with target name\n");

	for (ptr = chainname; *ptr; ptr++)
		if (isspace(*ptr))
			xtables_error(PARAMETER_PROBLEM,
			"Invalid chain name `%s'", chainname);
}

int do_command4(int argc, char *argv[], char **table, void **handle)
{
	struct iptables_command_state cs;
	struct ipt_entry *e = NULL;
	unsigned int nsaddrs = 0, ndaddrs = 0;
	struct in_addr *saddrs = NULL, *smasks = NULL;
	struct in_addr *daddrs = NULL, *dmasks = NULL;

	int verbose = 0;
	const char *chain = NULL;
	const char *shostnetworkmask = NULL, *dhostnetworkmask = NULL;
	const char *policy = NULL, *newname = NULL;
	unsigned int rulenum = 0, command = 0;
	const char *pcnt = NULL, *bcnt = NULL;
	int ret = 1;
	struct xtables_match *m;
	struct xtables_rule_match *matchp;
	struct xtables_target *t;
	unsigned long long cnt;

	memset(&cs, 0, sizeof(cs));
	cs.jumpto = "";
	cs.argv = argv;

	/* re-set optind to 0 in case do_command4 gets called
	 * a second time */
	optind = 0;

	/* clear mflags in case do_command4 gets called a second time
	 * (we clear the global list of all matches for security)*/
	for (m = xtables_matches; m; m = m->next)
		m->mflags = 0;

	for (t = xtables_targets; t; t = t->next) {
		t->tflags = 0;
		t->used = 0;
	}

	/* Suppress error messages: we may add new options if we
           demand-load a protocol. */
	opterr = 0;

	iptables_globals.opts = iptables_globals.orig_opts;
	while ((cs.c = getopt_long(argc, argv,
	   "-:A:C:D:R:I:L::S::M:F::Z::N:X::E:P:Vh::o:p:s:d:j:i:fbvnt:m:xc:g:46",
	   iptables_globals.opts, NULL)) != -1) {
		switch (cs.c) {
			/*
			 * Command selection
			 */
		case 'A':
			add_command(&command, CMD_APPEND, CMD_NONE,
				    cs.invert);
			chain = optarg;
			break;

		case 'C':
			add_command(&command, CMD_CHECK, CMD_NONE,
				    cs.invert);
			chain = optarg;
			break;

		case 'D':
			add_command(&command, CMD_DELETE, CMD_NONE,
				    cs.invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!') {
				rulenum = parse_rulenumber(argv[optind++]);
				command = CMD_DELETE_NUM;
			}
			break;

		case 'R':
			add_command(&command, CMD_REPLACE, CMD_NONE,
				    cs.invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				rulenum = parse_rulenumber(argv[optind++]);
			else
				xtables_error(PARAMETER_PROBLEM,
					   "-%c requires a rule number",
					   cmd2char(CMD_REPLACE));
			break;

		case 'I':
			add_command(&command, CMD_INSERT, CMD_NONE,
				    cs.invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				rulenum = parse_rulenumber(argv[optind++]);
			else rulenum = 1;
			break;

		case 'F':
			add_command(&command, CMD_FLUSH, CMD_NONE,
				    cs.invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'Z':
			add_command(&command, CMD_ZERO, CMD_LIST|CMD_LIST_RULES,
				    cs.invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				&& argv[optind][0] != '!')
				chain = argv[optind++];
			if (optind < argc && argv[optind][0] != '-'
				&& argv[optind][0] != '!') {
				rulenum = parse_rulenumber(argv[optind++]);
				command = CMD_ZERO_NUM;
			}
			break;

		case 'N':
			parse_chain(optarg);
			add_command(&command, CMD_NEW_CHAIN, CMD_NONE,
				    cs.invert);
			chain = optarg;
			break;

		case 'X':
			add_command(&command, CMD_DELETE_CHAIN, CMD_NONE,
				    cs.invert);
			if (optarg) chain = optarg;
			else if (optind < argc && argv[optind][0] != '-'
				 && argv[optind][0] != '!')
				chain = argv[optind++];
			break;

		case 'E':
			add_command(&command, CMD_RENAME_CHAIN, CMD_NONE,
				    cs.invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				newname = argv[optind++];
			else
				xtables_error(PARAMETER_PROBLEM,
					   "-%c requires old-chain-name and "
					   "new-chain-name",
					    cmd2char(CMD_RENAME_CHAIN));
			break;

		case 'P':
			add_command(&command, CMD_SET_POLICY, CMD_NONE,
				    cs.invert);
			chain = optarg;
			if (optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				policy = argv[optind++];
			else
				xtables_error(PARAMETER_PROBLEM,
					   "-%c requires a chain and a policy",
					   cmd2char(CMD_SET_POLICY));
			break;

		case 'p':
			set_option(&cs.options, OPT_PROTOCOL, &cs.fw.ip.invflags,
				   cs.invert);

			/* Canonicalize into lower case */
			for (cs.protocol = optarg; *cs.protocol; cs.protocol++)
				*cs.protocol = tolower(*cs.protocol);

			cs.protocol = optarg;
			cs.fw.ip.proto = xtables_parse_protocol(cs.protocol);

			if (cs.fw.ip.proto == 0
			    && (cs.fw.ip.invflags & XT_INV_PROTO))
				xtables_error(PARAMETER_PROBLEM,
					   "rule would never match protocol");
			break;

		case 's':
			set_option(&cs.options, OPT_SOURCE, &cs.fw.ip.invflags,
				   cs.invert);
			shostnetworkmask = optarg;
			break;

		case 'd':
			set_option(&cs.options, OPT_DESTINATION, &cs.fw.ip.invflags,
				   cs.invert);
			dhostnetworkmask = optarg;
			break;

#ifdef IPT_F_GOTO
		case 'g':
			set_option(&cs.options, OPT_JUMP, &cs.fw.ip.invflags,
				   cs.invert);
			cs.fw.ip.flags |= IPT_F_GOTO;
			cs.jumpto = parse_target(optarg);
			break;
#endif

		case 'j':
			command_jump(&cs);
			break;


		case 'i':
			if (*optarg == '\0')
				xtables_error(PARAMETER_PROBLEM,
					"Empty interface is likely to be "
					"undesired");
			set_option(&cs.options, OPT_VIANAMEIN, &cs.fw.ip.invflags,
				   cs.invert);
			xtables_parse_interface(optarg,
					cs.fw.ip.iniface,
					cs.fw.ip.iniface_mask);
			break;

		case 'o':
			if (*optarg == '\0')
				xtables_error(PARAMETER_PROBLEM,
					"Empty interface is likely to be "
					"undesired");
			set_option(&cs.options, OPT_VIANAMEOUT, &cs.fw.ip.invflags,
				   cs.invert);
			xtables_parse_interface(optarg,
					cs.fw.ip.outiface,
					cs.fw.ip.outiface_mask);
			break;

		case 'f':
			set_option(&cs.options, OPT_FRAGMENT, &cs.fw.ip.invflags,
				   cs.invert);
			cs.fw.ip.flags |= IPT_F_FRAG;
			break;

		case 'v':
			if (!verbose)
				set_option(&cs.options, OPT_VERBOSE,
					   &cs.fw.ip.invflags, cs.invert);
			verbose++;
			break;

		case 'm':
			command_match(&cs);
			break;

		case 'n':
			set_option(&cs.options, OPT_NUMERIC, &cs.fw.ip.invflags,
				   cs.invert);
			break;

		case 't':
			if (cs.invert)
				xtables_error(PARAMETER_PROBLEM,
					   "unexpected ! flag before --table");
			*table = optarg;
			break;

		case 'x':
			set_option(&cs.options, OPT_EXPANDED, &cs.fw.ip.invflags,
				   cs.invert);
			break;

		case '0':
			set_option(&cs.options, OPT_LINENUMBERS, &cs.fw.ip.invflags,
				   cs.invert);
			break;

		case 'M':
			xtables_modprobe_program = optarg;
			break;

		case 'c':

			set_option(&cs.options, OPT_COUNTERS, &cs.fw.ip.invflags,
				   cs.invert);
			pcnt = optarg;
			bcnt = strchr(pcnt + 1, ',');
			if (bcnt)
			    bcnt++;
			if (!bcnt && optind < argc && argv[optind][0] != '-'
			    && argv[optind][0] != '!')
				bcnt = argv[optind++];
			if (!bcnt)
				xtables_error(PARAMETER_PROBLEM,
					"-%c requires packet and byte counter",
					opt2char(OPT_COUNTERS));

			if (sscanf(pcnt, "%llu", &cnt) != 1)
				xtables_error(PARAMETER_PROBLEM,
					"-%c packet counter not numeric",
					opt2char(OPT_COUNTERS));
			cs.fw.counters.pcnt = cnt;

			if (sscanf(bcnt, "%llu", &cnt) != 1)
				xtables_error(PARAMETER_PROBLEM,
					"-%c byte counter not numeric",
					opt2char(OPT_COUNTERS));
			cs.fw.counters.bcnt = cnt;
			break;

		case '4':
			/* This is indeed the IPv4 iptables */
			break;

		case '6':
			/* This is not the IPv6 ip6tables */
			fprintf(stderr, "This is the IPv4 version of iptables.\n");
			return 2;

		case 1: /* non option */
			if (optarg[0] == '!' && optarg[1] == '\0') {
				if (cs.invert)
					xtables_error(PARAMETER_PROBLEM,
						   "multiple consecutive ! not"
						   " allowed");
				cs.invert = TRUE;
				optarg[0] = '\0';
				continue;
			}
			fprintf(stderr, "Bad argument `%s'\n", optarg);
			return (2);

		default:
			if (command_default(&cs, &iptables_globals) == 1)
				/* cf. ip6tables.c */
				continue;
			break;
		}
		cs.invert = FALSE;
	}

	if (strcmp(*table, "nat") == 0 &&
	    ((policy != NULL && strcmp(policy, "DROP") == 0) ||
	    (cs.jumpto != NULL && strcmp(cs.jumpto, "DROP") == 0)))
		xtables_error(PARAMETER_PROBLEM,
			"\nThe \"nat\" table is not intended for filtering, "
		        "the use of DROP is therefore inhibited.\n\n");

	for (matchp = cs.matches; matchp; matchp = matchp->next)
		xtables_option_mfcall(matchp->match);
	if (cs.target != NULL)
		xtables_option_tfcall(cs.target);

	/* Fix me: must put inverse options checking here --MN */

	if (optind < argc)
		xtables_error(PARAMETER_PROBLEM,
			   "unknown arguments found on commandline");
	if (!command)
		xtables_error(PARAMETER_PROBLEM, "no command specified");
	if (cs.invert)
		xtables_error(PARAMETER_PROBLEM,
			   "nothing appropriate following !");

	if (command & (CMD_REPLACE | CMD_INSERT | CMD_DELETE | CMD_APPEND | CMD_CHECK)) {
		if (!(cs.options & OPT_DESTINATION))
			dhostnetworkmask = "0.0.0.0/0";
		if (!(cs.options & OPT_SOURCE))
			shostnetworkmask = "0.0.0.0/0";
	}

	if (shostnetworkmask)
		xtables_ipparse_multiple(shostnetworkmask, &saddrs,
					 &smasks, &nsaddrs);

	if (dhostnetworkmask)
		xtables_ipparse_multiple(dhostnetworkmask, &daddrs,
					 &dmasks, &ndaddrs);

	if ((nsaddrs > 1 || ndaddrs > 1) &&
	    (cs.fw.ip.invflags & (IPT_INV_SRCIP | IPT_INV_DSTIP)))
		xtables_error(PARAMETER_PROBLEM, "! not allowed with multiple"
			   " source or destination IP addresses");

	if (command == CMD_REPLACE && (nsaddrs != 1 || ndaddrs != 1))
		xtables_error(PARAMETER_PROBLEM, "Replacement rule does not "
			   "specify a unique address");

	generic_opt_check(command, cs.options);

	/*if (!xtables_lock(false)) {
		fprintf(stderr, "Another app is currently holding the xtables lock. "
			"Perhaps you want to use the -w option?\n");
		xtables_free_opts(1);
		return 4;
	}*/

	if (chain != NULL && strlen(chain) >= XT_EXTENSION_MAXNAMELEN)
		xtables_error(PARAMETER_PROBLEM,
			   "chain name `%s' too long (must be under %u chars)",
			   chain, XT_EXTENSION_MAXNAMELEN);

	/* only allocate handle if we weren't called with a handle */
	if (!*handle)
		*handle = init_handle(*table);

	if (!*handle)
		xtables_error(VERSION_PROBLEM,
			   "can't initialize iptables table `%s': %s",
			   *table, iptc_strerror(errno));

	if (command == CMD_APPEND
	    || command == CMD_DELETE
	    || command == CMD_CHECK
	    || command == CMD_INSERT
	    || command == CMD_REPLACE) {
		if (strcmp(chain, "PREROUTING") == 0
		    || strcmp(chain, "INPUT") == 0) {
			/* -o not valid with incoming packets. */
			if (cs.options & OPT_VIANAMEOUT)
				xtables_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEOUT),
					   chain);
		}

		if (strcmp(chain, "POSTROUTING") == 0
		    || strcmp(chain, "OUTPUT") == 0) {
			/* -i not valid with outgoing packets */
			if (cs.options & OPT_VIANAMEIN)
				xtables_error(PARAMETER_PROBLEM,
					   "Can't use -%c with %s\n",
					   opt2char(OPT_VIANAMEIN),
					   chain);
		}

		if (cs.target && iptc_is_chain(cs.jumpto, *handle)) {
			fprintf(stderr,
				"Warning: using chain %s, not extension\n",
				cs.jumpto);

			if (cs.target->t)
				free(cs.target->t);

			cs.target = NULL;
		}

		/* If they didn't specify a target, or it's a chain
		   name, use standard. */
		if (!cs.target
		    && (strlen(cs.jumpto) == 0
			|| iptc_is_chain(cs.jumpto, *handle))) {
			size_t size;

			cs.target = xtables_find_target(XT_STANDARD_TARGET,
					 XTF_LOAD_MUST_SUCCEED);

			size = sizeof(struct xt_entry_target)
				+ cs.target->size;
			cs.target->t = xtables_calloc(1, size);
			cs.target->t->u.target_size = size;
			strcpy(cs.target->t->u.user.name, cs.jumpto);
			if (!iptc_is_chain(cs.jumpto, *handle))
				cs.target->t->u.user.revision = cs.target->revision;
			xs_init_target(cs.target);
		}

		if (!cs.target) {
			/* it is no chain, and we can't load a plugin.
			 * We cannot know if the plugin is corrupt, non
			 * existant OR if the user just misspelled a
			 * chain. */
#ifdef IPT_F_GOTO
			if (cs.fw.ip.flags & IPT_F_GOTO)
				xtables_error(PARAMETER_PROBLEM,
					   "goto '%s' is not a chain\n",
					   cs.jumpto);
#endif
			xtables_find_target(cs.jumpto, XTF_LOAD_MUST_SUCCEED);
		} else {
			e = generate_entry(&cs.fw, cs.matches, cs.target->t);
			free(cs.target->t);
		}
	}

	switch (command) {
	case CMD_APPEND:
		ret = append_entry(chain, e,
				   nsaddrs, saddrs, smasks,
				   ndaddrs, daddrs, dmasks,
				   cs.options&OPT_VERBOSE,
				   *handle);
		break;
	case CMD_DELETE:
		ret = delete_entry(chain, e,
				   nsaddrs, saddrs, smasks,
				   ndaddrs, daddrs, dmasks,
				   cs.options&OPT_VERBOSE,
				   *handle, cs.matches, cs.target);
		break;
	case CMD_DELETE_NUM:
		ret = iptc_delete_num_entry(chain, rulenum - 1, *handle);
		break;
	case CMD_CHECK:
		ret = check_entry(chain, e,
				   nsaddrs, saddrs, smasks,
				   ndaddrs, daddrs, dmasks,
				   cs.options&OPT_VERBOSE,
				   *handle, cs.matches, cs.target);
		break;
	case CMD_REPLACE:
		ret = replace_entry(chain, e, rulenum - 1,
				    saddrs, smasks, daddrs, dmasks,
				    cs.options&OPT_VERBOSE, *handle);
		break;
	case CMD_INSERT:
		ret = insert_entry(chain, e, rulenum - 1,
				   nsaddrs, saddrs, smasks,
				   ndaddrs, daddrs, dmasks,
				   cs.options&OPT_VERBOSE,
				   *handle);
		break;
	case CMD_FLUSH:
		ret = flush_entries4(chain, cs.options&OPT_VERBOSE, *handle);
		break;
	case CMD_ZERO:
		ret = zero_entries(chain, cs.options&OPT_VERBOSE, *handle);
		break;
	case CMD_ZERO_NUM:
		ret = iptc_zero_counter(chain, rulenum, *handle);
		break;
	case CMD_NEW_CHAIN:
		ret = iptc_create_chain(chain, *handle);
		break;
	case CMD_DELETE_CHAIN:
		ret = delete_chain4(chain, cs.options&OPT_VERBOSE, *handle);
		break;
	case CMD_RENAME_CHAIN:
		ret = iptc_rename_chain(chain, newname,	*handle);
		break;
	case CMD_SET_POLICY:
		ret = iptc_set_policy(chain, policy, cs.options&OPT_COUNTERS ? &cs.fw.counters : NULL, *handle);
		break;
	default:
		/* We should never reach this... */
		return (2);
	}

	if (verbose > 1)
		dump_entries(*handle);

	clear_rule_matches(&cs.matches);

	if (e != NULL) {
		free(e);
		e = NULL;
	}

	free(saddrs);
	free(smasks);
	free(daddrs);
	free(dmasks);
	xtables_free_opts(1);

	return ret;
}
