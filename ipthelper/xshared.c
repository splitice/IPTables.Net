#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#if defined(__unix__) || defined(__APPLE__)
#include <dlfcn.h>
#endif
#include "xtables.h"
#include <math.h>
#include "xshared.h"

#define XS_LONGOPTS_SCAN_LIMIT 4096U

#if defined(__unix__) || defined(__APPLE__)
#define XS_HAVE_DLADDR 1
#else
#define XS_HAVE_DLADDR 0
#endif

static size_t xs_longopts_count(const struct option *opts, const char *ext_name)
{
	size_t i;

	if (opts == NULL)
		return 0;

	for (i = 0; i < XS_LONGOPTS_SCAN_LIMIT; ++i) {
		if (opts[i].name == NULL)
			return i;
	}

	if (ext_name != NULL)
		xtables_error(OTHER_PROBLEM,
					  "Extension \"%s\" returned an unterminated option table.",
					  ext_name);

	xtables_error(OTHER_PROBLEM,
				  "xtables option table is missing its terminator.");
	return 0;
}

#if XS_HAVE_DLADDR
static bool xs_option_name_pointer_is_valid(const char *name)
{
	Dl_info info;

	if (name == NULL)
		return true;

	return dladdr((const void *)name, &info) != 0;
}
#else
static bool xs_option_name_pointer_is_valid(const char *name)
{
	if (name == NULL)
		return true;

#if INTPTR_MAX > 0xffffffff
	if ((uintptr_t)name < 0x100000000ULL)
		return false;
#endif
	return true;
}
#endif

static void xs_validate_new_longopts(struct option *opts, size_t start,
									 const char *ext_name)
{
	size_t total;
	size_t i;

	if (opts == NULL || ext_name == NULL)
		return;

	total = xs_longopts_count(opts, ext_name);
	if (start >= total)
		return;

	for (i = start; i < total; ++i) {
		if (!xs_option_name_pointer_is_valid(opts[i].name)) {
			xtables_error(OTHER_PROBLEM,
						  "Extension \"%s\" was built against an incompatible libxtables release (detected corrupt option metadata). Please rebuild the module.",
						  ext_name);
		}
	}
}

/*
 * Print out any special helps. A user might like to be able to add a --help
 * to the commandline, and see expected results. So we call help for all
 * specified matches and targets.
 */
void print_extension_helps(const struct xtables_target *t,
    const struct xtables_rule_match *m)
{
	for (; t != NULL; t = t->next) {
		if (t->used) {
			printf("\n");
			if (t->help == NULL)
				printf("%s does not take any options\n",
				       t->name);
			else
				t->help();
		}
	}
	for (; m != NULL; m = m->next) {
		printf("\n");
		if (m->match->help == NULL)
			printf("%s does not take any options\n",
			       m->match->name);
		else
			m->match->help();
	}
}

const char *
proto_to_name(uint8_t proto, int nolookup)
{
	unsigned int i;

	if (proto && !nolookup) {
		struct protoent *pent = getprotobynumber(proto);
		if (pent)
			return pent->p_name;
	}

	for (i = 0; xtables_chain_protos[i].name != NULL; ++i)
		if (xtables_chain_protos[i].num == proto)
			return xtables_chain_protos[i].name;

	return NULL;
}

static struct xtables_match *
find_proto(const char *pname, enum xtables_tryload tryload,
	   int nolookup, struct xtables_rule_match **matches)
{
	unsigned int proto;

	if (xtables_strtoui(pname, NULL, &proto, 0, UINT8_MAX)) {
		const char *protoname = proto_to_name(proto, nolookup);

		if (protoname)
			return xtables_find_match(protoname, tryload, matches);
	} else
		return xtables_find_match(pname, tryload, matches);

	return NULL;
}

/*
 * Some explanations (after four different bugs in 3 different releases): If
 * we encounter a parameter, that has not been parsed yet, it's not an option
 * of an explicitly loaded match or a target. However, we support implicit
 * loading of the protocol match extension. '-p tcp' means 'l4 proto 6' and at
 * the same time 'load tcp protocol match on demand if we specify --dport'.
 *
 * To make this work, we need to make sure:
 * - the parameter has not been parsed by a match (m above)
 * - a protocol has been specified
 * - the protocol extension has not been loaded yet, or is loaded and unused
 *   [think of ip6tables-restore!]
 * - the protocol extension can be successively loaded
 */
static bool should_load_proto(struct iptables_command_state *cs)
{
	if (cs->protocol == NULL)
		return false;
	if (find_proto(cs->protocol, XTF_DONT_LOAD,
	    cs->options & OPT_NUMERIC, NULL) == NULL)
		return true;
	return !cs->proto_used;
}

struct xtables_match *load_proto(struct iptables_command_state *cs)
{
	if (!should_load_proto(cs))
		return NULL;
	return find_proto(cs->protocol, XTF_TRY_LOAD,
			  cs->options & OPT_NUMERIC, &cs->matches);
}

int command_default(struct iptables_command_state *cs,
		    struct xtables_globals *gl)
{
	struct xtables_rule_match *matchp;
	struct xtables_match *m;

	if (cs->target != NULL &&
	    (cs->target->parse != NULL || cs->target->x6_parse != NULL) &&
	    cs->c >= cs->target->option_offset &&
	    cs->c < cs->target->option_offset + XT_OPTION_OFFSET_SCALE) {
		xtables_option_tpcall(cs->c, cs->argv, cs->invert,
				      cs->target, &cs->fw);
		return 0;
	}

	for (matchp = cs->matches; matchp; matchp = matchp->next) {
		m = matchp->match;

		//if (matchp->completed ||
		if( 
		   (m->x6_parse == NULL && m->parse == NULL))
			continue;
		if (cs->c < matchp->match->option_offset ||
		    cs->c >= matchp->match->option_offset + XT_OPTION_OFFSET_SCALE)
			continue;
		xtables_option_mpcall(cs->c, cs->argv, cs->invert, m, &cs->fw);
		return 0;
	}

	/* Try loading protocol */
	m = load_proto(cs);
	if (m != NULL) {
		size_t size;
		size_t merge_start;

		cs->proto_used = 1;

		size = XT_ALIGN(sizeof(struct xt_entry_match)) + m->size;

		m->m = xtables_calloc(1, size);
		m->m->u.match_size = size;
		strcpy(m->m->u.user.name, m->name);
		m->m->u.user.revision = m->revision;
		xs_init_match(m);

		merge_start = xs_longopts_count(gl->opts, NULL);
		if (m->x6_options != NULL)
			gl->opts = xtables_options_xfrm(gl->orig_opts,
							gl->opts,
							m->x6_options,
							&m->option_offset);
		else
			gl->opts = xtables_merge_options(gl->orig_opts,
						 	 gl->opts,
						 	 m->extra_opts,
						 	 &m->option_offset);
		if (gl->opts == NULL)
			xtables_error(OTHER_PROBLEM, "can't alloc memory!");
		xs_validate_new_longopts(gl->opts, merge_start,
					     m->real_name != NULL ?
					     m->real_name : m->name);
		optind--;
		/* Indicate to rerun getopt *immediately* */
 		return 1;
	}

	if (cs->c == ':')
		xtables_error(PARAMETER_PROBLEM, "option \"%s\" "
		              "requires an argument", cs->argv[optind-1]);
	if (cs->c == '?')
		xtables_error(PARAMETER_PROBLEM, "unknown option "
			      "\"%s\"", cs->argv[optind-1]);
	xtables_error(PARAMETER_PROBLEM, "Unknown arg \"%s\"", optarg);
	return 0;
}

static mainfunc_t subcmd_get(const char *cmd, const struct subcommand *cb)
{
	for (; cb->name != NULL; ++cb)
		if (strcmp(cb->name, cmd) == 0)
			return cb->main;
	return NULL;
}

int subcmd_main(int argc, char **argv, const struct subcommand *cb)
{
	const char *cmd = basename(*argv);
	mainfunc_t f = subcmd_get(cmd, cb);

	if (f == NULL && argc > 1) {
		/*
		 * Unable to find a main method for our command name?
		 * Let's try again with the first argument!
		 */
		++argv;
		--argc;
		f = subcmd_get(*argv, cb);
	}

	/* now we should have a valid function pointer */
	if (f != NULL)
		return f(argc, argv);

	fprintf(stderr, "ERROR: No valid subcommand given.\nValid subcommands:\n");
	for (; cb->name != NULL; ++cb)
		fprintf(stderr, " * %s\n", cb->name);
	exit(EXIT_FAILURE);
}

void xs_init_target(struct xtables_target *target)
{
	if (target->udata_size != 0) {
		free(target->udata);
		target->udata = calloc(1, target->udata_size);
		if (target->udata == NULL)
			xtables_error(RESOURCE_PROBLEM, "malloc");
	}
	if (target->init != NULL)
		target->init(target->t);
}

void xs_init_match(struct xtables_match *match)
{
	if (match->udata_size != 0) {
		/*
		 * As soon as a subsequent instance of the same match
		 * is used, e.g. "-m time -m time", the first instance
		 * is no longer reachable anyway, so we can free udata.
		 * Same goes for target.
		 */
		free(match->udata);
		match->udata = calloc(1, match->udata_size);
		if (match->udata == NULL)
			xtables_error(RESOURCE_PROBLEM, "malloc");
	}
	if (match->init != NULL)
		match->init(match->m);
}

static int xtables_lock(int wait, struct timeval *wait_interval)
{
	return 0;
}
void xtables_unlock(int lock)
{
}

int xtables_lock_or_exit(int wait, struct timeval *wait_interval)
{
}

int parse_wait_time(int argc, char *argv[])
{
	int wait = -1;

	if (optarg) {
		if (sscanf(optarg, "%i", &wait) != 1)
			xtables_error(PARAMETER_PROBLEM,
				"wait seconds not numeric");
	} else if (xs_has_arg(argc, argv))
		if (sscanf(argv[optind++], "%i", &wait) != 1)
			xtables_error(PARAMETER_PROBLEM,
				"wait seconds not numeric");

	return wait;
}

void parse_wait_interval(int argc, char *argv[], struct timeval *wait_interval)
{
	const char *arg;
	unsigned int usec;
	int ret;

	if (optarg)
		arg = optarg;
	else if (xs_has_arg(argc, argv))
		arg = argv[optind++];
	else
		xtables_error(PARAMETER_PROBLEM, "wait interval value required");

	ret = sscanf(arg, "%u", &usec);
	if (ret == 1) {
		if (usec > 999999)
			xtables_error(PARAMETER_PROBLEM,
				      "too long usec wait %u > 999999 usec",
				      usec);

		wait_interval->tv_sec = 0;
		wait_interval->tv_usec = usec;
		return;
	}
	xtables_error(PARAMETER_PROBLEM, "wait interval not numeric");
}

int parse_counters(const char *string, struct xt_counters *ctr)
{
	int ret;

	if (!string)
		return 0;

	ret = sscanf(string, "[%llu:%llu]",
		     (unsigned long long *)&ctr->pcnt,
		     (unsigned long long *)&ctr->bcnt);

	return ret == 2;
}

inline bool xs_has_arg(int argc, char *argv[])
{
	return optind < argc &&
	       argv[optind][0] != '-' &&
	       argv[optind][0] != '!';
}

/* global new argv and argc */
char *newargv[255];
int newargc = 0;

/* saved newargv and newargc from save_argv() */
char *oldargv[255];
int oldargc = 0;

/* arg meta data, were they quoted, frinstance */
int newargvattr[255];

/* function adding one argument to newargv, updating newargc
 * returns true if argument added, false otherwise */
int add_argv(const char *what, int quoted)
{
	DEBUGP("add_argv: %s\n", what);
	if (what && newargc + 1 < ARRAY_SIZE(newargv)) {
		newargv[newargc] = strdup(what);
		newargvattr[newargc] = quoted;
		newargv[++newargc] = NULL;
		return 1;
	} else {
		xtables_error(PARAMETER_PROBLEM,
			      "Parser cannot handle more arguments\n");
	}
}

void free_argv(void)
{
	while (newargc)
		free(newargv[--newargc]);
	while (oldargc)
		free(oldargv[--oldargc]);
}

/* Save parsed rule for comparison with next rule to perform action aggregation
 * on duplicate conditions.
 */
void save_argv(void)
{
	unsigned int i;

	while (oldargc)
		free(oldargv[--oldargc]);

	oldargc = newargc;
	newargc = 0;
	for (i = 0; i < oldargc; i++) {
		oldargv[i] = newargv[i];
	}
}

void add_param_to_argv(char *parsestart, int line)
{
	int quote_open = 0, escaped = 0, param_len = 0;
	char param_buffer[1024], *curchar;

	/* After fighting with strtok enough, here's now
	 * a 'real' parser. According to Rusty I'm now no
	 * longer a real hacker, but I can live with that */

	for (curchar = parsestart; *curchar; curchar++) {
		if (quote_open) {
			if (escaped) {
				param_buffer[param_len++] = *curchar;
				escaped = 0;
				continue;
			} else if (*curchar == '\\') {
				escaped = 1;
				continue;
			} else if (*curchar == '"') {
				quote_open = 0;
				*curchar = '"';
			} else {
				param_buffer[param_len++] = *curchar;
				continue;
			}
		} else {
			if (*curchar == '"') {
				quote_open = 1;
				continue;
			}
		}

		switch (*curchar) {
		case '"':
			break;
		case ' ':
		case '\t':
		case '\n':
			if (!param_len) {
				/* two spaces? */
				continue;
			}
			break;
		default:
			/* regular character, copy to buffer */
			param_buffer[param_len++] = *curchar;

			if (param_len >= sizeof(param_buffer))
				xtables_error(PARAMETER_PROBLEM,
					      "Parameter too long!");
			continue;
		}

		param_buffer[param_len] = '\0';

		/* check if table name specified */
		if ((param_buffer[0] == '-' &&
		     param_buffer[1] != '-' &&
		     strchr(param_buffer, 't')) ||
		    (!strncmp(param_buffer, "--t", 3) &&
		     !strncmp(param_buffer, "--table", strlen(param_buffer)))) {
			xtables_error(PARAMETER_PROBLEM,
				      "The -t option (seen in line %u) cannot be used in %s.\n",
				      line, xt_params->program_name);
		}

		add_argv(param_buffer, 0);
		param_len = 0;
	}
}

static const char *ipv4_addr_to_string(const struct in_addr *addr,
				       const struct in_addr *mask,
				       unsigned int format)
{
	static char buf[BUFSIZ];

	if (!mask->s_addr && !(format & FMT_NUMERIC))
		return "anywhere";

	if (format & FMT_NUMERIC)
		strncpy(buf, xtables_ipaddr_to_numeric(addr), BUFSIZ - 1);
	else
		strncpy(buf, xtables_ipaddr_to_anyname(addr), BUFSIZ - 1);
	buf[BUFSIZ - 1] = '\0';

	strncat(buf, xtables_ipmask_to_numeric(mask),
		BUFSIZ - strlen(buf) - 1);

	return buf;
}

void print_ipv4_addresses(const struct ipt_entry *fw, unsigned int format)
{
	fputc(fw->ip.invflags & IPT_INV_SRCIP ? '!' : ' ', stdout);
	printf(FMT("%-19s ", "%s "),
	       ipv4_addr_to_string(&fw->ip.src, &fw->ip.smsk, format));

	fputc(fw->ip.invflags & IPT_INV_DSTIP ? '!' : ' ', stdout);
	printf(FMT("%-19s ", "-> %s"),
	       ipv4_addr_to_string(&fw->ip.dst, &fw->ip.dmsk, format));
}

static const char *ipv6_addr_to_string(const struct in6_addr *addr,
				       const struct in6_addr *mask,
				       unsigned int format)
{
	static char buf[BUFSIZ];

	if (IN6_IS_ADDR_UNSPECIFIED(addr) && !(format & FMT_NUMERIC))
		return "anywhere";

	if (format & FMT_NUMERIC)
		strncpy(buf, xtables_ip6addr_to_numeric(addr), BUFSIZ - 1);
	else
		strncpy(buf, xtables_ip6addr_to_anyname(addr), BUFSIZ - 1);
	buf[BUFSIZ - 1] = '\0';

	strncat(buf, xtables_ip6mask_to_numeric(mask),
		BUFSIZ - strlen(buf) - 1);

	return buf;
}

void print_ipv6_addresses(const struct ip6t_entry *fw6, unsigned int format)
{
	fputc(fw6->ipv6.invflags & IP6T_INV_SRCIP ? '!' : ' ', stdout);
	printf(FMT("%-19s ", "%s "),
	       ipv6_addr_to_string(&fw6->ipv6.src,
				   &fw6->ipv6.smsk, format));

	fputc(fw6->ipv6.invflags & IP6T_INV_DSTIP ? '!' : ' ', stdout);
	printf(FMT("%-19s ", "-> %s"),
	       ipv6_addr_to_string(&fw6->ipv6.dst,
				   &fw6->ipv6.dmsk, format));
}

/* Luckily, IPT_INV_VIA_IN and IPT_INV_VIA_OUT
 * have the same values as IP6T_INV_VIA_IN and IP6T_INV_VIA_OUT
 * so this function serves for both iptables and ip6tables */
void print_ifaces(const char *iniface, const char *outiface, uint8_t invflags,
		  unsigned int format)
{
	const char *anyname = format & FMT_NUMERIC ? "*" : "any";
	char iface[IFNAMSIZ + 2];

	if (!(format & FMT_VIA))
		return;

	snprintf(iface, IFNAMSIZ + 2, "%s%s",
		 invflags & IPT_INV_VIA_IN ? "!" : "",
		 iniface[0] != '\0' ? iniface : anyname);

	printf(FMT(" %-6s ", "in %s "), iface);

	snprintf(iface, IFNAMSIZ + 2, "%s%s",
		 invflags & IPT_INV_VIA_OUT ? "!" : "",
		 outiface[0] != '\0' ? outiface : anyname);

	printf(FMT("%-6s ", "out %s "), iface);
}

void command_match(struct iptables_command_state *cs)
{
	struct option *opts = xt_params->opts;
	struct xtables_match *m;
	size_t size;

	if (cs->invert)
		xtables_error(PARAMETER_PROBLEM,
			   "unexpected ! flag before --match");

	m = xtables_find_match(optarg, XTF_LOAD_MUST_SUCCEED, &cs->matches);
	size = XT_ALIGN(sizeof(struct xt_entry_match)) + m->size;
	m->m = xtables_calloc(1, size);
	m->m->u.match_size = size;
	if (m->real_name == NULL) {
		strcpy(m->m->u.user.name, m->name);
	} else {
		strcpy(m->m->u.user.name, m->real_name);
		if (!(m->ext_flags & XTABLES_EXT_ALIAS))
			fprintf(stderr, "Notice: the %s match is converted into %s match "
				"in rule listing and saving.\n", m->name, m->real_name);
	}
	m->m->u.user.revision = m->revision;
	xs_init_match(m);
	if (m == m->next)
		return;
	/* Merge options for non-cloned matches */
	{
		bool merged = false;
		size_t merge_start = xs_longopts_count(opts, NULL);

		if (m->x6_options != NULL) {
			opts = xtables_options_xfrm(xt_params->orig_opts, opts,
					    m->x6_options, &m->option_offset);
			merged = true;
		} else if (m->extra_opts != NULL) {
			opts = xtables_merge_options(xt_params->orig_opts, opts,
					     m->extra_opts, &m->option_offset);
			merged = true;
		}

		if (opts == NULL)
			xtables_error(OTHER_PROBLEM, "can't alloc memory!");
		if (merged)
			xs_validate_new_longopts(opts, merge_start,
					     m->real_name != NULL ?
					     m->real_name : m->name);
	}
	xt_params->opts = opts;
}

const char *xt_parse_target(const char *targetname)
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

void command_jump(struct iptables_command_state *cs)
{
	struct option *opts = xt_params->opts;
	size_t size;

	cs->jumpto = xt_parse_target(optarg);
	/* TRY_LOAD (may be chain name) */
	cs->target = xtables_find_target(cs->jumpto, XTF_TRY_LOAD);

	if (cs->target == NULL)
		return;

	size = XT_ALIGN(sizeof(struct xt_entry_target)) + cs->target->size;

	cs->target->t = xtables_calloc(1, size);
	cs->target->t->u.target_size = size;
	if (cs->target->real_name == NULL) {
		strcpy(cs->target->t->u.user.name, cs->jumpto);
	} else {
		/* Alias support for userspace side */
		strcpy(cs->target->t->u.user.name, cs->target->real_name);
		if (!(cs->target->ext_flags & XTABLES_EXT_ALIAS))
			fprintf(stderr, "Notice: The %s target is converted into %s target "
				"in rule listing and saving.\n",
				cs->jumpto, cs->target->real_name);
	}
	cs->target->t->u.user.revision = cs->target->revision;
	xs_init_target(cs->target);

	{
		bool merged = false;
		size_t merge_start = xs_longopts_count(opts, NULL);

		if (cs->target->x6_options != NULL) {
			opts = xtables_options_xfrm(xt_params->orig_opts, opts,
					    cs->target->x6_options,
					    &cs->target->option_offset);
			merged = true;
		} else if (cs->target->extra_opts != NULL) {
			opts = xtables_merge_options(xt_params->orig_opts, opts,
					     cs->target->extra_opts,
					     &cs->target->option_offset);
			merged = true;
		}
		if (opts == NULL)
			xtables_error(OTHER_PROBLEM, "can't alloc memory!");
		if (merged)
			xs_validate_new_longopts(opts, merge_start,
					 cs->target->real_name != NULL ?
					 cs->target->real_name : cs->jumpto);
	}
	xt_params->opts = opts;
}
