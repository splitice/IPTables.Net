#ifndef _IPTABLES_USER_H
#define _IPTABLES_USER_H

#include <netinet/ip.h>
#include <xtables.h>
#include <libiptc/libiptc.h>
//#include <iptables/internal.h>

typedef char xt_chainlabel[32];
extern struct xtables_globals iptables_globals;

/* Your shared library should call one of these. */
int do_command4(int argc, char *argv[], char **table,
	void **handle);

#endif /*_IPTABLES_USER_H*/
