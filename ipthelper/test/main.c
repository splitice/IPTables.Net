#include <stdio.h>
#include <stdbool.h>

#include <libiptc/libiptc.h>

#include "../ipthelper.h"
#include "../ct.h"

char* last_error(void);
void basic_test(void);
void ct_test(void);

void main() {
    basic_test();
    ct_test();
}

void basic_test(void) {
    init_helper4();
    void *h = init_handle4("filter");
    int r1 = execute_command4("iptables -v  -A INPUT -s 1.1.1.1 -m comment --comment a -j ACCEPT", h);
puts("======");
    int r2 = execute_command4("iptables -A INPUT -s 1.1.1.2 -m comment --comment b -j ACCEPT", h);
	printf("done -> %d %d %s\n", r1, r2, last_error());
	iptc_commit(h);
}

void ct_test(void) {
    struct cr_img out;
    dump_nf_cts(0, &out);
}