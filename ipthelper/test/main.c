#include <stdio.h>
#include <stdbool.h>

#include <libiptc/libiptc.h>

#include "../ipthelper.h"
#include "../ct.h"

char* last_error(void);
void basic_test(void);
void rule_output_simple_test(void);
void rule_input_test(void);
void basic_v6_test(void);
void ct_dump_test(void);
void ct_dump_filtered_test(void);

void main() {
    basic_test();
    rule_output_simple_test();
    rule_input_test();
    //basic_v6_test();
    ct_dump_test();
    ct_dump_filtered_test();
}

void basic_test(void) {
    printf("%s started\n", __FUNCTION__);

    init_helper4();

    void *h = init_handle4("filter");
    if (h == NULL)
    {
        puts("failed -> cannot init handle for IPv4");
        return;
    }

    int r1 = execute_command4("iptables -v  -A INPUT -s 1.1.1.1 -m comment --comment a -j ACCEPT", h);
    puts("======");
    int r2 = execute_command4("iptables -A INPUT -s 1.1.1.2 -m comment --comment b -j ACCEPT", h);
	printf("done -> %d %d %s\n", r1, r2, last_error());
	iptc_commit(h);
}

void rule_output_simple_test(void) {
    printf("%s started\n", __FUNCTION__);

    init_helper4();

    void *h = init_handle4("filter");
    if (h == NULL)
    {
        puts("failed -> cannot init handle for IPv4");
        return;
    }

    // Test Startup
    int r0 = execute_command4("iptables -F test", h);
    int r1 = execute_command4("iptables -N test", h);
    int r2 = execute_command4("iptables -A test -j ACCEPT", h);

	printf("done -> %d %d %d %s\n", r0, r1, r2, last_error());
	iptc_commit(h);

    // Act
    const struct ipt_entry* rule = iptc_first_rule("test", h);
    if (NULL == rule)
    {
        puts("failed -> fetch rule");
        return;
    }

    // Test Destroy
    r0 = execute_command4("iptables -F test", h);
    r1 = execute_command4("iptables -X test", h);
	printf("done -> %d %d %s\n", r0, r1, last_error());
	iptc_commit(h);
}

void rule_input_test(void) {
    printf("%s started\n", __FUNCTION__);

    init_helper4();

    void *h = init_handle4("filter");
    if (h == NULL)
    {
        puts("failed -> cannot init handle for IPv4");
        return;
    }

    // Test Startup
    int r0 = execute_command4("iptables -F test2", h);
    int r1 = execute_command4("iptables -N test2", h);

	printf("done -> %d %d %s\n", r0, r1, last_error());
	iptc_commit(h);

    // Act
    r0 = execute_command4("iptables -A test2 -d 1.1.1.1 -p tcp -m tcp --dport 80 -j ACCEPT", h);
	printf("done -> %d %s\n", r0, last_error());

    // Test Destroy
    r0 = execute_command4("iptables -F test2", h);
    r1 = execute_command4("iptables -X test2", h);
	printf("done -> %d %d %s\n", r0, r1, last_error());
	iptc_commit(h);
}

void basic_v6_test(void) {
    printf("%s started\n", __FUNCTION__);

    init_helper6();

    void *h = init_handle6("filter");
    if (h == NULL)
    {
        puts("failed -> cannot init handle for IPv6");
        return;
    }
    int r1 = execute_command6("ip6tables -v  -A INPUT -s 1.1.1.1 -m comment --comment a -j ACCEPT", h);
    puts("======");
    int r2 = execute_command6("ip6tables -A INPUT -s 1.1.1.2 -m comment --comment b -j ACCEPT", h);
	printf("done -> %d %d %s\n", r1, r2, last_error());
	iptc_commit(h);
}

void ct_dump_test(void) {
    printf("%s started\n", __FUNCTION__);

    struct cr_img out;
    dump_nf_cts(0, &out);
}

#include <linux/netfilter/nfnetlink_conntrack.h>

#define ADDRESS_FAMILY_UNSPECIFIED 0

#define IPV4_ADDR(a, b, c, d)(((a & 0xff) << 24) | ((b & 0xff) << 16) | \
        ((c & 0xff) << 8) | (d & 0xff))

void ct_dump_filtered_test(void) {
    printf("%s started\n", __FUNCTION__);

    uint32_t addr = IPV4_ADDR(1,1,1,1);
    struct cr_filter filters[] = {
        {
            .key = CTA_TUPLE_ORIG,
            .max = CTA_TUPLE_MAX,
            .compare_len = 0
        },
        {
            .key = CTA_TUPLE_IP,
            .max = CTA_IP_MAX,
            .compare_len = 0
        },
        {
            .key = CTA_IP_V4_DST,
            .max = 0,
            .compare_len = 4,
            .compare = (char*)&addr 
        }
    };

    conditional_init(ADDRESS_FAMILY_UNSPECIFIED, filters, sizeof(filters) / sizeof(struct cr_filter));
    struct cr_img out;
    dump_nf_cts(0, &out);
    conditional_free();
}