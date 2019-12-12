#include "../ipthelper.h"
#include <stdio.h>

char* last_error(void);

void main(){
    init_helper4();
    void *h = init_handle4("filter");
    int r1 = execute_command4("iptables -v  -A INPUT -s 1.1.1.1 -m comment --comment a -j ACCEPT", h);
puts("======");
    int r2 = execute_command4("iptables -A INPUT -s 1.1.1.2 -m comment --comment b -j ACCEPT", h);
	printf("done -> %d %d %s\n", r1, r2, last_error());
	iptc_commit(h);
}

