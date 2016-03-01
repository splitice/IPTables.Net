#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <string.h>
#include <net/if_arp.h>
#include <sys/wait.h>
#include <sched.h>
#include <sys/mount.h>
#include <net/if.h>
#include <linux/sockios.h>
#include <libnl3/netlink/msg.h>
#include <assert.h>
#include <stdint.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <cstring>

#include "common.h"
#include "libnetlink.h"
#include "ct.h"

struct cmp_str
{
	bool operator()(char const *a, char const *b)
	{
		return std::strcmp(a, b) < 0;
	}
};

static std::map<const char*, uint16_t, cmp_str> constants = {
	{ "CTA_UNSPEC", CTA_UNSPEC },
	{ "CTA_TUPLE_ORIG", CTA_TUPLE_ORIG },
	{ "CTA_TUPLE_REPLY", CTA_TUPLE_REPLY },
	{ "CTA_STATUS", CTA_STATUS },
	{ "CTA_PROTOINFO", CTA_PROTOINFO },
	{ "CTA_HELP", CTA_HELP },
	{ "CTA_NAT_SRC", CTA_NAT_SRC },
	{ "CTA_NAT", CTA_NAT },
	{ "CTA_TIMEOUT", CTA_TIMEOUT },
	{ "CTA_MARK", CTA_MARK },
	{ "CTA_COUNTERS_ORIG", CTA_COUNTERS_ORIG },
	{ "CTA_COUNTERS_REPLY", CTA_COUNTERS_REPLY },
	{ "CTA_USE", CTA_USE },
	{ "CTA_ID", CTA_ID },
	{ "CTA_NAT_DST", CTA_NAT_DST },
	{ "CTA_TUPLE_MASTER", CTA_TUPLE_MASTER },
	{ "CTA_NAT_SEQ_ADJ_ORIG", CTA_NAT_SEQ_ADJ_ORIG },
	{ "CTA_NAT_SEQ_ADJ_REPLY", CTA_NAT_SEQ_ADJ_REPLY },
	{ "CTA_SECMARK", CTA_SECMARK },
	{ "CTA_ZONE", CTA_ZONE },
	{ "CTA_SECCTX", CTA_SECCTX },
	{ "CTA_TIMESTAMP", CTA_TIMESTAMP },
		
#ifndef OLD_IPTABLES
	{ "CTA_MARK_MASK", CTA_MARK_MASK },
#endif

	{ "CTA_MAX", CTA_MAX },
	{ "CTA_TUPLE_UNSPEC", CTA_TUPLE_UNSPEC },
	{ "CTA_TUPLE_IP", CTA_TUPLE_IP },
	{ "CTA_TUPLE_PROTO", CTA_TUPLE_PROTO },
	{ "CTA_TUPLE_MAX", CTA_TUPLE_MAX },
	{ "CTA_IP_UNSPEC", CTA_IP_UNSPEC },
	{ "CTA_IP_V4_SRC", CTA_IP_V4_SRC },
	{ "CTA_IP_V4_DST", CTA_IP_V4_DST },
	{ "CTA_IP_V6_SRC", CTA_IP_V6_SRC },
	{ "CTA_IP_V6_DST", CTA_IP_V6_DST },
	{ "CTA_IP_MAX", CTA_IP_MAX },
	{ "CTA_PROTO_UNSPEC", CTA_PROTO_UNSPEC },
	{ "CTA_PROTO_NUM", CTA_PROTO_NUM },
	{ "CTA_PROTO_SRC_PORT", CTA_PROTO_SRC_PORT },
	{ "CTA_PROTO_DST_PORT", CTA_PROTO_DST_PORT },
	{ "CTA_PROTO_ICMP_ID", CTA_PROTO_ICMP_ID },
	{ "CTA_PROTO_ICMP_TYPE", CTA_PROTO_ICMP_TYPE },
	{ "CTA_PROTO_ICMP_CODE", CTA_PROTO_ICMP_CODE },
	{ "CTA_PROTO_ICMPV6_ID", CTA_PROTO_ICMPV6_ID },
	{ "CTA_PROTO_ICMPV6_TYPE", CTA_PROTO_ICMPV6_TYPE },
	{ "CTA_PROTO_ICMPV6_CODE", CTA_PROTO_ICMPV6_CODE },
	{ "CTA_PROTO_MAX", CTA_PROTO_MAX },
	{ "CTA_PROTOINFO_UNSPEC", CTA_PROTOINFO_UNSPEC },
	{ "CTA_PROTOINFO_TCP", CTA_PROTOINFO_TCP },
	{ "CTA_PROTOINFO_DCCP", CTA_PROTOINFO_DCCP },
	{ "CTA_PROTOINFO_SCTP", CTA_PROTOINFO_SCTP },
	{ "CTA_PROTOINFO_MAX", CTA_PROTOINFO_MAX },
	{ "CTA_PROTOINFO_TCP_UNSPEC", CTA_PROTOINFO_TCP_UNSPEC },
	{ "CTA_PROTOINFO_TCP_STATE", CTA_PROTOINFO_TCP_STATE },
	{ "CTA_PROTOINFO_TCP_WSCALE_ORIGINAL", CTA_PROTOINFO_TCP_WSCALE_ORIGINAL },
	{ "CTA_PROTOINFO_TCP_WSCALE_REPLY", CTA_PROTOINFO_TCP_WSCALE_REPLY },
	{ "CTA_PROTOINFO_TCP_FLAGS_ORIGINAL", CTA_PROTOINFO_TCP_FLAGS_ORIGINAL },
	{ "CTA_PROTOINFO_TCP_FLAGS_REPLY", CTA_PROTOINFO_TCP_FLAGS_REPLY },
	{ "CTA_PROTOINFO_TCP_MAX", CTA_PROTOINFO_TCP_MAX },
	{ "CTA_PROTOINFO_DCCP_UNSPEC", CTA_PROTOINFO_DCCP_UNSPEC },
	{ "CTA_PROTOINFO_DCCP_STATE", CTA_PROTOINFO_DCCP_STATE },
	{ "CTA_PROTOINFO_DCCP_ROLE", CTA_PROTOINFO_DCCP_ROLE },
	{ "CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ", CTA_PROTOINFO_DCCP_HANDSHAKE_SEQ },
	{ "CTA_PROTOINFO_DCCP_MAX", CTA_PROTOINFO_DCCP_MAX },
	{ "CTA_PROTOINFO_SCTP_UNSPEC", CTA_PROTOINFO_SCTP_UNSPEC },
	{ "CTA_PROTOINFO_SCTP_STATE", CTA_PROTOINFO_SCTP_STATE },
	{ "CTA_PROTOINFO_SCTP_VTAG_ORIGINAL", CTA_PROTOINFO_SCTP_VTAG_ORIGINAL },
	{ "CTA_PROTOINFO_SCTP_VTAG_REPLY", CTA_PROTOINFO_SCTP_VTAG_REPLY },
	{ "CTA_PROTOINFO_SCTP_MAX", CTA_PROTOINFO_SCTP_MAX },
	{ "CTA_COUNTERS_UNSPEC", CTA_COUNTERS_UNSPEC },
	{ "CTA_COUNTERS_PACKETS", CTA_COUNTERS_PACKETS },
	{ "CTA_COUNTERS_BYTES", CTA_COUNTERS_BYTES },
	{ "CTA_COUNTERS32_PACKETS", CTA_COUNTERS32_PACKETS },
	{ "CTA_COUNTERS32_BYTES", CTA_COUNTERS32_BYTES },
	{ "CTA_COUNTERS_MAX", CTA_COUNTERS_MAX },
	{ "CTA_TIMESTAMP_UNSPEC", CTA_TIMESTAMP_UNSPEC },
	{ "CTA_TIMESTAMP_START", CTA_TIMESTAMP_START },
	{ "CTA_TIMESTAMP_STOP", CTA_TIMESTAMP_STOP },
	{ "CTA_TIMESTAMP_MAX", CTA_TIMESTAMP_MAX },
	{ "CTA_NAT_UNSPEC", CTA_NAT_UNSPEC },
		
#ifndef OLD_IPTABLES
	{ "CTA_NAT_V4_MINIP", CTA_NAT_V4_MINIP },
	{ "CTA_NAT_MINIP", CTA_NAT_MINIP },
	{ "CTA_NAT_V4_MAXIP", CTA_NAT_V4_MAXIP },
	{ "CTA_NAT_MAXIP", CTA_NAT_MAXIP },
	{ "CTA_NAT_PROTO", CTA_NAT_PROTO },
	{ "CTA_NAT_V6_MINIP", CTA_NAT_V6_MINIP },
	{ "CTA_NAT_V6_MAXIP", CTA_NAT_V6_MAXIP },
#endif

	{ "CTA_NAT_MAX", CTA_NAT_MAX },
	{ "CTA_PROTONAT_UNSPEC", CTA_PROTONAT_UNSPEC },
	{ "CTA_PROTONAT_PORT_MIN", CTA_PROTONAT_PORT_MIN },
	{ "CTA_PROTONAT_PORT_MAX", CTA_PROTONAT_PORT_MAX },
	{ "CTA_PROTONAT_MAX", CTA_PROTONAT_MAX },
	{ "CTA_NAT_SEQ_UNSPEC", CTA_NAT_SEQ_UNSPEC },
	{ "CTA_NAT_SEQ_CORRECTION_POS", CTA_NAT_SEQ_CORRECTION_POS },
	{ "CTA_NAT_SEQ_OFFSET_BEFORE", CTA_NAT_SEQ_OFFSET_BEFORE },
	{ "CTA_NAT_SEQ_OFFSET_AFTER", CTA_NAT_SEQ_OFFSET_AFTER },
	{ "CTA_NAT_SEQ_MAX", CTA_NAT_SEQ_MAX },
	{ "CTA_EXPECT_UNSPEC", CTA_EXPECT_UNSPEC },
	{ "CTA_EXPECT_MASTER", CTA_EXPECT_MASTER },
	{ "CTA_EXPECT_TUPLE", CTA_EXPECT_TUPLE },
	{ "CTA_EXPECT_MASK", CTA_EXPECT_MASK },
	{ "CTA_EXPECT_TIMEOUT", CTA_EXPECT_TIMEOUT },
	{ "CTA_EXPECT_ID", CTA_EXPECT_ID },
	{ "CTA_EXPECT_HELP_NAME", CTA_EXPECT_HELP_NAME },
	{ "CTA_EXPECT_ZONE", CTA_EXPECT_ZONE },
	{ "CTA_EXPECT_FLAGS", CTA_EXPECT_FLAGS },
#ifndef OLD_IPTABLES
	{ "CTA_EXPECT_CLASS", CTA_EXPECT_CLASS },
	{ "CTA_EXPECT_NAT", CTA_EXPECT_NAT },
	{ "CTA_EXPECT_FN", CTA_EXPECT_FN },
	{ "CTA_EXPECT_MAX", CTA_EXPECT_MAX },
	{ "CTA_EXPECT_NAT_UNSPEC", CTA_EXPECT_NAT_UNSPEC },
	{ "CTA_EXPECT_NAT_DIR", CTA_EXPECT_NAT_DIR },
	{ "CTA_EXPECT_NAT_TUPLE", CTA_EXPECT_NAT_TUPLE },
	{ "CTA_EXPECT_NAT_MAX", CTA_EXPECT_NAT_MAX },
#endif

	{ "CTA_HELP_UNSPEC", CTA_HELP_UNSPEC },
	{ "CTA_HELP_NAME", CTA_HELP_NAME },
		
#ifndef OLD_IPTABLES
	{ "CTA_HELP_INFO", CTA_HELP_INFO },
#endif
	{ "CTA_HELP_MAX", CTA_HELP_MAX },
	{ "CTA_SECCTX_UNSPEC", CTA_SECCTX_UNSPEC },
	{ "CTA_SECCTX_NAME", CTA_SECCTX_NAME },
	{ "CTA_SECCTX_MAX", CTA_SECCTX_MAX },
		
#ifndef OLD_IPTABLES
	{ "CTA_STATS_UNSPEC", CTA_STATS_UNSPEC },
	{ "CTA_STATS_SEARCHED", CTA_STATS_SEARCHED },
	{ "CTA_STATS_FOUND", CTA_STATS_FOUND },
	{ "CTA_STATS_NEW", CTA_STATS_NEW },
	{ "CTA_STATS_INVALID", CTA_STATS_INVALID },
	{ "CTA_STATS_IGNORE", CTA_STATS_IGNORE },
	{ "CTA_STATS_DELETE", CTA_STATS_DELETE },
	{ "CTA_STATS_DELETE_LIST", CTA_STATS_DELETE_LIST },
	{ "CTA_STATS_INSERT", CTA_STATS_INSERT },
	{ "CTA_STATS_INSERT_FAILED", CTA_STATS_INSERT_FAILED },
	{ "CTA_STATS_DROP", CTA_STATS_DROP },
	{ "CTA_STATS_EARLY_DROP", CTA_STATS_EARLY_DROP },
	{ "CTA_STATS_ERROR", CTA_STATS_ERROR },
	{ "CTA_STATS_SEARCH_RESTART", CTA_STATS_SEARCH_RESTART },
	{ "CTA_STATS_MAX", CTA_STATS_MAX },
	{ "CTA_STATS_GLOBAL_UNSPEC", CTA_STATS_GLOBAL_UNSPEC },
	{ "CTA_STATS_GLOBAL_ENTRIES", CTA_STATS_GLOBAL_ENTRIES },
	{ "CTA_STATS_GLOBAL_MAX", CTA_STATS_GLOBAL_MAX },
	{ "CTA_STATS_EXP_UNSPEC", CTA_STATS_EXP_UNSPEC },
	{ "CTA_STATS_EXP_NEW", CTA_STATS_EXP_NEW },
	{ "CTA_STATS_EXP_CREATE", CTA_STATS_EXP_CREATE },
	{ "CTA_STATS_EXP_DELETE", CTA_STATS_EXP_DELETE },
	{ "CTA_STATS_EXP_MAX", CTA_STATS_EXP_MAX }
#endif
};

static cr_filter* filter = NULL;
static int filter_len;
static int filter_af = 0;
static uint32_t restore_mark = 0, restore_mark_mask = -1;

void restore_mark_init(uint32_t mark, uint32_t mark_mask) {
	restore_mark = htonl(mark);
	restore_mark_mask = ~htonl(mark_mask);
}
void restore_mark_free() {
	restore_mark_init(0, 0);
}

uint16_t cr_constant(const char* key)
{
	auto it = constants.find(key);
	if (it == constants.begin())
	{
		return it->second;
	}
	return -1;
}

void conditional_free()
{
	if (filter == NULL) return;
	
	for (int i = 0; i < filter_len; i++)
	{
		if (filter[i].max != 0)
		{
			free(filter[i].internal);
		}
	}
	filter = NULL;
}
void conditional_init(int address_family, cr_filter* filters, int filters_len)
{
	if (filter != NULL)
	{
		conditional_free();
	}
	if (filters_len == 0)
	{
		filter = NULL;
	}
	else
	{
		filter = filters;
		for (int i = 0; i < filters_len; i++)
		{
			if (filters[i].max != 0)
			{
				filters[i].internal = malloc(sizeof(nlattr *) * (filters[i].max + 1));
			}
		}
		
	}
	filter_len = filters_len;
	filter_af = address_family;
}
bool conditional_filter(struct nlmsghdr *nlh)
{
	struct nfgenmsg *msg;
	msg = (nfgenmsg *)NLMSG_DATA(nlh);

	if (filter_af != 0 && msg->nfgen_family != filter_af)
		return false;

	if (filter == NULL)
	{
		return true;
	}
	struct nlattr *tb[CTA_MAX + 1];
	struct nlattr ** tb_cur;
	int err;
	char* data;
	bool ret = true;
	
	err = nlmsg_parse(nlh, sizeof(struct nfgenmsg), tb, CTA_MAX, NULL);
	if (err < 0)
		goto out;
	
	tb_cur = tb;
	for (int i = 0; i < filter_len; i++)
	{
		cr_filter* f = &filter[i];
		
		if (f->max != 0)
		{
			err = nla_parse_nested((struct nlattr **)f->internal, f->max, tb_cur[f->key], NULL);
			if (err < 0)
				goto out;
		
			tb_cur = (nlattr **)f->internal;
		}
		else if (f->compare_len != 0)
		{
			data = (char *)nla_data(tb_cur[f->key]);
			//printf("%s\n", inet_ntoa(*(in_addr*)data));
			
			ret = memcmp(data, f->compare, f->compare_len) == 0;
		}
	}
	
out:
	return ret;
}
static int dump_one_nf(struct nlmsghdr *hdr, void *arg)
{
	struct cr_img *img = (cr_img *)arg;
	
	if (!conditional_filter(hdr))
	{
		return 0;
	}

	cr_node* node = (cr_node*)malloc(sizeof(cr_node*) + hdr->nlmsg_len);
	memcpy(node->data, hdr, hdr->nlmsg_len);
	
	node->next = img->start;
	img->start = node;
		
	return 0;
}

static int ct_restore_callback(struct nlmsghdr *nlh)
{
	struct nfgenmsg *msg;
	struct nlattr *tb[CTA_MAX + 1], *tbp[CTA_PROTOINFO_MAX + 1], *tb_tcp[CTA_PROTOINFO_TCP_MAX + 1];
	int err;

	msg = (nfgenmsg *)NLMSG_DATA(nlh);

	if (msg->nfgen_family != AF_INET && msg->nfgen_family != AF_INET6)
		return 0;

	err = nlmsg_parse(nlh, sizeof(struct nfgenmsg), tb, CTA_MAX, NULL);
	if (err < 0)
		return -1;
	
	if (restore_mark != 0 || restore_mark_mask != -1) {
		uint32_t* mark = (uint32_t*)nla_data(tb[CTA_MARK]);
		//printf("old mark: 0x%08x\n", ntohl(*mark));
		*mark = (*mark & restore_mark_mask) ^ restore_mark;
		//printf("new mark: 0x%08x\n", ntohl(*mark));
	}

	if (!tb[CTA_PROTOINFO])
		return 0;

	err = nla_parse_nested(tbp, CTA_PROTOINFO_MAX, tb[CTA_PROTOINFO], NULL);
	if (err < 0)
		return -1;

	if (!tbp[CTA_PROTOINFO_TCP])
		return 0;

	err = nla_parse_nested(tb_tcp, CTA_PROTOINFO_TCP_MAX, tbp[CTA_PROTOINFO_TCP], NULL);
	if (err < 0)
		return -1;

	if (tb_tcp[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]) {
		struct nf_ct_tcp_flags *flags;

		flags = (nf_ct_tcp_flags *)nla_data(tb_tcp[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]);
		flags->flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		flags->mask |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	if (tb_tcp[CTA_PROTOINFO_TCP_FLAGS_REPLY]) {
		struct nf_ct_tcp_flags *flags;

		flags = (nf_ct_tcp_flags *)nla_data(tb_tcp[CTA_PROTOINFO_TCP_FLAGS_REPLY]);
		flags->flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
		flags->mask |= IP_CT_TCP_FLAG_BE_LIBERAL;
	}

	return 0;
}

/*
Restore from buffer
*/
int restore_nf_cts(bool expectation, char* data, int data_len)
{
	struct nlmsghdr *nlh = NULL;
	int exit_code = -1, sk;
	int i = 0;

	sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		exit_code = sk;
		goto out_img;
	}

	while (i < data_len) {
		int ret;

		nlh = (struct nlmsghdr *)&data[i];
		
		if (i + nlh->nlmsg_len > data_len)
		{
			break;
		}
		i += nlh->nlmsg_len;
		
		if (!expectation)
			if (ct_restore_callback(nlh))
				goto out;

		nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
		ret = do_rtnl_req(sk, nlh, nlh->nlmsg_len, NULL, NULL, NULL);
		if (ret) {
			exit_code = ret;
			goto out;
		}
		
		assert(i <= data_len);
	}
	
	if (i == data_len) {
		exit_code = 0;
	}
	else {
		exit_code = data_len - i;
	}
	
out:
	close(sk);
out_img:
	return exit_code;
}

/**
Dump connections
*/
int dump_nf_cts(bool expectations, struct cr_img* out)
{
	struct cr_img img = {};
	struct {
		struct nlmsghdr nlh;
		struct nfgenmsg g;
	} req;
	int sk, ret;

	pr_info("Dumping netns links\n");

	ret = sk = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (sk < 0) {
		pr_perror("Can't open rtnl sock for net dump");
		*out = { };
		goto out;
	}

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8);

	if (!expectations)
		req.nlh.nlmsg_type |= IPCTNL_MSG_CT_GET;
	else
		req.nlh.nlmsg_type |= IPCTNL_MSG_EXP_GET;

	req.nlh.nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = CR_NLMSG_SEQ;
	req.g.nfgen_family = AF_UNSPEC;

	ret = do_rtnl_req(sk, &req, sizeof(req), dump_one_nf, NULL, &img);
	close(sk);
	
	*out = img;
out:
	return ret;

}

/**
Free all memory in the crimg linked list
*/
void cr_free(cr_img* img)
{
	struct cr_node* node = img->start;
	while (node != NULL)
	{
		struct cr_node* temp = node->next;
		free(node);
		node = temp;
	}
}

int cr_length(cr_node* node)
{
	struct nlmsghdr *hdr = (struct nlmsghdr *)node->data;	
	return hdr->nlmsg_len + sizeof(cr_node*);
}