#pragma once

#include <stdint.h>

extern "C"
{
	struct cr_node
	{
		struct cr_node* next;
		char data[1];
	};
	struct cr_img
	{
		struct cr_node* start;
	};
	
	struct cr_filter
	{
		int32_t key; /* e.g CTA_PROTOINFO */
		uint16_t max; /* e.g CTA_PROTOINFO_MAX, or 0 if doing comparison */
		uint16_t compare_len; /* comparison length, only used if max == 0 */
		union
		{
			char* compare; /* Value to compare with */
			void* internal;
		};
	}  __attribute__((aligned(2))) __attribute__((packed));

	void restore_mark_init(uint32_t mark, uint32_t mark_mask);
	void restore_mark_free();
	
	int dump_nf_cts(bool expectations, struct cr_img* out);
	int restore_nf_cts(bool expectation, char* data, int data_len);
	void cr_free(cr_img* img);
	int cr_length(cr_node* node);
	int cr_constant(const char* key);
	
	void conditional_free();
	void conditional_init(int address_family, cr_filter* filters, int filters_len);
	bool conditional_filter(struct nlmsghdr *nlh);
}