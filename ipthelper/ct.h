#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif
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
	void cr_free(struct cr_img* img);
	int cr_length(struct cr_node* node);
	void cr_output(struct cr_node* node);
	int cr_constant(const char* key);
	bool cr_extract_field(struct cr_filter* filter,
		int filter_len,
		struct nlmsghdr *nlh,
		void* output,
		int output_len);
	
	void conditional_free();
	void conditional_init(int address_family, struct cr_filter* filters, int filters_len);
	bool conditional_filter(struct nlmsghdr *nlh);
	
#ifdef __cplusplus
}
#endif