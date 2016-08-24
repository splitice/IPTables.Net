#pragma once
#include <libiptc/libiptc.h>
#include <libiptc/libip6tc.h>

#if defined(_MSC_VER)
//  Microsoft 
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#elif defined(_GCC)
//  GCC
#define EXPORT __attribute__((visibility("default")))
#define IMPORT
#else
//  do nothing and hope for the best?
#define EXPORT
#define IMPORT
#pragma warning Unknown dynamic link import/export semantics.
#endif

#ifdef __cplusplus
extern "C" {
#endif
	extern EXPORT const char* output_rule4(const struct ipt_entry *e, void *h, const char *chain, int counters);
	extern EXPORT const char* output_rule6(const struct ip6t_entry *e, void *h, const char *chain, int counters);
	extern EXPORT int execute_command6(const char* rule, void *h);
	extern EXPORT int execute_command4(const char* rule, void *h);
	extern EXPORT int init_helper4(void);
	extern EXPORT int init_helper6(void);
	extern EXPORT void* init_handle4(const char* table);
	extern EXPORT void* init_handle6(const char* table);
	extern EXPORT char* ipth_bpf_compile(const char* dltname, const char* program, int length);
	extern EXPORT void ipth_free(void* ptr);
	extern EXPORT void* set_modprobe(const char* program);
#ifdef __cplusplus
}
#endif
