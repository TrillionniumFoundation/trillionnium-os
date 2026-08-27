#ifndef TRILLIONNIUM_PROVIDER_POST_EXEC_BOOTSTRAP_H
#define TRILLIONNIUM_PROVIDER_POST_EXEC_BOOTSTRAP_H

#if !defined(__x86_64__) && !defined(__aarch64__)
#error "Trillionnium provider bootstrap supports only reviewed 64-bit architectures"
#endif

#ifndef __ASSEMBLER__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This function is an internal final-image entry, not a provider-callable API.
 * It must be linked hidden and reached only through the receipt-bound entry
 * trampoline or the unique final-ELF preinit slot.
 */
__attribute__((visibility("hidden"), noinline, used)) void
trillionnium_provider_post_final_exec_bootstrap(void);

#ifdef __cplusplus
}
#endif

#endif

#endif
