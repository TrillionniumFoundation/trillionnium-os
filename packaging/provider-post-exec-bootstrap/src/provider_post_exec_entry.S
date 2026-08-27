#include "trillionnium_provider_post_exec_bootstrap.h"

.hidden trillionnium_provider_post_final_exec_bootstrap

#if defined(__x86_64__)
.section .text.trillionnium_provider_post_final_exec_entry,"ax",@progbits
.globl trillionnium_provider_post_final_exec_entry
.hidden trillionnium_provider_post_final_exec_entry
.type trillionnium_provider_post_final_exec_entry,@function
trillionnium_provider_post_final_exec_entry:
  /* Preserve the initial stack and the rtld-finalizer register required by
   * the x86-64 process-entry ABI before entering the original CRT. */
  push %r15
  push %rdx
  call trillionnium_provider_post_final_exec_bootstrap
  pop %rdx
  pop %r15
  jmp _start
.size trillionnium_provider_post_final_exec_entry,.-trillionnium_provider_post_final_exec_entry
#elif defined(__aarch64__)
.section .text.trillionnium_provider_post_final_exec_entry,"ax",%progbits
.globl trillionnium_provider_post_final_exec_entry
.hidden trillionnium_provider_post_final_exec_entry
.type trillionnium_provider_post_final_exec_entry,%function
trillionnium_provider_post_final_exec_entry:
  /* Static AArch64 begins with a 16-byte-aligned stack. Preserve the entry
   * stack plus the argument/link registers before the freestanding call. */
  stp x29, x30, [sp, #-16]!
  stp x0, x1, [sp, #-16]!
  stp x2, x3, [sp, #-16]!
  bl trillionnium_provider_post_final_exec_bootstrap
  ldp x2, x3, [sp], #16
  ldp x0, x1, [sp], #16
  ldp x29, x30, [sp], #16
  b _start
.size trillionnium_provider_post_final_exec_entry,.-trillionnium_provider_post_final_exec_entry
#endif

.section .note.GNU-stack,"",%progbits
