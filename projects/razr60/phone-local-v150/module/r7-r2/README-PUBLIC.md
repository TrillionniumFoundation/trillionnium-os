# r7-r2 module review sources

This increment preserves the original phone-local model, thirteen provider sources, native runtime, executor and budgets. The policy source adds exactly four file-read permissions from the dedicated worker domain to servicemanager_prop: getattr, open, read, and map. The actual live-policy audit passed 26 checks and established this exact semantic change with all other checked tables unchanged.

The module uses a new release namespace. It retains the existing action journal and both original timed-out actions, checks their original terminal cleanup, and verifies the existing provider payload instead of replacing it. Historical failures remain part of their original combinations.

These are review sources, not an installable package. The public projection index records each original SHA-256 and public byte hash. Private retained-claim digests, boot/process bindings, configuration digests and operation evidence references use explicit placeholders. Production seals, archives, credentials, prior task receipts and raw policy binaries are not distributed here.

The privately retained exact archive is 2,138,009 bytes, SHA-256 f0c7abb46bc0b119e9296390ad845f6ff53992e669f747fb9a558206eb2003cf; its module manifest SHA-256 is 1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd. The archive builder normalized uid/gid to zero and verified its members. This records the observed build and readback, not an independently reproduced binary build.

## Installation history

The first installer stopped in its preflight before unpacking or starting a role: its GNU chroot could not read /sys/fs/selinux/enforce. The original installer and failed output were preserved. A separate second operator required the exact failed original output and absence of installed state, then read the existing host SELinux view through /proc/1/root/sys/fs/selinux/ and used a new output directory. It changed neither the sealed module nor its policy.

The second install and readiness observations completed with zero host, actor and phone exit statuses. Readiness checked 89 startup originals, all 67 module files, 65 module sums, 44 payloads and the 22 existing provider/config/service files. Large prior evidence was hashed rather than repeatedly exported as base64.

Readiness and policy audit do not qualify business tasks, cancellation, fold states, cold boot or daily use. New health and business outcomes belong to their own versioned checkpoint.
