# r7-r3 IPC policy evidence

This independent increment adds exactly three permission atoms to r7-r2: servicemanager may transfer Binder objects to the dedicated worker; system_server may use a worker file descriptor and write to its pipe. It adds no reverse servicemanager call, pipe getattr permission, new type, broad attribute or permissive rule.

The actual Magisk offline delta and full parses produced identical candidate bytes. Their separate comparisons passed 22 checks each. After the old module was retired, Root applied the delta once under Enforcing. The actual live audit passed 24 checks: exactly the three atoms were added, none removed, and the other audited TE/non-TE tables, roles, users, attributes, contexts and GENFS records remained unchanged.

The live serialization differs from the offline candidate. This establishes semantic equivalence, not byte identity. The exact delta keeps its original proposed-rule filename/comments as historical source; the summary records the subsequent actual audit.

The missing edges and static dependencies support this narrow repair but do not establish a sole cause for all prior failures. Rules are type-wide. Current health and business behavior require separate fresh tasks under the new combination. Raw compiled policies, private diagnostics, process identities and original action records are excluded.
