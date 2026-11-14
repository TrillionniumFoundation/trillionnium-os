# Exact ordinary-App UI-Venus runtime transfer

This CI-only successor rebuilds the existing pinned worker on the macOS producer
and verifies its complete file identity before allowing the unchanged Android
assembler to use it. It adds no model download, model inference, phone operation
or runtime pin change.

The producer runs the original independent build helper from the complete App
source closure. Its fixed NDK revision, compiler wrapper, SDK library identities,
native source boundary, original warning flags, imported VLM functions and ELF
checks remain mandatory. The new whole worker must remain 58,144 bytes with
SHA-256 `5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551`.

The original build receipt remains an unchanged historical file in the runtime
directory. The actual new build receipt is retained separately. The current Git
source SHA, complete App source manifest, CI run and attempt, build helper,
compiler observation, new receipt and full worker identity are bound together.
The Linux consumer verifies the same identities and original packaging API
before exporting the runtime directory to the assembler. A previous attempt,
different source, altered helper, missing member or changed payload is rejected.

The offline tests use the actual preserved public build contract. They exercise
fixed-field and SDK changes, empty compile arguments, invalid run identities,
duplicate and nonfinite metadata, hard links, symlinks and changed binding inputs.
Passing those tests does not establish that CI executed a compiler. Only the
actual producer and consumer results establish this workflow's build outcome.

The App source manifest for this successor is the explicit public Code21 source
derivative. Its identity is different from the retained private Code21 device
build, as recorded in the source manifest and publication derivation. Compiled
Java and native code bytes remain unchanged; complete CI results belong to their
own exact Git commit.
