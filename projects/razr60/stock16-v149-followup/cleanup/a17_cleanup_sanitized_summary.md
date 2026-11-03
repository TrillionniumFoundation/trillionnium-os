# RAZR60 old A17 UI cleanup — final verified accounting

**State: closed within the fixed inventory scope.** All approved obsolete-output and duplicate-transfer targets were removed. The fixed magic scan has zero unclassified items. Source, assets, configs, build scripts, original inputs/toolchains and current A16 dependencies remain protected.

Across six distinct hosts, **4,763 exact targets covering 3,611,735 filesystem files** were deleted. Their measured file allocation totals **173,518,000,128 B (161.601 GiB)**. This is exact removed-file allocation, not a claim of net filesystem free-space growth.

## Per-host results

| Host | Targets | Files | Deleted allocated B | Sum of observed df deltas B | Available B at final snapshot | UTC |
|---|---:|---:|---:|---:|---:|---|
| main | 4,590 | 3,610,284 | 40,485,056,512 | 41,397,940,224 + first 55 unmeasured | 376,724,529,152 | 2026-11-03T12:13:38.045314+00:00 |
| pocket4 | 159 | 159 | 129,180,299,264 | 129,180,217,344 | 509,259,071,488 | 2026-11-03T12:09:28.860384+00:00 |
| rog | 12 | 1,290 | 3,762,520,064 | 3,762,614,272 | 205,646,467,072 | 2026-11-03T12:09:33.521095+00:00 |
| desktop | 2 | 2 | 90,124,288 | 90,124,288 | 111,885,537,280 | 2026-11-03T12:09:22.968462+00:00 |
| ai395 | 0 | 0 | 0 | 0 | 1,243,032,379,392 | 2026-11-03T12:08:46.977395+00:00 |
| x230 | 0 | 0 | 0 | 0 | 36,168,916,992 | 2026-11-03T12:09:36.564898+00:00 |

Measured batch df deltas sum to **174,430,896,128 B**, with one unmeasured batch. The first 55 Mac targets remain accurately recorded as pinned absence reconciliation with df = null. These separate windows are affected by concurrent activity and filesystem allocation behavior; they are not one end-to-end measurement.

## Exact deletion batches

| Host / batch | Files | Allocated B | Observed df delta B |
|---|---:|---:|---:|
| main / mac_initial_55 | 55 | 794,931,200 | not recorded |
| main / mac_root_remaining_63 | 63 | 410,382,336 | 402616320 |
| main / captured24 | 24 | 167,976,960 | 167915520 |
| main / class331 | 3,568,498 | 17,098,063,872 | 18796666880 |
| main / nonclass2141 | 2,141 | 17,777,573,888 | 17775640576 |
| main / media1_localclass861 | 861 | 178,843,648 | 177455104 |
| main / archives215 | 215 | 1,286,565,888 | 1286447104 |
| main / residual_class38076 | 38,076 | 183,881,728 | 204914688 |
| main / historical3 | 3 | 108,085,248 | 108048384 |
| main / falsehold11 | 11 | 490,741,760 | 490610688 |
| main / final5 | 5 | 39,976,960 | 39989248 |
| main / extensionless81 | 81 | 4,427,776 | 4136960 |
| main / unusual33 | 33 | 40,587,264 | 40509440 |
| main / three-duplicate-dex | 3 | 27,672,576 | 27639808 |
| main / outputs157 | 157 | 667,344,896 | 666943488 |
| main / fixed111-final58 | 58 | 1,208,000,512 | 1208406016 |
| rog / rog_old_ui | 1,290 | 3,762,520,064 | 3762614272 |
| desktop / desktop_old_ui | 2 | 90,124,288 | 90124288 |
| pocket4 / signing54 | 54 | 2,443,317,248 | 2443309056 |
| pocket4 / images98 | 98 | 125,095,723,008 | 125095665664 |
| pocket4 / held_images7 | 7 | 1,641,259,008 | 1641242624 |

## Source preservation and final checks

The final Mac verification found all **4,590 exact targets absent**, with zero duplicate or nested target counting. It reread **1,677 distinct retained content pins** with zero changes, including 265 source-only archives, 1,105 resource XML files, 191 original tools, 29 original tool/debug inputs, 59 retained containers, 15 current input sentinels and 15 new preservation ZIP/map files. Some groups overlap; their counts are not summed as unique files.

The final 58 targets consisted of 49 old delivery containers and nine redundant source-transfer chunks. All three whole source archives that exactly match those chunks remain, as do five source-only fragments without a duplicate whole archive. Its retained source tree contained 1,060,585 entries and 19,028,358,474 logical bytes; before/after SHA-256 was identical: `d798e35f4cf7541c385f8a207bf0a78dbc0d7f9eb9c6794d9a7a1aa9420f8832`. All 16 preservation/proof pins and current sentinels passed.

Independent preservation review verified 28 original RRO source members, 1,171 Java-serialized telephone assets, and nine SQLite assets in each of two distinct delivery origins. It read 1,208 unique preserved blobs from the ZIPs and rechecked their SHA-256. The obsolete APEX retained all six payload configuration files plus its manifest; all 20 payload file identities matched the original build receipt. Raw binary XML and ARSC remain resource provenance, not a claim of recovered editable upstream source.

New audit and preservation files occupy **1,139,609,600 allocated B** in the final snapshots. The allocation accounting balance is **172,378,390,528 B** after that recorded cost; it is not measured net free space.

| Host | New audit allocated B | Source/resource/provenance allocated B | Relationship |
|---|---:|---:|---|
| main | 833,847,296 | 351,928,320 | source is a subset of audit |
| pocket4 | 11,517,952 | 0 | no new source archive |
| rog | 271,982,592 | 0 | no new source archive |
| desktop | 880,640 | 21,364,736 | source is outside audit; added once |
| ai395 | 8,192 | 0 | no new source archive |
| x230 | 8,192 | 0 | no new source archive |

The main audit cost includes its separate container-review proof directory. All archive/map SHA-256 values, per-batch source-tree seals and receipt hashes are in the accompanying JSON. Private path-level manifests and deletion journals remain on the originating hosts.

## Fixed residual classification

The fixed scan read recognized magic from all **1,254,267 regular files** in the known Mac project scope. Its 1,436 initially unresolved binary/container entries are now classified without overlap:

| Final disposition of the original 1,436 | Count |
|---|---:|
| Retained binary XML resources | 1,105 |
| Deleted unusual runtime/cache files | 33 |
| Deleted duplicate DEX | 3 |
| Deleted historical outputs | 155 |
| Deleted after final container/source preservation | 52 |
| Retained source/resource/current/original containers | 59 |
| Retained original tool/debug inputs | 29 |
| Unclassified | 0 |

The 81 native/test outputs were already classified as generated, so they are not counted again in those 1,436. Two obsolete HEPTA46/47 outputs and six sibling duplicate source chunks were also removed under their explicit manifests. The current HEPTA49 payload and all current A16 inputs remain.

## Scope and measurement limits

- Deleted allocated bytes sum st_blocks * 512 for the exact old files actually removed; they are neither candidate sizes nor a physical net-free claim.
- Independent per-batch df observations can differ from file allocation because of concurrent activity, metadata, compression, copy-on-write and delayed accounting. Their sum is not one end-to-end filesystem measurement.
- The first 55 Mac files were reconciled absent against pinned intent after a permission stop; that batch has no final df observation and remains null.
- New source preservation and audit storage is reported separately at the final snapshots. Main source ZIPs, maps and extracted source trees are subsets of main audit storage. Desktop source ZIP is outside its audit directory and counted once.
- The main audit cost includes the separate temporary container-review proof directory. Snapshot self-writes, later small summary copies, runtime job logs and new A16 builds are excluded. Current available space is a per-host timestamped observation, not aggregate cleanup reclaim.
- Source-archive allocation uses the final stat snapshot; it may differ from the allocation immediately after writing. SHA-256 content pins remain identical.
- Main and Mac are one host. Previously absent cold archives and earlier migrations are excluded. Overlapping protected source trees and embedded member counts are not added to deleted file counts.
- Nine byte-identical redundant source-transfer chunks are accounted separately from old compiled outputs. All three equivalent whole source archives and the five source-only chunks without a whole duplicate remain.
- Raw Android binary XML, ARSC, SQLite and serialized assets retain source/resource provenance. This does not assert that every upstream source file has been reconstructed or that an old binary is independently rebuildable.
- Some removed historical deliveries contained captured upstream runtime or factory ELF copies. They are obsolete copies, not claimed as binaries compiled by this project. Actual original toolchains and current inputs remain protected.
- Bounded lsof -b no-hit checks carried warnings and are not complete all-system open-descriptor proofs; exact process argv and current dependency scans also showed no target references.
- Scope is the known project and explicitly bounded development roots, with a fixed complete regular-file magic scan on the Mac project. Unrelated projects and every file on every host are outside this conclusion.

Cleanup performed **zero phone, USB, ADB or installed DSU operations**.
