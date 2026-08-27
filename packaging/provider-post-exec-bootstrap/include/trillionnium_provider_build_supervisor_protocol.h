#ifndef TRILLIONNIUM_PROVIDER_BUILD_SUPERVISOR_PROTOCOL_H
#define TRILLIONNIUM_PROVIDER_BUILD_SUPERVISOR_PROTOCOL_H

#include <stdint.h>

#define TPBS_MAGIC UINT32_C(0x54505331)
#define TPBS_VERSION UINT16_C(1)
#define TPBS_CHALLENGE_BYTES 32u
#define TPBS_ATTEMPT_BYTES 64u
#define TPBS_CONTAINER_ID_BYTES 64u
#define TPBS_CONTAINER_NAME_BYTES 128u
#define TPBS_INIT_FD_COUNT 6u

enum tpbs_kind {
    TPBS_HELLO = 1,
    TPBS_INIT = 2,
    TPBS_CID_REQUEST = 3,
    TPBS_CID_RESPONSE = 4,
    TPBS_READY = 5,
};

enum tpbs_role {
    TPBS_ROLE_SUCCESS = 1,
    TPBS_ROLE_FAILURE = 2,
};

struct __attribute__((packed)) tpbs_header {
    uint32_t magic;
    uint16_t version;
    uint16_t kind;
    uint32_t size;
    uint32_t flags;
};

struct __attribute__((packed)) tpbs_hello {
    struct tpbs_header header;
    uint8_t reserved[16];
};

struct __attribute__((packed)) tpbs_init {
    struct tpbs_header header;
    uint8_t challenge[TPBS_CHALLENGE_BYTES];
    uint32_t descriptor_count;
    uint32_t worker_pid;
    uint32_t worker_uid;
    uint32_t worker_gid;
};

struct __attribute__((packed)) tpbs_cid_request {
    struct tpbs_header header;
    uint8_t challenge[TPBS_CHALLENGE_BYTES];
    uint8_t attempt[TPBS_ATTEMPT_BYTES];
};

struct __attribute__((packed)) tpbs_cid_response {
    struct tpbs_header header;
    uint8_t challenge[TPBS_CHALLENGE_BYTES];
    uint32_t descriptor_count;
    uint8_t attempt[TPBS_ATTEMPT_BYTES];
};

struct __attribute__((packed)) tpbs_ready {
    struct tpbs_header header;
    uint8_t challenge[TPBS_CHALLENGE_BYTES];
    uint32_t role;
    uint32_t worker_status;
    uint32_t descriptor_count;
    uint64_t candidate_device;
    uint64_t candidate_inode;
    uint8_t container_id[TPBS_CONTAINER_ID_BYTES];
    uint8_t container_name[TPBS_CONTAINER_NAME_BYTES];
};

_Static_assert(sizeof(struct tpbs_header) == 16, "tpbs header size");
_Static_assert(sizeof(struct tpbs_hello) == 32, "tpbs hello size");
_Static_assert(sizeof(struct tpbs_init) == 64, "tpbs init size");
_Static_assert(sizeof(struct tpbs_cid_request) == 112, "tpbs cid request size");
_Static_assert(sizeof(struct tpbs_cid_response) == 116, "tpbs cid response size");
_Static_assert(sizeof(struct tpbs_ready) == 268, "tpbs ready size");

#endif
