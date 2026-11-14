/* Hepta one-shot LiteRT-LM runner candidate.
 * Original implementation, 2026-11-11. Upstream API: LiteRT-LM v0.19.1,
 * packaged C API 1.0.0 headers, Apache-2.0. JSON parser: yyjson 0.13.0, MIT.
 * This process only performs inference. It never executes model tool calls.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "engine.h"
#include "conversation.h"
#include "yyjson.h"

_Static_assert(LITERT_LM_C_API_VERSION_MAJOR == 1, "C API major must be 1");
_Static_assert(LITERT_LM_C_API_VERSION_MINOR == 0, "C API minor must be 0");

#define INPUT_LIMIT (1024u * 1024u)
#define OUTPUT_LIMIT (1024u * 1024u)
#define MODEL_RESPONSE_LIMIT (256u * 1024u)
#define INPUT_DEADLINE_MS 10000u
#define MAX_DEADLINE_MS 300000u
#define FINAL_WRITE_MS 500u

enum Phase { PH_INPUT, PH_VALIDATE, PH_CONFIGURE, PH_LOAD, PH_GENERATE,
             PH_CLEANUP, PH_SERIALIZE, PH_PUBLISH };
static const char *const phase_names[] = {"input", "validate", "configure",
    "load", "generate", "cleanup", "serialize", "publish"};
static uint64_t started_ms;
static _Atomic uint64_t deadline_ms;
static atomic_int phase;
static atomic_bool final_claimed;
static atomic_int final_code;
static atomic_bool request_id_ready;
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal cancellation requires lock-free int atomics");
static atomic_int cancel_signal;
static char request_id[65];
static int response_fd = -1;

static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _Exit(70);
    return (uint64_t)t.tv_sec * 1000u + (uint64_t)t.tv_nsec / 1000000u;
}
static void on_signal(int signo) { atomic_store_explicit(&cancel_signal, signo, memory_order_relaxed); }
static bool claim_final(int code) {
    bool expected = false;
    if (!atomic_compare_exchange_strong(&final_claimed, &expected, true)) return false;
    atomic_store(&final_code, code);
    return true;
}

/* At most one JSON is attempted. A stopped/blocked reader can cause a partial
 * record; the caller MUST require a complete record, EOF and observed exit.
 * The watchdog remains able to _Exit even after another thread won the claim.
 */
static bool bounded_write(const char *text, size_t length, uint64_t end) {
    if (length > OUTPUT_LIMIT) return false;
    size_t at = 0;
    while (at < length && now_ms() < end) {
        ssize_t n = write(response_fd, text + at, length - at);
        if (n > 0) { at += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd p = {response_fd, POLLOUT, 0};
            (void)poll(&p, 1, 10);
            continue;
        }
        return false;
    }
    return at == length;
}
static void emergency_exit(const char *status, int code, const char *reason) {
    if (claim_final(code)) {
        char buffer[1400];
        const char *id = atomic_load_explicit(&request_id_ready,
                                              memory_order_acquire)
                             ? request_id : "";
        int p = atomic_load(&phase);
        if (p < PH_INPUT || p > PH_PUBLISH) p = PH_INPUT;
        int n = snprintf(buffer, sizeof(buffer),
            "{\"schema\":\"hepta.litert-once.result.v1\","
            "\"request_id\":\"%s\",\"status\":\"%s\","
            "\"phase\":\"%s\",\"error\":\"%s\","
            "\"inference_completed\":false,\"cleanup\":\"incomplete\","
            "\"sdk_cancel_called\":false,\"process_exit_observed\":false,"
            "\"termination_method\":\"process_exit_without_sdk_cleanup\","
            "\"exit_code_intended\":%d,\"elapsed_ms\":%" PRIu64 ","
            "\"tools_executed\":false,\"business_success_verified\":false,"
            "\"controller_validation_required\":true,"
            "\"publication_requires_complete_json_eof_and_exit\":true}\n",
            id, status, phase_names[p], reason, code, now_ms() - started_ms);
        if (n > 0 && (size_t)n < sizeof(buffer))
            (void)bounded_write(buffer, (size_t)n, now_ms() + FINAL_WRITE_MS);
    } else {
        /* Another terminal publisher owns the sole record. Allow its bounded
         * write to finish, but never let that ownership prevent hard exit. */
        uint64_t end = now_ms() + FINAL_WRITE_MS;
        while (now_ms() < end) {
            struct timespec pause = {0, 5000000};
            (void)nanosleep(&pause, NULL);
        }
    }
    _Exit(code);
}
static void *watchdog(void *unused) {
    (void)unused;
    for (;;) {
        if (cancel_signal)
            emergency_exit("cancelled", 128 + cancel_signal, "signal_received");
        if (now_ms() >= atomic_load(&deadline_ms))
            emergency_exit("deadline_exceeded", 124, "monotonic_deadline");
        struct timespec interval = {0, 5000000};
        (void)nanosleep(&interval, NULL);
    }
    return NULL;
}
static void check_deadline(void) {
    if (cancel_signal)
        emergency_exit("cancelled", 128 + cancel_signal, "signal_received");
    if (now_ms() >= atomic_load(&deadline_ms))
        emergency_exit("deadline_exceeded", 124, "monotonic_deadline");
}

static bool clean_string(const yyjson_val *v, size_t low, size_t high) {
    if (!yyjson_is_str(v)) return false;
    size_t n = yyjson_get_len(v);
    return n >= low && n <= high && !memchr(yyjson_get_str(v), '\0', n);
}
/* yyjson flags=0 and build-time NON_STANDARD/UTF8/depth settings keep the
 * parser strict. Duplicate keys and embedded decoded NUL are rejected here.
 */
static bool unique_tree(const yyjson_val *v, unsigned depth, size_t *nodes) {
    if (!v || depth > 32 || ++*nodes > 16384) return false;
    if (yyjson_is_str(v)) return clean_string(v, 0, INPUT_LIMIT);
    if (yyjson_is_obj(v)) {
        if (yyjson_obj_size(v) > 512) return false;
        size_t i, maximum; yyjson_val *key, *value;
        yyjson_obj_foreach(v, i, maximum, key, value) {
            if (!clean_string(key, 1, 1024)) return false;
            size_t j, total; yyjson_val *other, *other_value;
            yyjson_obj_foreach(v, j, total, other, other_value) {
                (void)other_value;
                if (j >= i) break;
                if (yyjson_get_len(key) == yyjson_get_len(other) &&
                    !memcmp(yyjson_get_str(key), yyjson_get_str(other),
                            yyjson_get_len(key))) return false;
            }
            if (!unique_tree(value, depth + 1, nodes)) return false;
        }
    } else if (yyjson_is_arr(v)) {
        if (yyjson_arr_size(v) > 4096) return false;
        size_t i, maximum; yyjson_val *value;
        yyjson_arr_foreach(v, i, maximum, value)
            if (!unique_tree(value, depth + 1, nodes)) return false;
    }
    return true;
}
static bool keys_allowed(const yyjson_val *obj, const char *const *keys,
                         size_t count) {
    if (!yyjson_is_obj(obj)) return false;
    size_t i, maximum; yyjson_val *key, *value;
    yyjson_obj_foreach(obj, i, maximum, key, value) {
        (void)value;
        bool found = false;
        for (size_t j = 0; j < count; ++j)
            if (yyjson_equals_str(key, keys[j])) { found = true; break; }
        if (!found) return false;
    }
    return true;
}
static bool bounded_integer(const yyjson_val *v, uint64_t low, uint64_t high,
                            uint64_t *out) {
    uint64_t value;
    if (yyjson_is_uint(v)) value = yyjson_get_uint(v);
    else if (yyjson_is_sint(v) && yyjson_get_sint(v) >= 0)
        value = (uint64_t)yyjson_get_sint(v);
    else return false;
    if (value < low || value > high) return false;
    *out = value;
    return true;
}
static bool local_refs_only(const yyjson_val *v) {
    if (yyjson_is_obj(v)) {
        size_t i, maximum; yyjson_val *key, *value;
        yyjson_obj_foreach(v, i, maximum, key, value) {
            if ((yyjson_equals_str(key, "$ref") ||
                 yyjson_equals_str(key, "$dynamicRef")) &&
                (!clean_string(value, 1, 4096) ||
                 yyjson_get_str(value)[0] != '#')) return false;
            if (!local_refs_only(value)) return false;
        }
    } else if (yyjson_is_arr(v)) {
        size_t i, maximum; yyjson_val *value;
        yyjson_arr_foreach(v, i, maximum, value)
            if (!local_refs_only(value)) return false;
    }
    return true;
}
static bool safe_id(const yyjson_val *v) {
    if (!clean_string(v, 1, 64)) return false;
    for (const unsigned char *p = (const unsigned char *)yyjson_get_str(v);
         *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '_' || *p == '-')) return false;
    return true;
}
/* Component-by-component openat prevents symlink traversal. A caller-owned
 * regular descriptor, not the input path, is transferred to the model API.
 */
static int open_absolute(const char *path, bool directory) {
    size_t length = strlen(path);
    if (!length || length >= PATH_MAX || path[0] != '/' || path[length - 1] == '/')
        return -1;
    for (size_t i = 0; i < length; ++i)
        if ((unsigned char)path[i] < 32 || (unsigned char)path[i] == 127) return -1;
    int parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (parent < 0) return -1;
    const char *at = path + 1;
    for (;;) {
        const char *slash = strchr(at, '/');
        size_t n = slash ? (size_t)(slash - at) : strlen(at);
        if (!n || n > NAME_MAX || (n == 1 && at[0] == '.') ||
            (n == 2 && at[0] == '.' && at[1] == '.')) { close(parent); return -1; }
        char component[NAME_MAX + 1]; memcpy(component, at, n); component[n] = 0;
        int flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK;
        if (slash || directory) flags |= O_DIRECTORY;
        int next = openat(parent, component, flags);
        close(parent);
        if (next < 0) return -1;
        parent = next;
        if (!slash) return parent;
        at = slash + 1;
    }
}
static char *message_json(const char *role, const char *text) {
    yyjson_mut_doc *d = yyjson_mut_doc_new(NULL);
    if (!d) return NULL;
    yyjson_mut_val *root = yyjson_mut_obj(d), *array = yyjson_mut_arr(d);
    yyjson_mut_val *part = yyjson_mut_obj(d);
    bool ok = root && array && part &&
        yyjson_mut_obj_add_str(d, root, "role", role) &&
        yyjson_mut_obj_add_str(d, part, "type", "text") &&
        yyjson_mut_obj_add_str(d, part, "text", text) &&
        yyjson_mut_arr_append(array, part) &&
        yyjson_mut_obj_add_val(d, root, "content", array);
    yyjson_mut_doc_set_root(d, root);
    char *result = ok ? yyjson_mut_write(d, 0, NULL) : NULL;
    yyjson_mut_doc_free(d);
    return result;
}
static bool same_file(const struct stat *a, const struct stat *b) {
#if defined(__APPLE__)
    bool precise = a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
                   a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
#else
    bool precise = a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
                   a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
#endif
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size && a->st_mtime == b->st_mtime &&
           a->st_ctime == b->st_ctime && precise;
}
static void copy_error(char out[2048], const char *source) {
    if (!source) source = "SDK call failed without error text";
    size_t i;
    for (i = 0; i < 2047 && source[i]; ++i) {
        unsigned char c = (unsigned char)source[i];
        out[i] = c >= 32 && c < 127 ? (char)c : '?';
    }
    out[i] = 0;
}

int main(int argc, char **argv) {
    (void)argv;
    started_ms = now_ms();
    atomic_init(&deadline_ms, started_ms + INPUT_DEADLINE_MS);
    atomic_init(&phase, PH_INPUT);
    atomic_init(&final_claimed, false);
    atomic_init(&final_code, 70);
    atomic_init(&request_id_ready, false);
    response_fd = dup(STDOUT_FILENO);
    if (response_fd < 0 || fcntl(response_fd, F_SETFD, FD_CLOEXEC) < 0 ||
        fcntl(response_fd, F_SETFL, fcntl(response_fd, F_GETFL) | O_NONBLOCK) < 0 ||
        dup2(STDERR_FILENO, STDOUT_FILENO) < 0) _Exit(74);
    struct sigaction sa; memset(&sa, 0, sizeof(sa)); sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) || sigaction(SIGINT, &sa, NULL)) _Exit(70);
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL)) _Exit(70);
    pthread_t watcher;
    if (pthread_create(&watcher, NULL, watchdog, NULL)) _Exit(70);
    (void)pthread_detach(watcher);

    char error[2048] = "";
    const char *status = "invalid_request";
    int exit_code = 64, sdk_code = 0, model_fd = -1, guard_fd = -1, cache_fd = -1;
    int api_major = -1, api_minor = -1, api_patch = -1;
    bool sdk_started = false, inference_completed = false, model_unchanged = false;
    uint64_t load_time = 0, generation_time = 0, cleanup_time = 0;
    uint64_t context_tokens = 8192, output_tokens = 256, timeout = 60000;
    char *input = NULL, *system_json = NULL, *user_json = NULL, *constraint_json = NULL;
    yyjson_doc *request = NULL, *response = NULL;
    yyjson_mut_doc *result = NULL;
    char *raw_copy = NULL;
    struct stat initial_stat; memset(&initial_stat, 0, sizeof(initial_stat));
    LiteRtLmEngineSettings *settings = NULL;
    LiteRtLmEngine *engine = NULL;
    LiteRtLmSessionConfig *session = NULL;
    LiteRtLmSamplerParams *sampler = NULL;
    LiteRtLmConversationConfig *conversation_config = NULL;
    LiteRtLmConversationOptionalArgs *optional = NULL;
    LiteRtLmConversation *conversation = NULL;
    LiteRtLmThinkingConfig *thinking = NULL;
    LiteRtLmSpeculativeDecodingConfig *speculative = NULL;
    LiteRtLmJsonResponse *native_response = NULL;
    const char *model_path = NULL, *cache_path = NULL, *speculation = "off";
    const char *constraint_type = NULL;
    size_t input_bytes = 0;

#define FAIL(message) do { copy_error(error, (message)); goto cleanup; } while (0)
#define SDK(call) do { check_deadline(); LiteRtLmStatusCode s_ = (call); \
    if (s_ != kLiteRtLmStatusOk) { sdk_code = (int)s_; status = "sdk_error"; \
        exit_code = 70; copy_error(error, litert_lm_get_last_error_message()); \
        goto cleanup; } } while (0)
    if (argc != 1) FAIL("No command-line arguments are accepted; send one JSON request on stdin");
    input = malloc(INPUT_LIMIT + 1);
    if (!input) FAIL("request allocation failed");
    for (;;) {
        check_deadline();
        struct pollfd p = {STDIN_FILENO, POLLIN, 0};
        int ready = poll(&p, 1, 50);
        if (ready < 0 && errno == EINTR) continue;
        if (ready < 0) FAIL("stdin poll failed");
        if (!ready) continue;
        ssize_t n = read(STDIN_FILENO, input + input_bytes,
                         INPUT_LIMIT + 1 - input_bytes);
        if (n < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (n < 0) FAIL("stdin read failed");
        if (!n) break;
        input_bytes += (size_t)n;
        if (input_bytes > INPUT_LIMIT) FAIL("request exceeds 1 MiB");
    }
    atomic_store(&phase, PH_VALIDATE);
    request = yyjson_read(input, input_bytes, 0);
    size_t nodes = 0;
    yyjson_val *root = request ? yyjson_doc_get_root(request) : NULL;
    if (!root || !yyjson_is_obj(root) || !unique_tree(root, 0, &nodes))
        FAIL("strict UTF-8 JSON object required; duplicate keys/NUL/depth/size rejected");
    static const char *const root_keys[] = {"schema", "request_id", "model_path",
        "system_prompt", "prompt", "backend", "max_context_tokens",
        "max_output_tokens", "constraint", "speculation", "deadline_ms", "cache_dir"};
    if (!keys_allowed(root, root_keys, sizeof(root_keys) / sizeof(root_keys[0])))
        FAIL("unknown request field");
    if (!yyjson_equals_str(yyjson_obj_get(root, "schema"), "hepta.litert-once.request.v1"))
        FAIL("request schema must be hepta.litert-once.request.v1");
    yyjson_val *value = yyjson_obj_get(root, "request_id");
    if (!safe_id(value)) FAIL("request_id must be 1..64 ASCII letters/digits/underscore/hyphen");
    memcpy(request_id, yyjson_get_str(value), yyjson_get_len(value) + 1);
    atomic_store_explicit(&request_id_ready, true, memory_order_release);
    value = yyjson_obj_get(root, "deadline_ms");
    if (!bounded_integer(value, 1000, MAX_DEADLINE_MS, &timeout))
        FAIL("deadline_ms must be an integer in 1000..300000");
    atomic_store(&deadline_ms, started_ms + timeout);
    check_deadline();
    value = yyjson_obj_get(root, "backend");
    if (value && !yyjson_equals_str(value, "gpu")) FAIL("only explicit GPU backend is supported");
    value = yyjson_obj_get(root, "max_context_tokens");
    if (value && !bounded_integer(value, 512, 32768, &context_tokens)) FAIL("context bound invalid");
    value = yyjson_obj_get(root, "max_output_tokens");
    if (value && !bounded_integer(value, 1, 2048, &output_tokens)) FAIL("output token bound invalid");
    if (output_tokens >= context_tokens) FAIL("output limit must be below context capacity");
    value = yyjson_obj_get(root, "speculation");
    if (value) {
        if (!(yyjson_equals_str(value, "off") || yyjson_equals_str(value, "on") ||
              yyjson_equals_str(value, "adaptive"))) FAIL("invalid speculation mode");
        speculation = yyjson_get_str(value);
    }
    value = yyjson_obj_get(root, "model_path");
    if (!clean_string(value, 1, PATH_MAX - 1)) FAIL("local absolute model_path required");
    model_path = yyjson_get_str(value);
    size_t path_length = strlen(model_path);
    if (path_length < 10 || strcmp(model_path + path_length - 9, ".litertlm"))
        FAIL("model_path must name a .litertlm file");
    model_fd = open_absolute(model_path, false);
    if (model_fd < 0 || fstat(model_fd, &initial_stat) || !S_ISREG(initial_stat.st_mode) ||
        initial_stat.st_uid != getuid() || initial_stat.st_size <= 0 ||
        (uint64_t)initial_stat.st_size > UINT64_C(68719476736))
        FAIL("model must be an existing caller-owned regular file, without symlink components");
    guard_fd = dup(model_fd);
    if (guard_fd < 0) FAIL("model identity descriptor could not be retained");
    value = yyjson_obj_get(root, "cache_dir");
    if (value) {
        if (!clean_string(value, 1, PATH_MAX - 1)) FAIL("invalid cache_dir");
        cache_path = yyjson_get_str(value);
        cache_fd = open_absolute(cache_path, true);
        struct stat cache_stat;
        if (cache_fd < 0 || fstat(cache_fd, &cache_stat) ||
            cache_stat.st_uid != getuid()) FAIL("cache_dir must be an existing caller-owned directory");
    }
    value = yyjson_obj_get(root, "prompt");
    if (!clean_string(value, 1, 262144)) FAIL("prompt must contain 1..262144 UTF-8 bytes");
    user_json = message_json("user", yyjson_get_str(value));
    value = yyjson_obj_get(root, "system_prompt");
    if (value && !clean_string(value, 0, 65536)) FAIL("system_prompt exceeds its bound");
    system_json = message_json("system", value ? yyjson_get_str(value) : "");
    yyjson_val *constraint = yyjson_obj_get(root, "constraint");
    static const char *const constraint_keys[] = {"type", "value"};
    if (!keys_allowed(constraint, constraint_keys, 2) || yyjson_obj_size(constraint) != 2)
        FAIL("constraint requires exactly type and value");
    yyjson_val *type = yyjson_obj_get(constraint, "type");
    yyjson_val *pattern = yyjson_obj_get(constraint, "value");
    LiteRtLmConstraintType constraint_enum;
    if (yyjson_equals_str(type, "json_schema")) {
        if (!yyjson_is_obj(pattern) || !local_refs_only(pattern)) FAIL("JSON Schema object with local references required");
        constraint_json = yyjson_val_write(pattern, 0, NULL);
        constraint_enum = kLiteRtLmConstraintTypeJsonSchema;
    } else if (yyjson_equals_str(type, "regex")) {
        if (!clean_string(pattern, 1, 65536)) FAIL("regex must contain 1..65536 bytes");
        constraint_json = strdup(yyjson_get_str(pattern));
        constraint_enum = kLiteRtLmConstraintTypeRegex;
    } else FAIL("constraint type must be json_schema or regex; GBNF is not supported");
    constraint_type = yyjson_get_str(type);
    if (!system_json || !user_json || !constraint_json || strlen(constraint_json) > 262144)
        FAIL("message/constraint serialization failed or exceeded bound");

    atomic_store(&phase, PH_CONFIGURE);
    SDK(litert_lm_get_api_version(&api_major, &api_minor, &api_patch));
    if (api_major != 1 || api_minor != 0 || api_patch != 0) {
        status = "runtime_version_mismatch"; exit_code = 70;
        FAIL("runner is qualified only against C API 1.0.0");
    }
    SDK(litert_lm_set_min_log_level(kLiteRtLmLogSeverityError));
    sdk_started = true;
    int transferred_fd = model_fd;
    model_fd = -1; /* Ownership is taken even if creation subsequently fails. */
    SDK(litert_lm_engine_settings_create_from_raw_file_descriptor(
        transferred_fd, "gpu", NULL, NULL, &settings));
    SDK(litert_lm_engine_settings_set_max_num_tokens(settings, (int)context_tokens));
    if (cache_path) SDK(litert_lm_engine_settings_set_cache_dir(settings, cache_path));
    SDK(litert_lm_speculative_decoding_config_create(&speculative));
    LiteRtLmSpeculativeDecodingMode mode = kLiteRtLmSpeculativeDecodingModeOff;
    if (!strcmp(speculation, "on")) mode = kLiteRtLmSpeculativeDecodingModeOn;
    if (!strcmp(speculation, "adaptive")) mode = kLiteRtLmSpeculativeDecodingModeAdaptive;
    SDK(litert_lm_speculative_decoding_config_set_mode(speculative, mode));
    SDK(litert_lm_engine_settings_set_speculative_decoding_config(settings, speculative));
    atomic_store(&phase, PH_LOAD);
    uint64_t mark = now_ms();
    SDK(litert_lm_engine_create(settings, &engine));
    load_time = now_ms() - mark;
    SDK(litert_lm_session_config_create(&session));
    SDK(litert_lm_session_config_set_max_output_tokens(session, (int)output_tokens));
    SDK(litert_lm_sampler_params_create(kLiteRtLmSamplerTypeGreedy, &sampler));
    SDK(litert_lm_sampler_params_set_seed(sampler, 42));
    SDK(litert_lm_session_config_set_sampler_params(session, sampler));
    SDK(litert_lm_conversation_config_create(&conversation_config));
    SDK(litert_lm_conversation_config_set_session_config(conversation_config, session));
    SDK(litert_lm_conversation_config_set_system_message(conversation_config, system_json));
    SDK(litert_lm_conversation_config_set_enable_constrained_decoding(conversation_config, true));
    SDK(litert_lm_conversation_config_set_constraint_provider(conversation_config,
        kLiteRtLmConstraintProviderTypeLlGuidance));
    SDK(litert_lm_thinking_config_create(&thinking));
    SDK(litert_lm_thinking_config_set_enable_thinking(thinking, false));
    SDK(litert_lm_conversation_config_set_thinking_config(conversation_config, thinking));
    SDK(litert_lm_conversation_create(engine, conversation_config, &conversation));
    SDK(litert_lm_conversation_optional_args_create(&optional));
    SDK(litert_lm_conversation_optional_args_set_max_output_tokens(optional, (int)output_tokens));
    SDK(litert_lm_conversation_optional_args_set_constraint(optional, constraint_enum, constraint_json));
    atomic_store(&phase, PH_GENERATE);
    mark = now_ms();
    SDK(litert_lm_conversation_send_message(conversation, user_json, NULL, optional, &native_response));
    generation_time = now_ms() - mark;
    const char *native_json = NULL;
    SDK(litert_lm_json_response_get_string(native_response, &native_json));
    if (!native_json || strnlen(native_json, MODEL_RESPONSE_LIMIT + 1) > MODEL_RESPONSE_LIMIT) {
        status = "response_invalid"; exit_code = 70; FAIL("model response missing or exceeds 256 KiB");
    }
    raw_copy = strdup(native_json);
    response = yyjson_read(native_json, strlen(native_json), 0);
    nodes = 0;
    if (!raw_copy || !response || !yyjson_is_obj(yyjson_doc_get_root(response)) ||
        !unique_tree(yyjson_doc_get_root(response), 0, &nodes)) {
        status = "response_invalid"; exit_code = 70; FAIL("SDK response is not a bounded strict JSON object");
    }
    inference_completed = true;
    status = "response_received"; exit_code = 0;

cleanup:
    atomic_store(&phase, PH_CLEANUP);
    {
        uint64_t cleanup_started = now_ms();
        /* All SDK operations, including deletion, remain on this one thread. */
        if (sdk_started) {
        litert_lm_json_response_delete(native_response);
        litert_lm_conversation_delete(conversation);
        litert_lm_conversation_optional_args_delete(optional);
        litert_lm_conversation_config_delete(conversation_config);
        litert_lm_thinking_config_delete(thinking);
        litert_lm_sampler_params_delete(sampler);
        litert_lm_session_config_delete(session);
        litert_lm_speculative_decoding_config_delete(speculative);
        litert_lm_engine_delete(engine);
        litert_lm_engine_settings_delete(settings);
        }
        cleanup_time = now_ms() - cleanup_started;
    }
    if (guard_fd >= 0) {
        struct stat after;
        model_unchanged = !fstat(guard_fd, &after) && same_file(&initial_stat, &after);
        close(guard_fd);
        if (!model_unchanged && !exit_code) {
            status = "model_changed"; exit_code = 70; inference_completed = false;
            copy_error(error, "model file metadata changed during inference");
        }
    }
    if (model_fd >= 0) close(model_fd);
    if (cache_fd >= 0) close(cache_fd);
    check_deadline();
    atomic_store(&phase, PH_SERIALIZE);
    result = yyjson_mut_doc_new(NULL);
    yyjson_mut_val *out = result ? yyjson_mut_obj(result) : NULL;
    if (!out) emergency_exit("internal_error", 70, "result_allocation_failed");
    yyjson_mut_doc_set_root(result, out);
    bool ok = true;
#define ADD_STR(key, val) do { ok = yyjson_mut_obj_add_str(result, out, (key), (val)) && ok; } while (0)
#define ADD_BOOL(key, val) do { ok = yyjson_mut_obj_add_bool(result, out, (key), (val)) && ok; } while (0)
#define ADD_INT(key, val) do { ok = yyjson_mut_obj_add_sint(result, out, (key), (int64_t)(val)) && ok; } while (0)
    ADD_STR("schema", "hepta.litert-once.result.v1");
    ADD_STR("request_id", atomic_load(&request_id_ready) ? request_id : "");
    ADD_STR("status", status);
    ADD_STR("runtime_release_expected", "v0.19.1");
    ADD_INT("api_major", api_major); ADD_INT("api_minor", api_minor); ADD_INT("api_patch", api_patch);
    ADD_STR("backend_requested", "gpu");
    ADD_BOOL("hardware_execution_independently_verified", false);
    ADD_BOOL("automatic_backend_fallback_requested", false);
    ADD_STR("speculation_requested", speculation);
    ADD_STR("constraint_type", constraint_type ? constraint_type : "");
    ADD_INT("max_context_tokens", context_tokens); ADD_INT("max_output_tokens", output_tokens);
    ADD_BOOL("inference_completed", inference_completed);
    ADD_STR("cleanup", sdk_started ? "sdk_delete_returned" : "sdk_not_started");
    ADD_BOOL("process_exit_observed", false); ADD_BOOL("sdk_cancel_called", false);
    ADD_BOOL("tools_executed", false); ADD_BOOL("business_success_verified", false);
    ADD_BOOL("controller_validation_required", true);
    ADD_BOOL("publication_requires_complete_json_eof_and_exit", true);
    ADD_BOOL("external_exec_watchdog_required", true);
    ADD_STR("deadline_scope", "main_entry_through_publication");
    ADD_STR("cache_path_check", cache_path ? "caller_owned_directory_preflight_only" : "not_set");
    ADD_BOOL("model_metadata_unchanged", model_unchanged);
    ADD_BOOL("model_sha256_verified_by_runner", false);
    ADD_INT("model_bytes", initial_stat.st_size);
    ADD_INT("sdk_status_code", sdk_code); ADD_STR("error", error);
    ADD_INT("exit_code_intended", exit_code);
    ADD_INT("load_ms", load_time); ADD_INT("generation_ms", generation_time);
    ADD_INT("cleanup_ms", cleanup_time); ADD_INT("elapsed_ms", now_ms() - started_ms);
    if (response && inference_completed) {
        yyjson_mut_val *copy = yyjson_val_mut_copy(result, yyjson_doc_get_root(response));
        ok = copy && yyjson_mut_obj_add_val(result, out, "response", copy) && ok;
        ADD_STR("raw_response_json", raw_copy);
    }
    size_t output_length = 0;
    char *output = ok ? yyjson_mut_write(result, YYJSON_WRITE_NEWLINE_AT_END, &output_length) : NULL;
    if (!output || output_length > OUTPUT_LIMIT)
        emergency_exit("output_limit", 70, "final_response_serialization_failed_or_oversized");
    /* No successful publication precedes completion of SDK destructors. */
    check_deadline();
    atomic_store(&phase, PH_PUBLISH);
    if (claim_final(exit_code)) {
        uint64_t end = now_ms() + FINAL_WRITE_MS;
        uint64_t overall = atomic_load(&deadline_ms);
        if (end > overall) end = overall;
        if (!bounded_write(output, output_length, end)) _Exit(74);
    } else {
        uint64_t end = now_ms() + FINAL_WRITE_MS;
        while (now_ms() < end) {
            struct timespec pause = {0, 5000000};
            (void)nanosleep(&pause, NULL);
        }
        _Exit(atomic_load(&final_code));
    }
    /* _Exit avoids unrelated shared-library exit hooks after publication.
     * Only the parent can observe this actual process exit. */
    _Exit(exit_code);
}
