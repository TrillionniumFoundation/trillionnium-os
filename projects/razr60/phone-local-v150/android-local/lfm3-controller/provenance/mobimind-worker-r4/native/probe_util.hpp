#pragma once
#include "sha_utf8.hpp"
#include <algorithm>
#include <cerrno>
#include <cmath>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

struct HashEvidence {
    std::uint64_t bytes = 0, hardware_blocks = 0, portable_blocks = 0;
    bool complete = false, selected_hardware = false;
    const char* backend = "not_observed";
};
inline HashEvidence hash_evidence(const Sha256& state,std::uint64_t bytes) {
    HashEvidence evidence;
    evidence.bytes=bytes;evidence.hardware_blocks=state.hardware_blocks;evidence.portable_blocks=state.portable_blocks;
    evidence.complete=true;evidence.selected_hardware=state.hardware;evidence.backend=hepta_sha256_backend(&state);
    return evidence;
}
inline std::string hash_string(const std::string& s) {
    char digest[65]; hash_bytes(s.data(), s.size(), digest); return digest;
}
inline std::string hash_string_evidence(const std::string& s,HashEvidence& evidence) {
    Sha256 state;sha_init(&state);sha_update(&state,s.data(),s.size());char digest[65];sha_finish(&state,digest);
    evidence=hash_evidence(state,s.size());return digest;
}
inline std::string quote(const std::string& s) {
    std::string out = "\"";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
        else if (c < 32) { char v[7]; std::snprintf(v, sizeof(v), "\\u%04x", c); out += v; }
        else out += static_cast<char>(c);
    }
    return out + "\"";
}
struct Object {
    std::string s = "{"; bool first = true;
    void raw(const std::string& key, const std::string& value) {
        if (!first) s += ',';
        first = false; s += quote(key) + ':' + value;
    }
    void str(const std::string& key, const std::string& value) { raw(key, quote(value)); }
    void num(const std::string& key, long long value) { raw(key, std::to_string(value)); }
    void flag(const std::string& key, bool value) { raw(key, value ? "true" : "false"); }
    std::string done() const { return s + '}'; }
};
inline bool lower_hex(const std::string& s, std::size_t n) {
    return s.size() == n && std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
inline void write_all(int fd, const char* data, std::size_t n) {
    while (n) { ssize_t k = ::write(fd, data, n);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) throw std::runtime_error("write_failed");
        data += k; n -= static_cast<std::size_t>(k);
    }
}
inline void write_new(const std::string& path, const std::string& s) {
    int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) throw std::runtime_error("output_create_failed:" + path);
    try { write_all(fd, s.data(), s.size()); if (::fsync(fd)) throw std::runtime_error("output_fsync_failed"); }
    catch (...) { ::close(fd); throw; }
    if (::close(fd)) throw std::runtime_error("output_close_failed");
}
struct BoundFile {
    std::string path;
    int fd = -1;
    struct stat initial{};
    BoundFile(const std::string& p, std::uint64_t limit, bool require_owner = true) : path(p) {
        fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) throw std::runtime_error("input_open_failed:" + path);
        if (::fstat(fd, &initial) || !S_ISREG(initial.st_mode) || initial.st_size < 0 ||
            static_cast<std::uint64_t>(initial.st_size) > limit ||
            (require_owner && initial.st_uid != ::getuid()) || (initial.st_mode & 0022)) {
            ::close(fd); fd = -1; throw std::runtime_error("input_identity_rejected:" + path);
        }
    }
    BoundFile(const BoundFile&) = delete;
    BoundFile& operator=(const BoundFile&) = delete;
    ~BoundFile() { if (fd >= 0) ::close(fd); }
    bool same(const struct stat& now) const {
        return initial.st_dev == now.st_dev && initial.st_ino == now.st_ino &&
            initial.st_size == now.st_size && initial.st_uid == now.st_uid &&
            initial.st_mode == now.st_mode && initial.st_mtim.tv_sec == now.st_mtim.tv_sec &&
            initial.st_mtim.tv_nsec == now.st_mtim.tv_nsec && initial.st_ctim.tv_sec == now.st_ctim.tv_sec &&
            initial.st_ctim.tv_nsec == now.st_ctim.tv_nsec;
    }
    void verify() const {
        struct stat from_fd{}, from_path{};
        if (::fstat(fd, &from_fd) || ::lstat(path.c_str(), &from_path) ||
            !same(from_fd) || !same(from_path)) throw std::runtime_error("input_changed:" + path);
    }
    std::string read(std::size_t cap) const {
        if (static_cast<std::uint64_t>(initial.st_size) > cap) throw std::runtime_error("input_too_large");
        std::string data(static_cast<std::size_t>(initial.st_size), '\0');
        std::size_t at = 0;
        while (at < data.size()) { ssize_t n = ::pread(fd, data.data()+at, data.size()-at, static_cast<off_t>(at));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw std::runtime_error("input_read_failed");
            at += static_cast<std::size_t>(n);
        }
        verify(); return data;
    }
    std::string hash(HashEvidence* evidence = nullptr) const {
        if(evidence)*evidence=HashEvidence{};
        Sha256 state; sha_init(&state); std::vector<char> buf(1 << 20); off_t at = 0;
        while (at < initial.st_size) {
            std::size_t want = std::min<std::uint64_t>(buf.size(), initial.st_size-at);
            ssize_t n = ::pread(fd, buf.data(), want, at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) throw std::runtime_error("model_hash_read_failed");
            sha_update(&state, buf.data(), static_cast<std::size_t>(n)); at += n;
        }
        verify(); char out[65]; sha_finish(&state, out);
        if(evidence)*evidence=hash_evidence(state,static_cast<std::uint64_t>(at));
        return out;
    }
};
inline void validate_prompt(const std::string& prompt) {
    if (prompt.empty() || prompt.size() > 65536 || prompt.find('\0') != std::string::npos ||
        !utf8(reinterpret_cast<const unsigned char*>(prompt.data()), prompt.size()))
        throw std::runtime_error("prompt_not_bounded_utf8");
    const std::string marker = "<img>screen</img>";
    auto at = prompt.find(marker);
    if (at == std::string::npos) throw std::runtime_error("prompt_requires_single_screen");
    std::string without = prompt; without.erase(at, marker.size());
    for (const char* forbidden : {"<img>", "</img>", "<audio>", "</audio>"})
        if (without.find(forbidden) != std::string::npos) throw std::runtime_error("extra_media_reference_rejected");
    // Both are public caller forms: built-in ClawMate GUI uses no final LF,
    // while generic Qwen ChatML appends LF. Preserve the caller's exact bytes.
    const std::string suffix = "<|im_start|>assistant";
    const std::string with_lf = suffix + "\n";
    const bool bare = prompt.size() >= suffix.size() &&
        prompt.compare(prompt.size()-suffix.size(), suffix.size(), suffix) == 0;
    const bool newline = prompt.size() >= with_lf.size() &&
        prompt.compare(prompt.size()-with_lf.size(), with_lf.size(), with_lf) == 0;
    if (!bare && !newline)
        throw std::runtime_error("prompt_missing_assistant_generation_suffix");
}
inline std::pair<int,int> image_target(int width, int height, int long_edge) {
    if (width < 32 || height < 32 || width > 8192 || height > 8192 ||
        static_cast<long long>(width)*height > 32000000 || long_edge < 256 || long_edge > 1536)
        throw std::runtime_error("image_dimensions_rejected");
    double scale = std::min(1.0, static_cast<double>(long_edge)/std::max(width,height));
    auto round32 = [](double v) { return std::max(32, static_cast<int>(std::lround(v/32.0))*32); };
    return {round32(width*scale), round32(height*scale)};
}
inline std::string token_ids_sha(const int* ids, std::size_t count) {
    Sha256 state; sha_init(&state);
    for (std::size_t i=0; i<count; ++i) {
        std::uint32_t id = static_cast<std::uint32_t>(ids[i]);
        unsigned char little[4] = {static_cast<unsigned char>(id), static_cast<unsigned char>(id>>8),
            static_cast<unsigned char>(id>>16), static_cast<unsigned char>(id>>24)};
        sha_update(&state, little, 4);
    }
    char out[65]; sha_finish(&state, out); return out;
}
