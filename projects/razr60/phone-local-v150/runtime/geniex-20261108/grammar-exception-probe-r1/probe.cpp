// Diagnostic only: original Qualcomm proc DSO, no model or QNN.
#include "geniex-proc/sampler.h"
#include "geniex-proc/tokenizer.h"
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <unistd.h>

static int construct_typed(const std::string& grammar, geniex::Tokenizer& tokenizer) {
    try {
        std::fprintf(stderr, "probe: before Grammar constructor (typed catch)\n");
        geniex::Grammar parsed(grammar, tokenizer, "root");
        std::fprintf(stderr, "probe: Grammar constructed and will destroy normally\n");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "probe: caught std::exception: %s\n", error.what());
        return 10;
    } catch (...) {
        std::fprintf(stderr, "probe: caught non-matching exception in catch(...)\n");
        return 11;
    }
}

static int construct_all(const std::string& grammar, geniex::Tokenizer& tokenizer) {
    try {
        std::fprintf(stderr, "probe: before Grammar constructor (catch-all only)\n");
        geniex::Grammar parsed(grammar, tokenizer, "root");
        std::fprintf(stderr, "probe: Grammar constructed and will destroy normally\n");
        return 0;
    } catch (...) {
        std::fprintf(stderr, "probe: caught exception in catch-all-only handler\n");
        return 12;
    }
}

extern "C" __attribute__((visibility("default")))
int grammar_exception_probe(int argc, char** argv) {
    const rlimit no_core{0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) return 65;
    alarm(15);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    if (argc < 3 || argc > 4) {
        std::fprintf(stderr, "usage: PROBE TOKENIZER valid|invalid-typed|invalid-all|local|file [GRAMMAR]\n");
        return 64;
    }
    const std::string mode(argv[2]);
    if (mode == "local") {
        try { throw std::runtime_error("local throw control"); }
        catch (const std::exception& e) {
            std::fprintf(stderr, "probe: local std::exception caught: %s\n", e.what());
            return 13;
        } catch (...) { return 14; }
    }
    std::string grammar = "root ::= \"B\"\n";
    if (mode == "invalid-typed" || mode == "invalid-all") {
        grammar = "root ::= \"unterminated\n";
    } else if (mode == "file") {
        if (argc != 4) return 64;
        std::ifstream input(argv[3], std::ios::binary);
        if (!input) return 66;
        char buffer[65537];
        input.read(buffer, sizeof(buffer));
        const auto count = input.gcount();
        if (count <= 0 || count > 65536 || !input.eof()) return 67;
        grammar.assign(buffer, static_cast<size_t>(count));
        if (grammar.find('\0') != std::string::npos) return 67;
    } else if (mode != "valid" || argc != 3) {
        return 64;
    }
    try {
        std::fprintf(stderr, "probe: before Tokenizer::from_file\n");
        auto tokenizer = geniex::Tokenizer::from_file(argv[1]);
        if (!tokenizer) return 68;
        std::fprintf(stderr, "probe: tokenizer loaded; vocab=%d; grammar_bytes=%zu\n",
                     tokenizer->vocab_size(), grammar.size());
        const int result = mode == "invalid-all"
            ? construct_all(grammar, *tokenizer)
            : construct_typed(grammar, *tokenizer);
        std::fprintf(stderr, "probe: constructor result=%d; normal tokenizer cleanup\n", result);
        tokenizer.reset();
        std::fprintf(stderr, "probe: all cleanup complete\n");
        return result;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "probe: outer std::exception: %s\n", e.what());
        return 20;
    } catch (...) {
        std::fprintf(stderr, "probe: outer catch-all\n");
        return 21;
    }
}

#ifndef GRAMMAR_PROBE_DSO
int main(int argc, char** argv) { return grammar_exception_probe(argc, argv); }
#endif

