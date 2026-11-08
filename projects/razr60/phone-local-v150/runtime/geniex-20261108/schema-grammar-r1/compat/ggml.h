// Only the JSON invariant hook is required; no ggml implementation is linked.
#pragma once
#include <cstdio>
#include <cstdlib>
#define GGML_ASSERT(condition) do { if (!(condition)) { std::fputs("JSON invariant failed\\n", stderr); std::abort(); } } while (0)
