// Standalone compatibility surface, not llama/common or a model runtime.
#pragma once
#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <vector>
// Exact value from common/common.h at pinned llama commit.
#define COMMON_RECURSIVE_LIMIT 128
std::string string_join(const std::vector<std::string>& values, const std::string& separator);
std::vector<std::string> string_split(const std::string& str, const std::string& delimiter);
std::string string_repeat(const std::string& str, std::size_t n);
