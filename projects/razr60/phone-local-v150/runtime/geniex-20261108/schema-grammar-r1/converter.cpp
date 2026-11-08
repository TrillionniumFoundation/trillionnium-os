// Strict standalone adapter around the pinned official JSON-Schema converter.
// This is a CPU-only text transformation. It cannot load models or execute UI actions.
#include "json-schema-to-grammar.h"
#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <iostream>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using J = nlohmann::ordered_json;
static constexpr std::size_t MAX_BYTES = 65536;
static constexpr const char * UPSTREAM = "19cce6919992fdffd92e0ac152caaf1e2b8f254e";
static constexpr const char * SUBSET = "hepta.mobile-schema-gbnf-subset.v1";
static const std::string PACKAGE_PATTERN = R"(^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$)";
static const std::string VIEW_PATTERN = R"(^[A-Za-z][A-Za-z0-9_.]*:id/[A-Za-z0-9_]+$)";

static void need(bool ok, const std::string & why) {
    if (!ok) throw std::invalid_argument(why);
}
static std::set<std::string> keys(const J & node) {
    need(node.is_object(), "schema node must be an object");
    std::set<std::string> out;
    for (const auto & item : node.items()) out.insert(item.key());
    return out;
}
static void exact_keys(const J & node, const std::set<std::string> & expected) {
    need(keys(node) == expected, "unknown, absent or combined schema keyword");
}
static int small_int(const J & value, int low, int high) {
    need(value.is_number_integer() && !value.is_boolean(), "integer bound required");
    if (value.is_number_unsigned()) {
        need(value.get<std::uint64_t>() <= static_cast<std::uint64_t>(high), "integer bound too large");
    }
    const auto n = value.get<std::int64_t>();
    need(n >= low && n <= high, "integer bound outside reviewed range");
    return static_cast<int>(n);
}
static std::set<std::string> string_set(const J & value) {
    need(value.is_array(), "string array required");
    std::set<std::string> out;
    for (const auto & item : value) {
        need(item.is_string(), "string array contains a nonstring");
        need(out.insert(item.get<std::string>()).second, "duplicate string value");
    }
    return out;
}

static void validate_node(const J & node, int depth, std::size_t & count) {
    need(depth <= 24 && ++count <= 2048, "schema structure exceeds reviewed bound");
    need(node.is_object(), "schema node must be an object");
    if (node.contains("const")) {
        exact_keys(node, {"const"});
        const auto & value = node.at("const");
        need(value.is_string() || (value.is_number_integer() && !value.is_boolean()
             && small_int(value, 0, 0) == 0), "only text constants or display zero are reviewed");
        return;
    }
    if (node.contains("enum")) {
        exact_keys(node, {"type", "enum"});
        need(node.at("type") == "string", "enum must explicitly contain strings");
        const auto values = string_set(node.at("enum"));
        need(!values.empty() && values.size() <= 64, "enum size outside reviewed catalogue bound");
        return;
    }
    need(node.contains("type") && node.at("type").is_string(), "explicit schema type required");
    const auto type = node.at("type").get<std::string>();
    if (type == "object") {
        exact_keys(node, {"type", "properties", "required", "additionalProperties"});
        need(node.at("additionalProperties").is_boolean() && node.at("additionalProperties") == false,
             "every object must be explicitly closed");
        const auto properties = keys(node.at("properties"));
        need(!properties.empty() && properties.size() <= 16, "object field count outside reviewed bound");
        need(string_set(node.at("required")) == properties, "every declared property must be required");
        for (const auto & item : node.at("properties").items()) validate_node(item.value(), depth + 1, count);
    } else if (type == "array") {
        // The current model-facing schema contains exact tuples only.
        // Reject items rather than relying on the upstream precedence quirk.
        exact_keys(node, {"type", "prefixItems", "minItems", "maxItems"});
        need(node.at("prefixItems").is_array(), "prefixItems must be an array");
        const auto n = node.at("prefixItems").size();
        need(n >= 1 && n <= 5, "tuple length outside reviewed range");
        need(small_int(node.at("minItems"), 1, 5) == static_cast<int>(n)
             && small_int(node.at("maxItems"), 1, 5) == static_cast<int>(n), "tuple bounds must equal its exact length");
        for (const auto & child : node.at("prefixItems")) validate_node(child, depth + 1, count);
    } else if (type == "string") {
        if (node.contains("pattern")) {
            exact_keys(node, {"type", "pattern"});
            need(node.at("pattern").is_string(), "pattern must be text");
            const auto pattern = node.at("pattern").get<std::string>();
            need(pattern == PACKAGE_PATTERN || pattern == VIEW_PATTERN, "pattern is outside the two reviewed ASCII grammars");
        } else {
            auto expected = std::set<std::string>{"type", "maxLength"};
            if (node.contains("minLength")) expected.insert("minLength");
            exact_keys(node, expected);
            const int maximum = small_int(node.at("maxLength"), 0, 4096);
            const int minimum = node.contains("minLength") ? small_int(node.at("minLength"), 0, 1) : 0;
            need(minimum <= maximum, "inverted text length");
            // minLength >1 is deliberately unsupported: an escaped surrogate
            // pair occupies two upstream char units but one decoded scalar.
            // Actual Hepta length minima are 0 or 1; maxima remain conservative.
        }
    } else if (type == "integer") {
        exact_keys(node, {"type", "minimum", "maximum"});
        const int lo = small_int(node.at("minimum"), 0, 1500);
        const int hi = small_int(node.at("maximum"), 0, 1500);
        need((lo == 0 && hi == 1000) || (lo == 100 && hi == 1500)
             || (lo == 500 && hi == 1500), "integer interval is outside the reviewed action ranges");
    } else {
        throw std::invalid_argument("unreviewed schema type");
    }
}

static void validate_mobile_schema(const J & schema) {
    exact_keys(schema, {"oneOf"});
    const auto & branches = schema.at("oneOf");
    need(branches.is_array() && !branches.empty() && branches.size() <= 32, "invalid action alternatives");
    const std::map<std::string, std::set<std::string>> fields = {
        {"terminate", {"action", "summary", "status"}},
        {"open", {"action", "summary", "text"}},
        {"screenshot", {"action", "summary", "display_id"}},
        {"click", {"action", "summary", "screenshot_id", "coordinate"}},
        {"swipe", {"action", "summary", "screenshot_id", "start_coordinate", "end_coordinate", "duration_ms"}},
        {"long_press", {"action", "summary", "screenshot_id", "coordinate", "duration_ms"}},
        {"back", {"action", "summary", "screenshot_id"}},
        {"home", {"action", "summary", "screenshot_id"}},
        {"type", {"action", "summary", "package", "view_id", "old_text", "text"}},
        {"focus_type", {"action", "summary", "package", "view_id", "old_text", "text"}},
        {"observe", {"action", "summary", "package"}},
        {"read_text", {"action", "summary", "package", "view_ids"}},
        {"read_text_anchor", {"action", "summary", "package", "title_view_id", "anchor_text", "value_view_id"}},
        {"return_hepta", {"action", "summary"}}
    };
    std::map<std::string, std::set<int>> discriminators;
    std::size_t count = 0;
    for (const auto & branch : branches) {
        validate_node(branch, 0, count);
        need(branch.at("type") == "object", "alternative must be an object");
        const auto & p = branch.at("properties");
        need(keys(p) == std::set<std::string>{"name", "arguments"}
             && p.at("name") == J{{"const", "mobile_use"}}, "mobile envelope differs");
        const auto & a = p.at("arguments");
        need(a.at("type") == "object", "arguments must be an object");
        const auto & ap = a.at("properties");
        need(ap.contains("action") && ap.at("action").contains("const")
             && ap.at("action").at("const").is_string(), "action discriminator absent");
        const auto action = ap.at("action").at("const").get<std::string>();
        const auto it = fields.find(action);
        need(it != fields.end() && keys(ap) == it->second, "action fields differ from reviewed signatures");
        int length = 0;
        if (action == "read_text") {
            need(ap.at("view_ids").at("type") == "array", "read_text discriminator is not a tuple");
            length = static_cast<int>(ap.at("view_ids").at("prefixItems").size());
        }
        // Upstream treats oneOf as a union. These discriminators prove the
        // branches cannot overlap: action constant, then read_text tuple size.
        need(discriminators[action].insert(length).second, "overlapping oneOf alternatives");
    }
}

static void validate_health_schema(const J & schema) {
    // The existing two-role health contract has an independent legacy shape.
    // It can never expose a tool or encode the requested nonce as an answer.
    exact_keys(schema, {"type", "properties", "required", "additionalProperties"});
    need(schema.at("type") == "object" && schema.at("additionalProperties").is_boolean()
         && schema.at("additionalProperties") == false, "health root must be closed");
    const std::set<std::string> names = {"kind", "call_id", "tool", "command", "argv", "summary", "task_status"};
    const auto & properties = schema.at("properties");
    need(keys(properties) == names && string_set(schema.at("required")) == names, "health fields differ");
    const std::map<std::string, std::string> constants = {
        {"kind", "turn.complete"}, {"tool", "none"}, {"call_id", ""},
        {"command", ""}, {"task_status", "completed"}
    };
    for (const auto & entry : constants) {
        const auto & node = properties.at(entry.first);
        exact_keys(node, {"type", "const"});
        need(node.at("type") == "string" && node.at("const").is_string()
             && node.at("const") == entry.second, "health terminal constant differs");
    }
    const auto & arguments = properties.at("argv");
    exact_keys(arguments, {"type", "items", "minItems", "maxItems"});
    exact_keys(arguments.at("items"), {"type"});
    need(arguments.at("type") == "array" && arguments.at("items").at("type") == "string"
         && small_int(arguments.at("minItems"), 0, 0) == 0
         && small_int(arguments.at("maxItems"), 0, 0) == 0, "health argv must be empty");
    const auto & summary = properties.at("summary");
    exact_keys(summary, {"type", "maxLength"});
    need(summary.at("type") == "string" && small_int(summary.at("maxLength"), 1024, 1024) == 1024,
         "health summary must remain unconstrained by any nonce");
}

int main(int argc, char ** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--version") {
            std::cout << J{{"schema", "hepta.schema-converter-version.v1"}, {"upstream_commit", UPSTREAM},
                           {"subset", SUBSET}, {"max_schema_bytes", MAX_BYTES}, {"max_grammar_bytes", MAX_BYTES},
                           {"loads_model", false}, {"links_inference_runtime", false}}.dump() << '\n';
            return 0;
        }
        need(argc == 1, "usage: hepta-schema-gbnf < original-schema.json > grammar.gbnf");
        std::string raw;
        std::array<char, 4096> block{};
        while (std::cin) {
            std::cin.read(block.data(), static_cast<std::streamsize>(block.size()));
            raw.append(block.data(), static_cast<std::size_t>(std::cin.gcount()));
            need(raw.size() <= MAX_BYTES, "schema bytes exceed limit");
        }
        need(std::cin.eof() && !raw.empty(), "schema read failed or empty");
        std::vector<std::set<std::string>> object_keys;
        auto callback = [&](int, J::parse_event_t event, J & parsed) {
            if (event == J::parse_event_t::object_start) object_keys.emplace_back();
            else if (event == J::parse_event_t::object_end) {
                need(!object_keys.empty(), "unbalanced parser object");
                object_keys.pop_back();
            } else if (event == J::parse_event_t::key) {
                need(!object_keys.empty() && object_keys.back().insert(parsed.get<std::string>()).second,
                     "duplicate JSON key");
            }
            return true;
        };
        const J schema = J::parse(raw, callback);
        need(object_keys.empty(), "unbalanced parser objects");
        if (schema.contains("oneOf")) validate_mobile_schema(schema);
        else validate_health_schema(schema);
        // The input bytes are sent unchanged to both parsers. No enum, branch,
        // bound, required field, or literal is projected out.
        const std::string grammar = json_schema_to_grammar(common_json::parse(raw), true);
        need(!grammar.empty() && grammar.size() <= MAX_BYTES, "generated grammar exceeds worker limit");
        need(grammar.find("root ::=") != std::string::npos, "root grammar absent");
        std::cout.write(grammar.data(), static_cast<std::streamsize>(grammar.size()));
        std::cout.flush();
        need(std::cout.good(), "grammar write failed");
        return 0;
    } catch (const std::exception & error) {
        // A JSON parse error may itself contain the rejected non-UTF8 byte.
        // Diagnostic encoding must fail closed without throwing in this catch.
        std::string message(error.what());
        if (message.size() > 512) message.resize(512);
        std::cerr << J{{"schema", "hepta.schema-converter-error.v1"}, {"error", message},
                       {"model_loaded", false}, {"native_action_authorized", false}}
                         .dump(-1, ' ', true, J::error_handler_t::replace) << '\n';
        return 65;
    }
}
