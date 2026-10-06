#pragma once

// File: EIDMigrate/JsonHelper.h
// Minimal JSON implementation for EIDMigrate export file format

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <sstream>
#include <Windows.h>

// Simple JSON value types
enum class JsonType
{
    Null,
    Boolean,
    Number,
    String,
    Array,
    Object
};

// Forward declarations
class JsonValue;

// JSON Array
class JsonArray
{
private:
    std::vector<std::shared_ptr<JsonValue>> m_values;

public:
    JsonArray() = default;
    size_t size() const { return m_values.size(); }
    bool empty() const { return m_values.empty(); }

    void push_back(const std::shared_ptr<JsonValue>& value) { m_values.push_back(value); }
    std::shared_ptr<JsonValue>& operator[](size_t index) { return m_values[index]; }
    const std::shared_ptr<JsonValue>& operator[](size_t index) const { return m_values[index]; }

    const std::vector<std::shared_ptr<JsonValue>>& values() const { return m_values; }
};

// JSON Object
class JsonObject // NOSONAR - noexcept move constructor not required; class is not performance-critical and std::map provides move semantics
{
private:
    std::map<std::string, std::shared_ptr<JsonValue>, std::less<>> m_members;

public:
    JsonObject() = default;
    size_t size() const { return m_members.size(); }
    bool empty() const { return m_members.empty(); }

    bool has(const std::string& key) const { return m_members.contains(key); }
    std::shared_ptr<JsonValue>& operator[](const std::string& key) { return m_members[key]; }
    const std::shared_ptr<JsonValue>& operator[](const std::string& key) const { return m_members.at(key); }

    const std::map<std::string, std::shared_ptr<JsonValue>, std::less<>>& members() const { return m_members; }
};

// JSON Value
class JsonValue
{
private:
    // Default member initialisers: every constructor leaves all scalars defined.
    // (This header is also used inside LSASS by EIDCardLibrary/CSVConfig.cpp.)
    JsonType m_type = JsonType::Null;
    bool m_boolValue = false;
    long long m_numberValue = 0;
    std::string m_stringValue;
    JsonArray m_arrayValue;
    JsonObject m_objectValue;

public:
    JsonValue() : m_type(JsonType::Null), m_boolValue(false), m_numberValue(0) {}

    explicit JsonValue(bool value) : m_type(JsonType::Boolean), m_boolValue(value) {} // NOSONAR - only m_boolValue used when m_type==Boolean
    explicit JsonValue(int value) : m_type(JsonType::Number), m_numberValue(value) {} // NOSONAR - only m_numberValue used when m_type==Number
    explicit JsonValue(long long value) : m_type(JsonType::Number), m_numberValue(value) {} // NOSONAR - only m_numberValue used when m_type==Number
    explicit JsonValue(double value) : m_type(JsonType::Number), m_numberValue(static_cast<long long>(value)) {} // NOSONAR - only m_numberValue used when m_type==Number
    explicit JsonValue(const char* value) : m_type(JsonType::String), m_stringValue(value) {} // NOSONAR - only m_stringValue used when m_type==String
    explicit JsonValue(const std::string& value) : m_type(JsonType::String), m_stringValue(value) {} // NOSONAR - only m_stringValue used when m_type==String
    explicit JsonValue(const JsonArray& value) : m_type(JsonType::Array), m_arrayValue(value) {} // NOSONAR - only m_arrayValue used when m_type==Array
    explicit JsonValue(const JsonObject& value) : m_type(JsonType::Object), m_objectValue(value) {} // NOSONAR - only m_objectValue used when m_type==Object

    JsonType type() const { return m_type; }

    bool isBool() const { return m_type == JsonType::Boolean; }
    bool isNumber() const { return m_type == JsonType::Number; }
    bool isString() const { return m_type == JsonType::String; }
    bool isArray() const { return m_type == JsonType::Array; }
    bool isObject() const { return m_type == JsonType::Object; }
    bool isNull() const { return m_type == JsonType::Null; }

    // Type-checked scalar accessors: a value of another type reads as false / 0.
    bool asBool() const { return m_type == JsonType::Boolean && m_boolValue; }
    long long asNumber() const { return m_type == JsonType::Number ? m_numberValue : 0; }
    const std::string& asString() const { return m_stringValue; }
    const JsonArray& asArray() const { return m_arrayValue; }
    const JsonObject& asObject() const { return m_objectValue; }

    JsonArray& asArray() { return m_arrayValue; }
    JsonObject& asObject() { return m_objectValue; }

    // Serialization
    std::string stringify(int indent = 0) const;
};

// JSON Builder for creating JSON structures
class JsonBuilder
{
private:
    JsonObject m_rootObject;

public:
    JsonBuilder() = default;

    void startObject([[maybe_unused]] std::string_view key = "") const
    {
        // For nested objects, we'd need a stack (not implemented for simple case)
        // The key parameter is ignored for the root object
    }

    void endObject() const
    {
        // Navigate back up (not fully implemented for this simple case)
    }

    void add(const std::string& key, bool value)
    {
        m_rootObject[key] = std::make_shared<JsonValue>(value);
    }

    void add(const std::string& key, int value)
    {
        m_rootObject[key] = std::make_shared<JsonValue>(value);
    }

    void add(const std::string& key, const std::string& value)
    {
        m_rootObject[key] = std::make_shared<JsonValue>(value);
    }

    void add(const std::string& key, const char* value)
    {
        m_rootObject[key] = std::make_shared<JsonValue>(std::string(value));
    }

    void add(const std::string& key, const JsonArray& value)
    {
        m_rootObject[key] = std::make_shared<JsonValue>(value);
    }

    void add(const std::string& key, const JsonObject& value)
    {
        m_rootObject[key] = std::make_shared<JsonValue>(value);
    }

    std::string build() const
    {
        JsonValue rootValue(m_rootObject);
        return rootValue.stringify();
    }

    const JsonObject& root() const { return m_rootObject; }
};

// JSON Parser for parsing JSON strings
class JsonParser
{
private:
    const std::string& m_json;
    size_t m_pos = 0;

    void skipWhitespace()
    {
        while (m_pos < m_json.length() && isspace(static_cast<unsigned char>(m_json[m_pos])))
            m_pos++;
    }

    char current() const { return m_pos < m_json.length() ? m_json[m_pos] : '\0'; }
    bool eof() const { return m_pos >= m_json.length(); }

    // SECURITY (L9): cap recursion depth for the mutually-recursive value/array/object
    // parsers so deeply nested input fails with a parse error instead of overflowing the stack.
    static constexpr int MAX_PARSE_DEPTH = 64;

    std::shared_ptr<JsonValue> parseValue(int depth = 0);
    std::string parseString();
    bool parseBool();
    long long parseNumber();
    JsonArray parseArray(int depth = 0);
    JsonObject parseObject(int depth = 0);

public:
    explicit JsonParser(const std::string& json) : m_json(json) {}

    std::shared_ptr<JsonValue> parse()
    {
        skipWhitespace();
        return parseValue();
    }
};
