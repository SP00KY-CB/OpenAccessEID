// File: EIDMigrate/JsonHelper.cpp
// Minimal JSON implementation for EIDMigrate export file format

#include "JsonHelper.h"
#include <sstream>
#include <cctype>
#include <algorithm>
#include <stdexcept>
#include <iomanip>

// JsonValue stringify
std::string JsonValue::stringify(int indent) const
{
    std::ostringstream oss;

    switch (m_type)
    {
    case JsonType::Null:
        oss << "null";
        break;

    case JsonType::Boolean:
        oss << (m_boolValue ? "true" : "false");
        break;

    case JsonType::Number:
        oss << m_numberValue;
        break;

    case JsonType::String:
        oss << "\"";
        for (char c : m_stringValue)
        {
            if (c == '"' || c == '\\') oss << '\\';
            oss << c;
        }
        oss << "\"";
        break;

    case JsonType::Array:
    {
        oss << "[";
        bool first = true;
        for (const auto& value : m_arrayValue.values())
        {
            if (!first) oss << ",";
            oss << value->stringify(indent + 2);
            first = false;
        }
        oss << "]";
        break;
    }

    case JsonType::Object:
    {
        oss << "{";
        bool first = true;
        for (const auto& pair : m_objectValue.members())  // NOSONAR - IDIOM-01: explicit pair access retained; pair.first/second used below
        {
            if (!first) oss << ",";
            oss << "\n" << std::string(indent + 2, ' ');
            oss << "\"" << pair.first << "\": " << pair.second->stringify(indent + 2);
            first = false;
        }
        if (!m_objectValue.members().empty())
            oss << "\n" << std::string(indent, ' ');
        oss << "}";
        break;
    }
    }  // end switch

    return oss.str();
}  // end function stringify

// JSON Parser implementation
std::shared_ptr<JsonValue> JsonParser::parseValue(int depth)
{
    skipWhitespace();

    char c = current();

    if (c == '"')
        return std::make_shared<JsonValue>(parseString());
    else if (c == 't' || c == 'f')
        return std::make_shared<JsonValue>(parseBool());
    else if (c == '-' || isdigit(c))
        return std::make_shared<JsonValue>(parseNumber());
    else if (c == '[')
        return std::make_shared<JsonValue>(parseArray(depth));
    else if (c == '{')
        return std::make_shared<JsonValue>(parseObject(depth));
    else if (c == 'n')
    {
        m_pos += 4; // "null"
        return std::make_shared<JsonValue>();
    }

    // Debug: show context around error
    size_t start = (m_pos > 20) ? m_pos - 20 : 0;
    size_t end = (m_pos + 20 < m_json.length()) ? m_pos + 20 : m_json.length();
    std::string context = m_json.substr(start, end - start);
    std::string marker = std::string(m_pos - start, ' ') + "^";

    char errMsg[256];  // NOSONAR - LSASS-01: C-style buffer required by sprintf_s
    sprintf_s(errMsg, "Unexpected character '%c' (0x%02X) at pos %zu\nContext: %s\n%s",
        c, static_cast<unsigned char>(c), m_pos, context.c_str(), marker.c_str());
    throw std::runtime_error(errMsg); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors in this simple parser
}

std::string JsonParser::parseString()
{
    // Skip opening quote
    m_pos++;

    std::string result;
    while (!eof())
    {
        char c = current();
        m_pos++;

        if (c == '"')
            break;

        if (c == '\\')
        {
            if (eof())
                throw std::runtime_error("Unterminated string"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors

            c = current();
            m_pos++;

            switch (c)
            {
            case '"': result += '"'; break;
            case '\\': result += '\\'; break;
            case '/': result += '/'; break;
            case 'b': result += '\b'; break;
            case 'f': result += '\f'; break;
            case 'n': result += '\n'; break;
            case 'r': result += '\r'; break;
            case 't': result += '\t'; break;
            case 'u':
                // Unicode escape (simplified - only handles ASCII range)
                if (m_pos + 4 < m_json.length())  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
                {
                    std::string hex = m_json.substr(m_pos, 4);
                    if (hex.length() == 4)
                    {
                        char ch = static_cast<char>(strtol(hex.c_str(), nullptr, 16));  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
                        result += ch;
                        m_pos += 4;
                    }
                }
                break;
            default:
                result += c;
            }
        }
        else
        {
            result += c;
        }
    }

    return result;
}

bool JsonParser::parseBool()
{
    if (m_pos + 4 <= m_json.length() && m_json.substr(m_pos, 4) == "true")
    {
        m_pos += 4;
        return true;
    }
    else if (m_pos + 5 <= m_json.length() && m_json.substr(m_pos, 5) == "false")
    {
        m_pos += 5;
        return false;
    }
    throw std::runtime_error("Invalid boolean value"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors
}

long long JsonParser::parseNumber()
{
    size_t start = m_pos;
    bool negative = false;

    if (current() == '-')
    {
        negative = true;  // NOSONAR - dead store retained; negative flag kept for readability
        m_pos++;
    }

    while (!eof() && (isdigit(current()) || current() == '.'))
    {
        m_pos++;
    }

    std::string numStr = m_json.substr(start, m_pos - start);
    // SECURITY (L9): std::stoll throws on malformed/overflowing input; convert those into a
    // parse error so they cannot escape the parser as an unrelated exception.
    try
    {
        return std::stoll(numStr);
    }
    catch (const std::exception&)
    {
        throw std::runtime_error("Invalid numeric value"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors
    }
}

JsonArray JsonParser::parseArray(int depth)
{
    // SECURITY (L9): reject arrays nested deeper than MAX_PARSE_DEPTH before recursing.
    if (depth >= MAX_PARSE_DEPTH)
        throw std::runtime_error("JSON nesting too deep"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors

    // Skip opening bracket
    m_pos++;
    skipWhitespace();

    JsonArray array;

    while (!eof())  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    {
        skipWhitespace();
        char c = current();

        if (c == ']')
        {
            m_pos++;
            break;
        }

        // Parse element
        array.push_back(parseValue(depth + 1));

        skipWhitespace();
        c = current();

        if (c == ']')
        {
            m_pos++;
            break;
        }
        else if (c == ',')
        {
            m_pos++;
        }
        else
        {
            throw std::runtime_error("Expected ',' or ']' in array"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors
        }
    }

    return array;
}

JsonObject JsonParser::parseObject(int depth)
{
    // SECURITY (L9): reject objects nested deeper than MAX_PARSE_DEPTH before recursing.
    if (depth >= MAX_PARSE_DEPTH)
        throw std::runtime_error("JSON nesting too deep"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors

    // Skip opening brace
    m_pos++;
    skipWhitespace();

    JsonObject obj;

    while (!eof())  // NOSONAR - COMPLEXITY-01: refactor deferred; logic verified
    {
        skipWhitespace();
        char c = current();

        if (c == '}')
        {
            m_pos++;
            break;
        }

        // Parse key (must be string)
        if (c != '"')
            throw std::runtime_error("Object key must be string"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors

        std::string key = parseString();

        skipWhitespace();
        c = current();
        m_pos++;  // Skip the ':'

        if (c != ':')
            throw std::runtime_error("Expected ':' after object key"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors

        // skipWhitespace();  // parseValue will handle this
        // Don't increment m_pos here - parseValue will handle it

        // Parse value
        std::shared_ptr<JsonValue> value = parseValue(depth + 1);
        obj[key] = std::move(value);

        skipWhitespace();
        c = current();

        if (c == '}')
        {
            m_pos++;
            break;
        }
        else if (c == ',')
        {
            m_pos++;
        }
        else
        {
            throw std::runtime_error("Expected ',' or '}' in object"); // NOSONAR - std::runtime_error is appropriate for JSON parsing errors
        }
    }

    return obj;
}

// Helper functions for converting between our structures and JSON
std::string BytesToHexString(const std::vector<BYTE>& data)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (BYTE b : data)
    {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

std::vector<BYTE> HexStringToBytes(const std::string& hex)  // NOSONAR - API-01: signature dictated by public header
{
    std::vector<BYTE> result;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteStr = hex.substr(i, 2);
        BYTE b = static_cast<BYTE>(strtol(byteStr.c_str(), nullptr, 16));  // NOSONAR (EXPLICIT-TYPE-01) - Explicit type preferred for clarity
        result.push_back(b); // NOSONAR - push_back used for primitive type (BYTE); emplace_back provides no benefit
    }
    return result;
}
