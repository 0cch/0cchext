#include "json_value.h"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <stdexcept>

JsonValue::JsonValue() = default;
JsonValue::JsonValue(bool value) : type_(Type::Boolean), boolean_(value) {}
JsonValue::JsonValue(double value) : type_(Type::Number), number_(value) {}
JsonValue::JsonValue(const std::string &value) : type_(Type::String), string_(value) {}

JsonValue JsonValue::Null() { return JsonValue(); }
JsonValue JsonValue::Boolean(bool value) { return JsonValue(value); }
JsonValue JsonValue::Number(double value) { return JsonValue(value); }
JsonValue JsonValue::String(const std::string &value) { return JsonValue(value); }

JsonValue JsonValue::Array(std::vector<JsonValue> values)
{
	JsonValue result;
	result.type_ = Type::Array;
	result.array_ = std::move(values);
	return result;
}

JsonValue JsonValue::Object(std::map<std::string, JsonValue> values)
{
	JsonValue result;
	result.type_ = Type::Object;
	result.object_ = std::move(values);
	return result;
}

JsonValue::Type JsonValue::GetType() const { return type_; }
bool JsonValue::IsNull() const { return type_ == Type::Null; }
bool JsonValue::IsObject() const { return type_ == Type::Object; }
bool JsonValue::IsArray() const { return type_ == Type::Array; }

bool JsonValue::AsBoolean() const
{
	if (type_ != Type::Boolean) {
		throw std::runtime_error("JSON value is not a boolean");
	}
	return boolean_;
}

double JsonValue::AsNumber() const
{
	if (type_ != Type::Number) {
		throw std::runtime_error("JSON value is not a number");
	}
	return number_;
}

const std::string &JsonValue::AsString() const
{
	if (type_ != Type::String) {
		throw std::runtime_error("JSON value is not a string");
	}
	return string_;
}

const std::vector<JsonValue> &JsonValue::AsArray() const
{
	if (type_ != Type::Array) {
		throw std::runtime_error("JSON value is not an array");
	}
	return array_;
}

const std::map<std::string, JsonValue> &JsonValue::AsObject() const
{
	if (type_ != Type::Object) {
		throw std::runtime_error("JSON value is not an object");
	}
	return object_;
}

const JsonValue *JsonValue::Get(const std::string &key) const
{
	if (type_ != Type::Object) {
		return nullptr;
	}
	auto it = object_.find(key);
	return it == object_.end() ? nullptr : &it->second;
}

std::string JsonValue::GetString(const std::string &key, const std::string &fallback) const
{
	const JsonValue *value = Get(key);
	return value != nullptr && value->GetType() == Type::String ? value->AsString() : fallback;
}

double JsonValue::GetNumber(const std::string &key, double fallback) const
{
	const JsonValue *value = Get(key);
	return value != nullptr && value->GetType() == Type::Number ? value->AsNumber() : fallback;
}

bool JsonValue::GetBoolean(const std::string &key, bool fallback) const
{
	const JsonValue *value = Get(key);
	return value != nullptr && value->GetType() == Type::Boolean ? value->AsBoolean() : fallback;
}

namespace
{
class JsonParser
{
public:
	explicit JsonParser(const std::string &text) : text_(text) {}

	JsonValue Parse()
	{
		SkipWhitespace();
		JsonValue value = ParseValue();
		SkipWhitespace();
		if (index_ != text_.size()) {
			throw std::runtime_error("unexpected trailing JSON data");
		}
		return value;
	}

private:
	const std::string &text_;
	size_t index_ = 0;

	void SkipWhitespace()
	{
		while (index_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[index_]))) {
			++index_;
		}
	}

	char Peek() const
	{
		if (index_ >= text_.size()) {
			throw std::runtime_error("unexpected end of JSON");
		}
		return text_[index_];
	}

	char Take()
	{
		if (index_ >= text_.size()) {
			throw std::runtime_error("unexpected end of JSON");
		}
		return text_[index_++];
	}

	void Expect(char expected)
	{
		if (Take() != expected) {
			throw std::runtime_error("invalid JSON token");
		}
	}

	bool Consume(const char *literal)
	{
		const size_t start = index_;
		while (*literal != '\0') {
			if (index_ >= text_.size() || text_[index_] != *literal) {
				index_ = start;
				return false;
			}
			++index_;
			++literal;
		}
		return true;
	}

	JsonValue ParseValue()
	{
		SkipWhitespace();
		const char c = Peek();
		if (c == '{') return ParseObject();
		if (c == '[') return ParseArray();
		if (c == '"') return JsonValue::String(ParseString());
		if (c == 't' && Consume("true")) return JsonValue::Boolean(true);
		if (c == 'f' && Consume("false")) return JsonValue::Boolean(false);
		if (c == 'n' && Consume("null")) return JsonValue::Null();
		return JsonValue::Number(ParseNumber());
	}

	JsonValue ParseObject()
	{
		Expect('{');
		std::map<std::string, JsonValue> values;
		SkipWhitespace();
		if (Peek() == '}') {
			Take();
			return JsonValue::Object(std::move(values));
		}

		for (;;) {
			SkipWhitespace();
			if (Peek() != '"') {
				throw std::runtime_error("JSON object key must be a string");
			}
			std::string key = ParseString();
			SkipWhitespace();
			Expect(':');
			values.emplace(std::move(key), ParseValue());
			SkipWhitespace();
			const char separator = Take();
			if (separator == '}') {
				break;
			}
			if (separator != ',') {
				throw std::runtime_error("invalid JSON object separator");
			}
		}
		return JsonValue::Object(std::move(values));
	}

	JsonValue ParseArray()
	{
		Expect('[');
		std::vector<JsonValue> values;
		SkipWhitespace();
		if (Peek() == ']') {
			Take();
			return JsonValue::Array(std::move(values));
		}

		for (;;) {
			values.push_back(ParseValue());
			SkipWhitespace();
			const char separator = Take();
			if (separator == ']') {
				break;
			}
			if (separator != ',') {
				throw std::runtime_error("invalid JSON array separator");
			}
		}
		return JsonValue::Array(std::move(values));
	}

	std::string ParseString()
	{
		Expect('"');
		std::string result;
		while (true) {
			const char c = Take();
			if (c == '"') {
				return result;
			}
			if (static_cast<unsigned char>(c) < 0x20) {
				throw std::runtime_error("control character in JSON string");
			}
			if (c != '\\') {
				result.push_back(c);
				continue;
			}

			const char escaped = Take();
			switch (escaped) {
			case '"': result.push_back('"'); break;
			case '\\': result.push_back('\\'); break;
			case '/': result.push_back('/'); break;
			case 'b': result.push_back('\b'); break;
			case 'f': result.push_back('\f'); break;
			case 'n': result.push_back('\n'); break;
			case 'r': result.push_back('\r'); break;
			case 't': result.push_back('\t'); break;
			case 'u': {
				unsigned code = 0;
				for (int i = 0; i < 4; ++i) {
					const char hex = Take();
					code <<= 4;
					if (hex >= '0' && hex <= '9') code |= hex - '0';
					else if (hex >= 'a' && hex <= 'f') code |= hex - 'a' + 10;
					else if (hex >= 'A' && hex <= 'F') code |= hex - 'A' + 10;
					else throw std::runtime_error("invalid JSON unicode escape");
				}
				if (code < 0x80) {
					result.push_back(static_cast<char>(code));
				} else {
					result.push_back('?');
				}
				break;
			}
			default:
				throw std::runtime_error("invalid JSON escape");
			}
		}
	}

	double ParseNumber()
	{
		const size_t start = index_;
		if (index_ < text_.size() && text_[index_] == '-') ++index_;
		while (index_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[index_]))) ++index_;
		if (index_ < text_.size() && text_[index_] == '.') {
			++index_;
			while (index_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[index_]))) ++index_;
		}
		if (index_ < text_.size() && (text_[index_] == 'e' || text_[index_] == 'E')) {
			++index_;
			if (index_ < text_.size() && (text_[index_] == '+' || text_[index_] == '-')) ++index_;
			while (index_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[index_]))) ++index_;
		}
		if (start == index_) {
			throw std::runtime_error("invalid JSON value");
		}
		return std::stod(text_.substr(start, index_ - start));
	}
};

void SerializeString(std::ostringstream &out, const std::string &value)
{
	out << '"';
	for (char c : value) {
		switch (c) {
		case '"': out << "\\\""; break;
		case '\\': out << "\\\\"; break;
		case '\b': out << "\\b"; break;
		case '\f': out << "\\f"; break;
		case '\n': out << "\\n"; break;
		case '\r': out << "\\r"; break;
		case '\t': out << "\\t"; break;
		default:
			if (static_cast<unsigned char>(c) < 0x20) {
				out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(static_cast<unsigned char>(c)) << std::dec;
			} else {
				out << c;
			}
			break;
		}
	}
	out << '"';
}

void Serialize(std::ostringstream &out, const JsonValue &value)
{
	switch (value.GetType()) {
	case JsonValue::Type::Null:
		out << "null";
		break;
	case JsonValue::Type::Boolean:
		out << (value.AsBoolean() ? "true" : "false");
		break;
	case JsonValue::Type::Number:
		out << std::setprecision(15) << value.AsNumber();
		break;
	case JsonValue::Type::String:
		SerializeString(out, value.AsString());
		break;
	case JsonValue::Type::Array: {
		out << '[';
		bool first = true;
		for (const auto &item : value.AsArray()) {
			if (!first) out << ',';
			first = false;
			Serialize(out, item);
		}
		out << ']';
		break;
	}
	case JsonValue::Type::Object: {
		out << '{';
		bool first = true;
		for (const auto &item : value.AsObject()) {
			if (!first) out << ',';
			first = false;
			SerializeString(out, item.first);
			out << ':';
			Serialize(out, item.second);
		}
		out << '}';
		break;
	}
	}
}
}

JsonValue ParseJson(const std::string &text)
{
	return JsonParser(text).Parse();
}

std::string SerializeJson(const JsonValue &value)
{
	std::ostringstream out;
	Serialize(out, value);
	return out.str();
}
