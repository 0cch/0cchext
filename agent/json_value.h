#pragma once

#include <map>
#include <string>
#include <vector>

class JsonValue
{
public:
	enum class Type
	{
		Null,
		Boolean,
		Number,
		String,
		Array,
		Object
	};

	JsonValue();
	explicit JsonValue(bool value);
	explicit JsonValue(double value);
	explicit JsonValue(const std::string &value);

	static JsonValue Null();
	static JsonValue Boolean(bool value);
	static JsonValue Number(double value);
	static JsonValue String(const std::string &value);
	static JsonValue Array(std::vector<JsonValue> values = {});
	static JsonValue Object(std::map<std::string, JsonValue> values = {});

	Type GetType() const;
	bool IsNull() const;
	bool IsObject() const;
	bool IsArray() const;
	bool AsBoolean() const;
	double AsNumber() const;
	const std::string &AsString() const;
	const std::vector<JsonValue> &AsArray() const;
	const std::map<std::string, JsonValue> &AsObject() const;
	const JsonValue *Get(const std::string &key) const;
	std::string GetString(const std::string &key, const std::string &fallback = "") const;
	double GetNumber(const std::string &key, double fallback = 0) const;
	bool GetBoolean(const std::string &key, bool fallback = false) const;

private:
	Type type_ = Type::Null;
	bool boolean_ = false;
	double number_ = 0;
	std::string string_;
	std::vector<JsonValue> array_;
	std::map<std::string, JsonValue> object_;
};

JsonValue ParseJson(const std::string &text);
std::string SerializeJson(const JsonValue &value);
