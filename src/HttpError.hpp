// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/utils/string/cat.hpp>

#include <string>
#include <string_view>
#include <stdexcept>

namespace xentara::samples::webService
{
// This class represents HTTP Errors.It includes the response code, message, and, if necessary,additional header
// information. This class inherits std::runtime error and may be thrown as an exception.
class HttpError : public std::runtime_error
{
public:
	// constructor
	HttpError(std::string_view responseCode, std::string_view message, std::string_view extraHeaderFiels = {}) :
		std::runtime_error(utils::string::cat("HTTP error ", responseCode, ": ", message)), _responseCode(responseCode),
		_responseData(utils::string::cat(message, " \r\n", extraHeaderFiels, "\r\n")),
		_extraHeaderFiels(extraHeaderFiels)
	{
	}

	//  Get the response code based on the HTTP protocol.
	constexpr auto responseCode() const noexcept -> std::string_view
	{
		return _responseCode;
	}

	//  Get the response data which contains the message and extra header fields if present
	constexpr auto responseData() const noexcept -> std::string_view
	{
		return _responseData;
	}

	//  Get the extra header fields
	constexpr auto extraHeaderFiels() const noexcept -> std::string_view
	{
		return _extraHeaderFiels;
	}

private:
	//  The HTTP response code
	std::string _responseCode;

	//  The message
	std::string _responseData;

	//  Extra header fields
	std::string_view _extraHeaderFiels;
};

} // namespace xentara::samples::webService