// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/config/Errors.hpp>
#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>

#include "JwtCpp.hpp"

#include <filesystem>
#include <string>

namespace xentara::samples::webService
{
//  The Abstract Class for Token Verification. This class contains all the necessary method which
// has to implemented by all the derived token verification classes
class AbstractTokenVerification
{
public:
	//  the virtual destructor
	virtual ~AbstractTokenVerification() = 0;

	//  Load the configurations from JSON Object for verification
	//  jsonObject the object from the json file
	virtual auto loadConfig(utils::json::decoder::Object &jsonObject) -> void = 0;

	// Initialize the parameters for the token Verification
	virtual auto initialize() -> void = 0;

	// verify the token
	virtual auto verify(const JwtToken &token) -> void = 0;

	//  read the from JSON Object, the type of authentication and returns the apropriate TokenVerifier
	static auto load(utils::json::decoder::Object &jsonObject) -> std::unique_ptr<AbstractTokenVerification>;

	//  read the key from the file
	auto readFile(const std::filesystem::path &path) -> std::string;
};

//  the virtual destructor
inline AbstractTokenVerification::~AbstractTokenVerification() = default;

} // namespace xentara::samples::webService