// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>

#include "JwtCpp.hpp"
#include "AbstractTokenVerification.hpp"

#include <filesystem>
#include <string>
#include <unordered_map>
#include <fstream>

namespace xentara::samples::webService
{

//  This is derived class of Token verification for JSON web key sets. 
class JwksTokenVerification : public AbstractTokenVerification
{
public:
	// Override function of AbstractTokenVerification::loadConfig(...). This function loads the configuration parameter
	// required for jwts token verification
	auto loadConfig(utils::json::decoder::Object &jsonObject) -> void final;

	// Override function of AbstractTokenVerification::initialize(). This function reads the file and creates a verifier
	auto initialize() -> void override;

	// Override function of AbstractTokenVerification::verify(...). This function creates the verification process of
	// the token
	auto verify(const JwtToken &token) -> void final;

private:
	//  Path to the keyFile
	std::filesystem::path _jwksFile;

	//  Jwts verifiers map
	std::unordered_map<std::string, JwtVerifier> _verifiers;
};

} // namespace xentara::samples::webService