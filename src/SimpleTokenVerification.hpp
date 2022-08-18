// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>

#include "JwtCpp.hpp"
#include "AbstractTokenVerification.hpp"
#include "TokenVerifierFactory.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace xentara::samples::webService
{
//  This is derived class of Token verification for simple tokens.
class SimpleTokenVerification final : public AbstractTokenVerification
{
public:
	//  Constructor for Simple verification tokens
	SimpleTokenVerification(std::reference_wrapper<const TokenVerifierFactory> verifierFactory) :
		_verifierFactory(verifierFactory) {};

	// Override function of AbstractTokenVerification::loadConfig(...).
	// It loads all the config parameter required for simple token verification
	auto loadConfig(utils::json::decoder::Object &jsonObject) -> void final;

	// Override function of AbstractTokenVerification::initialize()
	auto initialize() -> void final;

	// Override function of AbstractTokenVerification::verify(...)
	auto verify(const JwtToken &token) -> void final;

private:
	//  Path to the keyFile
	std::filesystem::path _keyFile;

	//  The factory the create the verifier
	std::reference_wrapper<const TokenVerifierFactory> _verifierFactory;

	//  the verifier
	std::optional<JwtVerifier> _verifier;
};

} // namespace xentara::samples::webService
