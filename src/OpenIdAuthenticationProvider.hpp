// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/config/Errors.hpp>
#include <xentara/utils/io/MemoryInputStream.hpp>
#include <xentara/utils/ios/toLocal.hpp>
#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>
#include <xentara/utils/json/decoder/String.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>

#include <libhttp.h>

#include "AbstractAuthenticationProvider.hpp"
#include "AbstractTokenVerification.hpp"


namespace xentara::samples::webService
{

//  This is the derived authentication class for OpenID.
/// More information about the openID can be found here: https://openid.net/connect/
class OpenIdAuthenticationProvider final : public AbstractAuthenticationProvider
{
public:
	// override function from AbstractAuthenticationProvider::loadConfig(...). This function loads the config parameter
	// from json file which are required for OpenID authentication
	auto loadConfig(utils::json::decoder::Object &jsonObject) -> void final;

	// override function from AbstractAuthenticationProvider::initialize(). This function initializes the verifiers and
	// build
	auto initialize() -> void final
	{
		// verify the token
		_verification->initialize();

		buildAuthenticationHeader();
	}

	// override function from AbstractAuthenticationProvider::checkAuthentication(...)
	auto checkAuthentication(const lh_rqi_t *request) -> void final;

private:
	//  Load the Claims details from Json Object
	auto loadClaims(utils::json::decoder::Object &jsonObject) -> void;

	//  Checks if the string is empty an all the characters on a string in asci table and accepts
	/// all characters between 0x21 to 0x7F exept 0x22(""") and 0x5C("/")
	/// @return false if the string meets the criteria
	std::optional<std::string> getScopeError(std::u8string string);

	//  Checks if the characters in the string are the visible characters
	/// @return false if at least one character is non visible
	std::optional<std::string> getRealmError(std::u8string string);

	//  Adds backslash ("\") before quote (""") and backslash ("\")
	auto makeRealm(std::u8string_view string) const -> const std::u8string;

	//  Built the authentication header for error message responce
	auto buildAuthenticationHeader() -> void;

	//  decode the token
	auto decodeJwt(const std::string &encodedToken) -> JwtToken;

	//  check the not before and expiration date are valid
	auto checkDate(const JwtToken &token) -> void;

	//  check if the audience is valid
	auto checkAudience(const JwtToken &token) -> void;

	//  Check if the issuer is valid
	auto checkIssuer(const JwtToken &token) -> void;

	//  verify the signature
	auto checkSignature(const JwtToken &token) -> void;

	//  Check the Claim titles
	auto checkClaims(const JwtToken &token) -> void;

	//  Check if the claim name
	auto checkClaim(
		const JwtToken &token, const std::string &claim, const std::unordered_set<std::string> &allowedValues) -> bool;

	//  Check if any claims value found
	auto checkClaimValue(const JwtClaimValue &value, const std::unordered_set<std::string> &allowedValues) -> bool;

	//  Checks the tokens validity
	auto checkJwt(const std::string &encodedToken) -> void;

	//  realm
	std::optional<std::u8string> _realm;

	//  issuer
	std::u8string _issuer;

	//  audience
	std::u8string _audience;

	//  list of scopes
	std::unordered_set<std::u8string> _scopes;

	//  list of the claims
	std::unordered_map<std::string, std::unordered_set<std::string>> _claims;

	//  authentication header for the error responce
	std::string _wwwAuthernicateHeader;

	//  Verifies the token
	std::unique_ptr<AbstractTokenVerification> _verification;
};

} // namespace xentara::samples::webService
