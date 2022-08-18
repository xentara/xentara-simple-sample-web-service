// Copyright (c) embedded ocean GmbH

#include "OpenIdAuthenticationProvider.hpp"
#include "HttpError.hpp"

#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable : 4242)
#endif

#ifdef __GNUC__
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

#include <jwt-cpp/jwt.h>

#if defined (_MSC_VER)
#	pragma warning(pop)
#endif

#ifdef __GNUC__
#	pragma GCC diagnostic pop
#endif

namespace xentara::samples::webService
{

auto OpenIdAuthenticationProvider::loadConfig(utils::json::decoder::Object &jsonObject) -> void
{

	// Go through all the parameters
	for (auto &&[key, value] : jsonObject)
	{
		if (key == u8"realm")
		{
			// realm is a string
			auto realm = value.asString<std::u8string>();

			// Check if realm is empty
			if (auto errorMessage = getRealmError(realm))
			{
				utils::json::decoder::throwWithLocation(
					value, std::runtime_error("error found in the realm : " + *errorMessage));
			}

			// Store realm
			_realm = makeRealm(realm);
		}
		else if (key == u8"scopes")
		{
			// Go through all the scopes
			for (auto &&scope : value.asArray())
			{
				// scope is a list
				auto scopeName = scope.asString<std::u8string>();

				// Check if the scopeName meets the criteria
				if (auto errorMessage = getScopeError(scopeName))
				{
					utils::json::decoder::throwWithLocation(
						scope, std::runtime_error("error found in a scope : " + *errorMessage));
				}

				// add new scope in scopes list
				_scopes.emplace(std::move(scopeName));
			}
		}
		else if (key == u8"issuer")
		{
			// issuer is a string
			auto issuer = value.asString<std::u8string>();

			// Check if issuer is empty
			if (issuer.empty())
			{
				utils::json::decoder::throwWithLocation(
					value, std::runtime_error("empty issuer , issuer can not be empty "));
			}

			// Store issuer
			_issuer = issuer;
		}
		else if (key == u8"audience")
		{
			// audience is a string
			auto audience = value.asString<std::u8string>();

			// Check if audience is empty
			if (audience.empty())
			{
				utils::json::decoder::throwWithLocation(
					value, std::runtime_error("empty audience , audience can not be empty"));
			}

			// Store audience
			_audience = audience;
		}
		else if (key == u8"claims")
		{
			// value is Object
			auto claims = value.asObject();

			// Load Claims
			loadClaims(claims);
		}
		else if (key == u8"verification")
		{
			// value is Object
			auto verification = value.asObject();

			// Load verification details
			_verification = AbstractTokenVerification::load(verification);
		}
		else
		{
			config::throwUnknownParameterError(key);
		}
	}

	// check if issuer list is defined
	if (_issuer.empty())
	{
		utils::json::decoder::throwWithLocation(jsonObject, std::runtime_error("missing issuer"));
	}

	// check if audience is defined
	if (_audience.empty())
	{
		utils::json::decoder::throwWithLocation(jsonObject, std::runtime_error("missing audience"));
	}

	// check if verification is defined
	if (!_verification)
	{
		utils::json::decoder::throwWithLocation(jsonObject, std::runtime_error("missing verification"));
	}
	
	return;
}

auto OpenIdAuthenticationProvider::buildAuthenticationHeader() -> void
{
	std::stringstream wwwAuthernicateHeader;
	wwwAuthernicateHeader << "WWW-Authenticate: Bearer";

	// Add realm if defined
	if (_realm)
	{
		wwwAuthernicateHeader << " realm=\"" << utils::ios::toLocal(*_realm) << "\"";
	}

	// Add scopes if defined
	wwwAuthernicateHeader << " scope=\"openid\"";
	for (auto &&scope : _scopes)
	{
		wwwAuthernicateHeader << ' ' << utils::ios::toLocal(scope);
	}

	wwwAuthernicateHeader << "\r\n";

	// store the header
	_wwwAuthernicateHeader = wwwAuthernicateHeader.str();

	return;
}

auto OpenIdAuthenticationProvider::loadClaims(utils::json::decoder::Object &jsonObject) -> void
{
	// Go through all the parameters
	for (auto &&[key, value] : jsonObject)
	{
		// key is a string
		std::string claimType = std::string(key.begin(), key.end());

		// Check if the given key has been added already in the of claims set
		if (_claims.count(claimType))
		{
			utils::json::decoder::throwWithLocation(value,
				std::runtime_error(std::string("dublicated items in claims not allowed : item \"" +
											   std::string(key.begin(), key.end()) + "\" is dublicated")));
		}

		// create a set of a type claim
		std::unordered_set<std::string> claim;

		// value is an array
		auto titleArray = value.asArray();

		// Go through all the parameters
		for (auto &&title : titleArray)
		{
			// name is a string
			auto titleU8String = title.asString<std::u8string>();
			auto titleString = std::string(titleU8String.begin(), titleU8String.end());

			// and new name to the claim
			claim.emplace(titleString);
		}

		// add the claim to claims
		_claims.emplace(claimType, std::move(claim));
	}

	return;
}

std::optional<std::string> OpenIdAuthenticationProvider::getScopeError(std::u8string string)
{
	// check if the scope is empty
	if (string.empty())
	{
		return R"(can not be empty string)";
	}

	// Go through all the characters in the string
	for (auto &&character : string)
	{
		// Check if the character is at least 31 in ascci table
		if (int(character) < 0x20)
		{
			return R"(non visible characters not allowed)";
		}

		// check if the character is DEL character
		if (int(character) == 0x7E)
		{
			return R"(non visible characters not allowed)";
		}

		// check if the character is space (" ")
		if (int(character) == 0x20)
		{
			return R"(space charracter (" ") is not allowed)";
		}

		// check if the character is quote (""")
		if (int(character) == 0x22)
		{
			return R"(quote charracter (""") is not allowed)";
		}

		// check if the character is backshlash ("\")
		if (int(character) == 0x5C)
		{
			return R"(backshlash character ("\") is not allowed)";
		}
	}
	return std::nullopt;
}

std::optional<std::string> OpenIdAuthenticationProvider::getRealmError(std::u8string string)
{

	// Go through all the characters in the string
	for (auto &&character : string)
	{
		// Check if the character is at least 31 in ascci table
		if (int(character) < 0x20 && int(character) != 0x9)
		{
			return R"(non visible characters are not allowed)";
		}

		// check if the character is DEL character
		if (int(character) == 0x7E)
		{
			return R"(non visible characters are not allowed)";
		}
	}
	return std::nullopt;
}

auto OpenIdAuthenticationProvider::decodeJwt(const std::string &encodedToken) -> JwtToken
{
	try
	{
		// Decode the token
		return jwt::decode(encodedToken);
	}
	catch (...)
	{
		// Thows exeption if the token after decoding is not valid
		throw HttpError("400 invalid token", "access denied" , _wwwAuthernicateHeader);
	}
}

auto OpenIdAuthenticationProvider::checkDate(const JwtToken &token) -> void
{
	std::optional<std::uint64_t> expirationTime;
	std::optional<std::uint64_t> notBefore;

	// Get the current time in Unix format to seconds
	auto now =
		std::chrono::time_point_cast<std::chrono::seconds>(std::chrono::system_clock::now()).time_since_epoch().count();

	// Go through all the claims
	for (auto &&[key, value] : token.get_payload_claims())
	{
		// If not before found
		if (key == "nbf")
		{
			notBefore = value.as_int();
		}

		// If expiration time found
		if (key == "exp")
		{
			expirationTime = value.as_int();
		}
	}

	// If not before found
	if (notBefore.has_value())
	{
		// Through exeption if the token is not valid yet
		if (now < notBefore)
		{
			throw HttpError("401 invalid token", "token not valid yet", _wwwAuthernicateHeader);
		}
	}

	// If expiration time is found
	if (expirationTime.has_value())
	{		
		// Through exeptio if the token expired
		if (now > expirationTime)
		{
			throw HttpError("401 invalid token", "token expired", _wwwAuthernicateHeader);
		}
	}
	return;
}

auto OpenIdAuthenticationProvider::checkAudience(const JwtToken &token) -> void
{

	// Go through all the claims
	for (auto &&[key, value] : token.get_payload_claims())
	{
		// if the audience is found
		if (key == "aud")
		{
			// Check if the audience matches matches with servers otherwise throw exeption
			if (value.to_json().to_str() == std::string(_audience.begin(), _audience.end()))
			{
				return;
			}
			else
			{
				throw HttpError("403 invalid token", "incorrect audience", _wwwAuthernicateHeader);
			}
		}
	}

	// Throw exeption when the audience is missing from the client's token
	throw HttpError("400 invalid scope", "incorrect audience", _wwwAuthernicateHeader);
}

auto OpenIdAuthenticationProvider::checkIssuer(const JwtToken &token) -> void
{
	// Go through all the claims
	for (auto &&[key, value] : token.get_payload_claims())
	{			
		// if issuer found
		if (key == "iss")
		{			
			// check if the issuer matches with servers issuer otherwise throw exeption
			if (value.to_json().to_str() == std::string(_issuer.begin(), _issuer.end()))
			{
				return;
			}
			else
			{
				throw HttpError("403 invalid scope", "access denied", _wwwAuthernicateHeader);
			}
		}

	}

	// Throw exeption when the issuer is missing from the client's token
	throw HttpError("403 invalid scope", "access denied", _wwwAuthernicateHeader);
}

auto OpenIdAuthenticationProvider::checkSignature(const JwtToken &token) -> void
{
	try
	{
		// Verifies if the signature is valid
		_verification.get()->verify(token);
	}
	catch (...)
	{
		// Throw exeption if any verification issue
		throw HttpError("401 invalid token", "Jwt verification failed", _wwwAuthernicateHeader);
	}
}

auto OpenIdAuthenticationProvider::checkClaims(const JwtToken &token) -> void
{
	// If no claims were specified, all tokens pass
	if (_claims.empty())
	{
		return;
	}

	// Check if at least one claim title is present
	for (auto &&claim : _claims)
	{
		// Check the names for this title
		if (checkClaim(token, claim.first, claim.second))
		{
			return;
		}
	}

	// No matching claims were found
	throw HttpError("403 invalid scope", "access denied" , _wwwAuthernicateHeader);
}

auto OpenIdAuthenticationProvider::checkClaim(
	const JwtToken &token, const std::string &claim, const std::unordered_set<std::string> &allowedValues) -> bool
{

	// Get the token
	if (!token.has_payload_claim(claim))
	{
		return false;
	}

	// Get the claim's value
	auto value = token.get_payload_claim(claim).to_json();

	// Handle array separately
	if (value.is<picojson::array>())
	{
		for (auto &&element : value.get<picojson::array>())
		{
			if (checkClaimValue(element, allowedValues))
			{
				return true;
			}
		}
	}
	else
	{
		if (checkClaimValue(value, allowedValues))
		{
			return true;
		}
	}
	// nothing matched
	return false;
}

auto OpenIdAuthenticationProvider::checkClaimValue(
	const JwtClaimValue &value, const std::unordered_set<std::string> &allowedValues) -> bool
{
	// check if the claim value is found in the server
	return value.is<std::string>() && allowedValues.find(value.get<std::string>()) != allowedValues.end();
}

auto OpenIdAuthenticationProvider::checkJwt(const std::string &encodedToken) -> void
{

	// Decode the token
	auto token = decodeJwt(encodedToken);

	// Check the not before and expiration Time
	checkDate(token); 
	
	// Check if the audience is found and if it matches with the servers
	checkAudience(token);

	// Check if the audience is found and if it matches with the servers
	checkIssuer(token);

	// Check if the signature is valid
	checkSignature(token);

	// Check if any claims are found and if it matches with the servers
	checkClaims(token);
}

auto OpenIdAuthenticationProvider::checkAuthentication(const lh_rqi_t *request) -> void
{
	using namespace std::literals;

	std::optional<std::string_view> authorization;

	// Iterate through all the headers received
	for (int i = 0; i < request->num_headers; ++i)
	{

		// if is authorization header store it
		if (request->http_headers[i].name == "Authorization"sv)
		{
			// check if the authorization header is already stored
			if (authorization)
			{
				throw HttpError("400 Bad Request",
					{},
					_wwwAuthernicateHeader +
						" error_code=\"invalid_request\" error_message=\"Duplicate Authorization header\"");
			}

			// store the content of the authorization header
			authorization = request->http_headers[i].value;
		}
	}

	// check if the content is empty
	if (!authorization)
	{
		throw HttpError("401 Unauthorized", "Authentication required", _wwwAuthernicateHeader);
	}

	// check if authentication header is found
	if (authorization->empty())
	{
		throw HttpError("400 Bad Request",
			{},
			_wwwAuthernicateHeader + " error_code=\"invalid_request\" error_message=\"Empty authentication field\"");
	}

	// check if Bearer authentication header is found
	static const auto kTokenKey = "Bearer "sv;
	if (!authorization->starts_with(kTokenKey))
	{
		throw HttpError("400 Bad Request",
			{},
			_wwwAuthernicateHeader +
				" error_code=\"invalid_request\" error_message=\"Unsupported authentication method\"");
	}

	// check if the JWT token is valid
	checkJwt(authorization->substr(kTokenKey.size()).data());

	return;
}

auto OpenIdAuthenticationProvider::makeRealm(std::u8string_view string) const -> const std::u8string
{
	std::u8string realmString(string);

	// Go through all characters
	for (std::size_t i = 0; realmString.size() > i; ++i)
	{
		// get the character by its intex
		char character = realmString.at(i);

		// Check if any character matches , add a backslash ("\") before the character
		if (character == '\\' || character == '"')
		{
			realmString.insert(i, u8"\\");
			i++;
		}
	}

	return realmString;
}

} // namespace xentara::samples::webService
