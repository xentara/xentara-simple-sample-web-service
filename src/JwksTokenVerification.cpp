// Copyright (c) embedded ocean GmbH

#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>
#include "JwksTokenVerification.hpp"
#include "TokenVerifierFactory.hpp"

#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable : 4242)
#endif

#ifdef __GNUC__
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

#include <jwt-cpp/jwt.h>

#if defined(_MSC_VER)
#	pragma warning(pop)
#endif

#ifdef __GNUC__
#	pragma GCC diagnostic pop
#endif

namespace xentara::samples::webService
{
using namespace std::literals;

auto JwksTokenVerification::loadConfig(utils::json::decoder::Object &jsonObject) -> void
{
	// Go through all parameters
	for (auto &&[key, value] : jsonObject)
	{
		if (key == u8"jwksFile")
		{
			// The keyFile is a string
			auto keyFile = value.asString<std::u8string>();

			// The serverCertificate may not be empty
			if (keyFile.empty())
			{
				utils::json::decoder::throwWithLocation(value,
					std::runtime_error("empty jwksFile for verification in Authentication for Web Service Server"));
			}

			// Store the serverCertificate
			_jwksFile = std::string(keyFile.begin(), keyFile.end());

			// check it the path the certificate is relative
			if (!_jwksFile.is_absolute())
			{
				utils::json::decoder::throwWithLocation(value,
					std::runtime_error("invalid jwksFile path : set absolute path for the keyFile for verification in "
									   "Authentication for Web Service Server"));
			}

			// Check the server certificate
			std::ifstream file(_jwksFile);
			if (!file.is_open())
			{
				utils::json::decoder::throwWithLocation(
					value, std::runtime_error("invalid jwksFile path : keyFile not found"));
			}
		}
		else
		{
			config::throwUnknownParameterError(key);
		}
	}

	// Check if the keyFile has been found
	if (_jwksFile.empty())
	{
		utils::json::decoder::throwWithLocation(jsonObject,
			std::runtime_error("missing jwksFile path for verification in Authentication for Web Service Server"));
	}
}

auto JwksTokenVerification::verify(const JwtToken &token) -> void
{

	// Find the verifier that matches the key id
	auto verifier = _verifiers.find(token.get_key_id());

	// If no key found through error
	if (verifier == _verifiers.end())
	{
		throw std::runtime_error("unknown key ID in token");
	}

	// Error code of the verifier
	std::error_code errorCode;

	// Verify the token
	verifier->second.verify(token, errorCode);

	// Check if there is any error during verification process
	if (errorCode.value() != static_cast<int>(jwt::error::token_verification_error::ok))
	{
		// Ignore token expiration error
		if (errorCode.value() != static_cast<int>(jwt::error::token_verification_error::token_expired))
		{
			throw std::runtime_error(errorCode.message());
		}
	}

	return;
}

auto JwksTokenVerification::initialize() -> void
{
	// Read the Jwks from the file
	auto jwks = jwt::parse_jwks(readFile(_jwksFile));

	// Go through all the keys and read the key
	for (auto &&jwk : jwks)
	{
		// Get the algorithm from the key
		const auto algorithmFactory = TokenVerifierFactory::factory(jwk.get_algorithm());

		// If one verification algorithm is not found do nothing
		if (algorithmFactory == nullptr)
		{
			continue;
		}

		// Convert the key to pem
		auto x5c = jwk.get_x5c_key_value();

		// Add the pem key and create new verifier
		_verifiers.emplace(jwk.get_key_id(), algorithmFactory->create(jwt::helper::convert_base64_der_to_pem(x5c)));
	}
}
} // namespace xentara::samples::webService