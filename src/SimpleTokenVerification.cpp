// Copyright (c) embedded ocean GmbH

#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>

#include "SimpleTokenVerification.hpp"

#include <fstream>

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

auto SimpleTokenVerification::loadConfig(utils::json::decoder::Object &jsonObject) -> void
{
	// Go through all parameters
	for (auto &&[key, value] : jsonObject)
	{
		if (key == u8"keyFile")
		{
			// The keyFile is a taken as a string
			auto keyFile = value.asString<std::u8string>();

			// Check if the serverCertificate is empty. If yes, throw error.
			if (keyFile.empty())
			{
				utils::json::decoder::throwWithLocation(value,
					std::runtime_error("empty keyFile for verification in Authentication for Web Service Server"));
			}

			// store the server certificate
			_keyFile = std::string(keyFile.begin(), keyFile.end());

			// check it the path the certificate is relative. If yes, throw error. Only absolute paths are allowed.
			if (!_keyFile.is_absolute())
			{
				utils::json::decoder::throwWithLocation(value,
					std::runtime_error("invalid keyFile path : set absolute path for the keyFile for verification in "
									   "Authentication for Web Service Server"));
			}

			// check the server certificate
			std::ifstream file(_keyFile);
			if (!file.is_open())
			{
				utils::json::decoder::throwWithLocation(
					value, std::runtime_error("invalid keyFile path : keyFile not found"));
			}
		}
		else
		{
			// In any other keys, throw unknown parameter error
			config::throwUnknownParameterError(key);
		}
	}

	// Check if the keyFile has been found
	if (_keyFile.empty())
	{
		utils::json::decoder::throwWithLocation(jsonObject,
			std::runtime_error("missing keyFile path for verification in Authentication for Web Service Server"));
	}
}

auto SimpleTokenVerification::initialize() -> void
{
	// Read the key from the file
	auto key = readFile(_keyFile);

	// Store the Verifier
	_verifier = _verifierFactory.get().create(key);
}

auto SimpleTokenVerification::verify(const JwtToken &token) -> void
{
	// error code of the verifier
	std::error_code errorCode;

	// Verify the token
	_verifier->verify(token, errorCode);

	// Check if there is any error during the verification process
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

} // namespace xentara::samples::webService