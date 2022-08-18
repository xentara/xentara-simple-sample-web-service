// Copyright (c) embedded ocean GmbH

#include <xentara/utils/io/FileInputStream.hpp>
#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>

#include "AbstractTokenVerification.hpp"
#include "JwksTokenVerification.hpp"
#include "SimpleTokenVerification.hpp"

#include <fstream>

#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable : 4242)
#endif

#include <jwt-cpp/jwt.h>

#ifdef _MSC_VER
#	pragma warning(pop)
#endif

namespace xentara::samples::webService
{
using namespace std::literals;

auto AbstractTokenVerification::load(utils::json::decoder::Object &jsonObject)
	-> std::unique_ptr<AbstractTokenVerification>
{
	// Create authentication Method
	std::unique_ptr<AbstractTokenVerification> authentication;

	// Go through all the parameters
	for (auto &&[key, value] : jsonObject)
	{
		// check if authentication is already defined
		if (authentication)
		{
			utils::json::decoder::throwWithLocation(
				key, std::runtime_error("extra members in verification block of web service server authentication"));
		}

		if (key == u8"@JWKS")
		{
			// Value is Object
			auto jwks = value.asObject();

			// Set authentication as Jwt
			authentication = std::make_unique<JwksTokenVerification>();

			// load configurations as Jwt
			authentication->loadConfig(jwks);
		}
		else if (key.starts_with(u8'@'))
		{
			// take the openId object
			auto openId = value.asObject();

			// Remove the @-sign to get the pure algorithm name
			const auto algorithmName = key.substr(1);

			// Get the algorithm
			const auto factory = TokenVerifierFactory::factory(
				std::string_view(reinterpret_cast<const char *>(algorithmName.data()), algorithmName.size()));

			// check if that algorithm exist
			if (!factory)
			{
				utils::json::decoder::throwWithLocation(key,
					std::runtime_error(utils::string::cat(
						"unkown verification method ", key, " in web service server authentication")));
			}

			// Set authentication as Simple token
			authentication = std::make_unique<SimpleTokenVerification>(*factory);

			// load configurations as Simple Token
			authentication->loadConfig(openId);
		}
		else
		{
			config::throwUnknownParameterError(key);
		}
	}

	// Check Authorization Provider defined
	if (!authentication)
	{
		utils::json::decoder::throwWithLocation(
			jsonObject, std::runtime_error("missing authentication provider for authentication in web service server"));
	}

	return authentication;
}

auto AbstractTokenVerification::readFile(const std::filesystem::path &path) -> std::string
{
	// set the path of the keyFile
	utils::io::File keyFile(path, utils::io::File::Access::Read);

	// Read all the file
	auto keyData = keyFile.readAll();

	// Convert it in to char
	auto keyText = std::span(reinterpret_cast<const char *>(keyData.data()), keyData.size());

	return { keyText.data(), keyText.size() };
}

} // namespace xentara::samples::webService