// Copyright (c) embedded ocean GmbH

#include <xentara/config/Resolver.hpp>
#include <xentara/data/WriteHandle.hpp>
#include <xentara/utils/io/FileInputStream.hpp>
#include <xentara/utils/ios/toLocal.hpp>
#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>
#include <xentara/utils/json/decoder/String.hpp>
#include <xentara/utils/network/Types.hpp>
#include <xentara/utils/string/cat.hpp>
#include <xentara/config/Errors.hpp>

#include "Server.hpp"
#include "OpenIdAuthenticationProvider.hpp"

#include <any>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <list>
#include <optional>
#include <ranges>
#include <sstream>
#include <string_view>
#include <vector>

namespace xentara::samples::webService
{

Server::Class Server::Class::_instance;

using namespace std::literals;

auto Server::loadConfig(const ConfigIntializer &initializer,
	utils::json::decoder::Object &jsonObject,
	config::Resolver &resolver,
	const FallbackConfigHandler &fallbackHandler) -> void
{
	bool readAuthentication = false;

	// Go through all the parameters
	for (auto &&[key, value] : jsonObject)
	{
		// Go through all the parameters
		if (key == u8"portNumber")
		{
			// The portNumber is a string
			auto portNumber = value.asNumber<utils::network::PortNumber>();

			// The portNumber may not be empty
			if (portNumber == 0)
			{
				utils::json::decoder::throwWithLocation(
					value, std::runtime_error("empty portNumber for webService Server"));
			}

			// store the portNumber
			_portNumber = portNumber;
		}
		else if (key == u8"authentication")
		{
			// The authentication is a string
			auto authentication = value.asObject();

			// Load Authentication Provider
			loadAuthenticationProvider(authentication);
			readAuthentication = true;
		}
		else if (key == u8"serverCertificate")
		{
			// The serverCertificate is a string
			auto serverCertificate = value.asString<std::u8string>();

			// The serverCertificate may not be empty
			if (serverCertificate.empty())
			{
				utils::json::decoder::throwWithLocation(
					value, std::runtime_error("empty serverCertificate for WebService Server"));
			}

			// store the serverCertificate
			_serverCertificatePath = std::string(serverCertificate.begin(), serverCertificate.end());
			
			// check it the path the certificate is relative
			if (!_serverCertificatePath.is_absolute())
			{
				utils::json::decoder::throwWithLocation(value,
					std::runtime_error(
						"invalid Certificate path : set absolute path for the Web Service Server Certificate"));
			}

			// check the server certificate
			std::ifstream file(_serverCertificatePath);
			if (!file.is_open())
			{
				utils::json::decoder::throwWithLocation(value, std::runtime_error("missing serverCertificate"));
			}
		}
		else
		{
			fallbackHandler(key, value);
		}
	}

	// Check portNumber defined
	if (_portNumber == 0)
	{
		utils::json::decoder::throwWithLocation(
			jsonObject, std::runtime_error("missing portNumber for webService Server"));
	}

	// Check Authorization defined
	if (!readAuthentication)
	{
		utils::json::decoder::throwWithLocation(
			jsonObject, std::runtime_error("missing Authentication for webService Server"));
	}

	// Check Server Certificate defined
	if (_serverCertificatePath.empty())
	{
		utils::json::decoder::throwWithLocation(
			jsonObject, std::runtime_error("missing serverCertificate for webService Server"));
	}
}

auto Server::loadAuthenticationProvider(utils::json::decoder::Object &jsonObject) -> void
{
	bool readAuthentication = false ;

	// Go through all the parameters
	for (auto &&[key, value] : jsonObject)
	{
		if (key == u8"@OpenID")
		{

			// check if authentication is already defined
			if (_authentication)
			{
				utils::json::decoder::throwWithLocation(
					key, std::runtime_error("duplicate authentication provider for authentication in web service server"));
			}

			// Value is Object
			auto openId = value.asObject();

			_authentication = std::make_unique<OpenIdAuthenticationProvider>();

			// load configurations as 
			_authentication->loadConfig(openId);
			readAuthentication = true;
		}
		else
		{
			config::throwUnknownParameterError(key);
		}
	}

	// Check Authorization Provider defined
	if (!readAuthentication)
	{
		utils::json::decoder::throwWithLocation(
			jsonObject, std::runtime_error("missing authentication provider for authentication in web service server"));
	}
	return;
}

auto Server::prepare() -> void
{

	// Inintiate all the verifires required
	_authentication->initialize();

	// add character 's' after port to enable security (https)
	auto portNumberString = std::to_string(_portNumber) + "s";

	// convert server certificate path to * char
	const std::string localPath = _serverCertificatePath.string();

	// Set the initiation options for the server
	const lh_opt_t options[] = {
		{ "listening_ports", portNumberString.c_str() }, { "ssl_certificate", localPath.c_str() }, { nullptr, nullptr }
	};

	// set the callback functions for the server
	const lh_clb_t callbacks { .begin_request = &Server::staticBeginRequestHandler,
		.log_message = &Server::staticLogMessageHandler };

	// start the server 
	_context = httplib_start(&callbacks, this, options);

	// check if the serve has been initalized sucessfully
	if (_context == nullptr)
	{
		throw std::runtime_error(
			"Could not initialize the web Service Server");
	}
}

auto Server::logMessageHandler(const lh_con_t *connection, const char *message) -> int
{
	std::cout << message << std::endl;
	return 1;
}

auto Server::staticLogMessageHandler(lh_ctx_t *context, const lh_con_t *connection, const char *message) -> int
{
	auto server = reinterpret_cast<Server *>(httplib_get_user_data(context));
	return server->logMessageHandler(connection, message);
}

auto Server::staticBeginRequestHandler(lh_ctx_t *context, lh_con_t *connection) -> int
{
	auto server = reinterpret_cast<Server *>(httplib_get_user_data(context));
	return server->beginRequestHandler(connection);
}

auto Server::beginRequestHandler(lh_con_t *connection) -> int
{
	using namespace std::literals;

	try
	{
		// get the HTTP request Info
		const auto request = httplib_get_request_info(connection);

		// Check if the client has the proper credentials
		_authentication->checkAuthentication(request);

		// validate for request Method
		const std::string requestMethod { request->request_method };
		
		// check if it is a Post
		if (requestMethod != "GET")
		{
			throw HttpError("405 Method Not Allowed", "only \"GET\" method is accepted");
		}

		// respond with successful messasge to client
		sendResponse(connection, "200 OK", "Hello from Xentara!"sv);

	}
	catch (const HttpError &exception)
	{
		sendResponse(connection, exception.responseCode(), exception.responseData());
	}
	catch (const std::exception &exception)
	{
		sendResponse(connection, "507 Internal Server Error"sv, exception.what());
	}

	return 1; // Mark request as processed
}

auto Server::sendResponse(lh_con_t *connection,
	std::string_view responseCode,
	std::string_view responseData,
	std::string_view extraHeaderFiels) -> void
{
	// Make the data for responce
	std::string response = utils::string::cat("HTTP/1.1 ",
		responseCode,
		"\r\n",
		extraHeaderFiels,
		"Content-Length: ",
		responseData.size(),
		"\r\n"
		"Content-Type: text/plain\r\n\r\n");

	// If responce data is not empty add responce data in the end
	if (!responseData.empty())
	{
		response += responseData;
	}

	// Write the response. 
	httplib_write(_context, connection, response.data(), response.size());

}

} // namespace xentara::samples::webService