// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/model/AttributeReference.hpp>
#include <xentara/model/GenericElement.hpp>
#include <xentara/plugin/EnableSharedFromThis.hpp>
#include <xentara/process/Microservice.hpp>
#include <xentara/process/MicroserviceClass.hpp>
#include <xentara/utils/ios/toLocal.hpp>
#include <xentara/utils/network/Types.hpp>

#include "AbstractAuthenticationProvider.hpp"
#include "HttpError.hpp"

#include <filesystem>
#include <string>
#include <unordered_map>

#include <libhttp.h>

namespace xentara::samples::webService
{

// A class representing a web server for exchaning .
class Server final : public process::Microservice
{
public:
	// The class object containing meta-information about this element type
	class Class final : public process::MicroserviceClass
	{
	public:
		//  Gets the global instance
		static auto instance() -> Class &
		{
			return _instance;
		}

		auto name() const -> std::u16string_view override
		{
			using namespace std::literals;
			// This is the name of the element class, as it appears in the model.json file 
			return u"Server"sv;
		}

		auto uuid() const -> utils::core::Uuid override
		{
			// This is an arbitrary unique UUID for the driver. This can be anything, but should never change.
			return "1990b329-a079-43bb-98d4-a28db23a5e2b"_uuid;
		}

	private:
		//  The global object that represents the class
		static Class _instance;
	};

protected:
	//  loads the configuration from the json model file
	auto loadConfig(const ConfigIntializer &initializer,
		utils::json::decoder::Object &jsonObject,
		config::Resolver &resolver,
		const FallbackConfigHandler &fallbackHandler) -> void final;

	//  override of the prepare 
	auto prepare() -> void final;

	//  override of the cleanup.
	auto cleanup() -> void final
	{
		httplib_stop(_context);
	}

private:
	//  Load the details for the authentication Provider
	auto loadAuthenticationProvider(utils::json::decoder::Object &jsonObject) -> void;

	// Sent HTTPs Responce
	auto sendResponse(lh_con_t *connection,
		std::string_view responseCode,
		std::string_view responseData = {},
		std::string_view extraHeaderFiels = {}) -> void;

	//  Message handler
	auto logMessageHandler(const lh_con_t *connection, const char *message) -> int;

	//  handler for incoming client messages
	auto beginRequestHandler(lh_con_t *connection) -> int;

	//  Statis version of logMessageHandler
	/// Uses context's user data as the server to call logMessageHandler()
	static auto staticLogMessageHandler(lh_ctx_t *context, const lh_con_t *connection, const char *message) -> int;

	//  Statis version of beginRequestHandler
	/// Uses context's user data as the server to call beginRequestHandler()
	static auto staticBeginRequestHandler(lh_ctx_t *context, lh_con_t *connection) -> int;

	//  The portNumber of the Server
	utils::network::PortNumber _portNumber;

	//  The authetication method for the Server
	std::unique_ptr<AbstractAuthenticationProvider> _authentication;

	//  Server Certificate for the Server
	std::filesystem::path _serverCertificatePath;

	//  contex
	lh_ctx_t *_context { nullptr };
};
} // namespace xentara::samples::webService