// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/process/ServiceProvider.hpp>

#include "Server.hpp"

#include <string_view>


namespace xentara::samples::webService
{
class Environment;

//  This is the service provider class. It registers all the elements the service provider provides,
// and creates the runtime environment.
class ServiceProvider : public process::ServiceProvider
{
public:

	auto name() const -> std::u16string_view override
	{
		using namespace std::literals;

		// This is the name of the micro service, as it appears in the model.json file
		return u"SimpleWebService"sv;
	}


	auto uuid() const -> utils::core::Uuid override
	{
		// This is an arbitrary unique UUID for the service provider. This can be anything, but should never change.
		return "62f9e307-1e4b-4034-a17a-7986172c74b2"_uuid;
	}

	auto registerObjects(Registry &registry) -> void override
	{
		// Register all the object classes
		registry << Server::Class::instance() ;
	}

	auto createEnvironment() -> std::unique_ptr<process::ServiceProvider::Environment> override;

private:
	//  The service provider runtime environment
	class Environment;
};

} // namespace xentara::samples::webService
