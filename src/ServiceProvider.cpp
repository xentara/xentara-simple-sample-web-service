// Copyright (c) embedded ocean GmbH

#include <xentara/utils/string/cat.hpp>
#include <xentara/plugin/SharedFactory.hpp>
#include <xentara/process/Microservice.hpp>

#include "ServiceProvider.hpp"
#include "Server.hpp"

#include <iostream>

namespace xentara::samples::webService
{

class ServiceProvider::Environment : public process::ServiceProvider::Environment
{
public:
	auto createMicroservice(const process::MicroserviceClass &microserviceClass,
		plugin::SharedFactory<process::Microservice> &factory)
		-> std::shared_ptr<process::Microservice> override;
};

auto ServiceProvider::Environment::createMicroservice(const process::MicroserviceClass &microserviceClass,
	plugin::SharedFactory<process::Microservice> &factory)
	-> std::shared_ptr<process::Microservice>
{ 
	if (&microserviceClass == &Server::Class::instance())
	{
		return factory.makeShared<Server>();
	}

	throw std::runtime_error(utils::string::cat("WebServer does not support microservices of type \"", microserviceClass.name(), "\""));
}

auto ServiceProvider::createEnvironment() -> std::unique_ptr<process::ServiceProvider::Environment>
{
	return std::make_unique<Environment>();
}

} // namespace xentara::samples::webService