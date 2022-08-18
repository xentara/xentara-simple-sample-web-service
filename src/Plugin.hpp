// Copyright (c) embedded ocean GmbH
#pragma once

#include "ServiceProvider.hpp"

#include <xentara/plugin/Plugin.hpp>

namespace xentara::samples::webService
{

//  This is the plugin class. This class registers all the drivers and service providers.
class Plugin final : plugin::Plugin
{
public:
	auto registerObjects(Registry &registry) -> void final
	{
		// Register the service provider object.
		registry << _serviceProvider;
	}

private:
	//  The service provider object
	ServiceProvider _serviceProvider;

	//  The global plugin object
	static Plugin _instance;
};

} // namespace xentara::samples::webService