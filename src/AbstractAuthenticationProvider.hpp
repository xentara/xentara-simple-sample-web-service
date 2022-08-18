// Copyright (c) embedded ocean GmbH
#pragma once

#include <xentara/utils/json/decoder/Document.hpp>
#include <xentara/utils/json/decoder/Errors.hpp>
#include <libhttp.h>

 namespace xentara::samples::webService
{

//  Authentication Provider Class. This is an abstract class containing all the necessary 
/// authentication methods that must be implemented by any derived authentication classes.
class AbstractAuthenticationProvider
{
public:
	//  virtual destructor
	virtual ~AbstractAuthenticationProvider() = 0;

	//  load all the parameters from JSON file
	/// @param jsonObject the object from the json file
	virtual auto loadConfig(utils::json::decoder::Object &jsonObject) -> void = 0;

	//  This function will initiates all the parameters for the Authentication Provider
	virtual auto initialize() -> void = 0;

	//  verifies the OpenId authentication
	/// @param request contains information about the HTTP request
	virtual auto checkAuthentication(const lh_rqi_t *request) -> void = 0;
};

//  Pure Virtual deconstructor
inline AbstractAuthenticationProvider ::~AbstractAuthenticationProvider() = default;

} // namespace xentara::samples::webService
