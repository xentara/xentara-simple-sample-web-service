cmake_minimum_required(VERSION 3.19)

project(xentara-simple-web-service
	VERSION 1.0.0
	DESCRIPTION "A simple webservice for Xentara"
	HOMEPAGE_URL "https://www.xentara.io"
	LANGUAGES CXX)

find_package(XentaraUtils REQUIRED)
find_package(XentaraPlugin REQUIRED)

# the JSON Web Tokens
find_package(jwt-cpp REQUIRED)

# the OpenSSL
find_package(OpenSSL REQUIRED)

# the libhttp
find_library(LIB_HTTP
	NAMES libhttp http
	REQUIRED
)
find_path(HTTP_HEADER_DIR
	NAMES libhttp.h
	REQUIRED
)

add_library(
	${PROJECT_NAME} MODULE
	
	"src/JwtCpp.hpp"
    "src/Plugin.cpp"
	"src/Plugin.hpp"
	"src/ServiceProvider.hpp"
	"src/ServiceProvider.cpp"
	"src/Server.hpp"
	"src/Server.cpp"
	"src/AbstractAuthenticationProvider.hpp"
	"src/OpenIdAuthenticationProvider.cpp"
	"src/OpenIdAuthenticationProvider.hpp"
	"src/HttpError.hpp"
	"src/AbstractTokenVerification.cpp"
	"src/AbstractTokenVerification.hpp"
	"src/SimpleTokenVerification.cpp"
	"src/SimpleTokenVerification.hpp"
	"src/JwksTokenVerification.cpp"
	"src/JwksTokenVerification.hpp"
	"src/TokenVerifierFactory.cpp"
	"src/TokenVerifierFactory.hpp"
)

target_link_libraries(
	${PROJECT_NAME}

	PRIVATE
		Xentara::xentara-utils
		Xentara::xentara-plugin
		OpenSSL::Crypto
		jwt-cpp::jwt-cpp
		${LIB_HTTP}
)

target_include_directories(
	${PROJECT_NAME}

	PRIVATE	
		${HTTP_HEADER_DIR}
)

install_xentara_plugin(${PROJECT_NAME})