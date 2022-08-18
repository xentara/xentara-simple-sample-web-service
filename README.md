# Simple Web Service for Xentara
This project contains a simple web service for Xentara. It requires the Xentara development environment, as well as a Xentara licence. You can get a Xentara licence in the [Xentara Online Shop](https://www.xentara.io/product/xentara-for-industrial-automation/).

The documentation for Xentara can be found at https://docs.xentara.io/xentara

This mircoservice used the Xentara Utility Llibrary, as well as the Xentara Plugin Framework. Docs can be found here:

- https://docs.xentara.io/xentara-utils/
- https://docs.xentara.io/xentara-plugin/

## Functionality
This Web Service acts as a server, authenticates the credential and uses HTTP/1.1 requests for communication with other devices.
The Web service only responses to GET request made by client. It will return _"Hello from Xentara!"_ message.

## Dependencies

The following tools must be installed in order to use this microservice:

* [openSSL](https://www.openssl.org/)
* [libhttp](https://www.libhttp.org/)
* [jwt-cpp](https://thalhammer.github.io/jwt-cpp/)

## Xentara Element: Server

This plugin is a [microservice](https://docs.xentara.io/xentara/xentara_microservices.html) with model file descriptor as `@Microservice.SimpleWebService.Server`, that represents a web server which uses HTTP/1.1 protocol with GET method implementation. 

The class can be found in the following files:

- [src/Server.hpp](src/Server.hpp)
- [src/Server.cpp](src/Server.cpp)

This server provides secure connections using HTTP/1.1 protocol for receiving requests. 
It can use different methods of authentication. 
Current implementation contains the use of [OpenID authentication](https://openid.net/connect/) to verify the identity of the end-user and to obtain basic user profile information.
OpenID is an open standard and decentralized authentication protocol. 

The class can be found in the following files:

- [src/AbstractAuthenticationProvider.hpp](src/AbstractAuthenticationProvider.hpp)
- [src/OpenIdAuthenticationProvider.hpp](src/OpenIdAuthenticationProvider.hpp)
- [src/OpenIdAuthenticationProvider.cpp](src/OpenIdAuthenticationProvider.cpp)

Server also supports simple and [JWKS](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets) tokens verification. 
When using simple token, the signature verification algorithm such as RS256 and key must be specified in the [config/model.json](config/model.json) file, whereas when using JWKS, the authentication process can detect the key from the given keychain automatically.

The class can be found in the following files:

- [src/AbstractTokenVerification.hpp](src/AbstractTokenVerification.hpp)
- [src/AbstractTokenVerification.cpp](src/AbstractTokenVerification.cpp)
- [src/TokenVerifierFactory.hpp](src/TokenVerifierFactory.hpp)
- [src/TokenVerifierFactory.cpp](src/TokenVerifierFactory.cpp)
- [src/SimpleTokenVerification.hpp](src/SimpleTokenVerification.hpp)
- [src/SimpleTokenVerification.cpp](src/SimpleTokenVerification.cpp)
- [src/JwksTokenVerification.hpp](src/JwksTokenVerification.hpp)
- [src/JwksTokenVerification.cpp](src/JwksTokenVerification.cpp)

**Note:** This microservice has no tasks, events or attributes. 


## The Sample Model
This project contains a sample model file [config/model.json](config/model.json). The file contains the following functionality:

1. Reads the port number and assigns it for web communication. 
1. Checks for different type of the authentication method. In this case, [OpenId authentication](https://openid.net/connect/) method is used. It authenticates and checks all of the details. [JWKS](https://auth0.com/docs/secure/tokens/json-web-tokens/json-web-key-sets) token is used for verification.
1. It validates the server certificate.
1. If everything appears to be in order, the web server is started and ready to accept GET requests. Only _"Hello from Xentara!"_ will be displayed.

