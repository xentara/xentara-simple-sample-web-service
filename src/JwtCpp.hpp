// Copyright (c) embedded ocean GmbH
#pragma once

#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable : 4242 4267)
#endif

#ifdef __GNUC__
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

#include <utility>

#include <jwt-cpp/jwt.h>

namespace xentara::samples::webService
{
// aliases
using JwtToken = decltype(jwt::decode(std::declval<std::string>()));
using JwtClaim = decltype(std::declval<JwtToken>().get_payload_claim(std::declval<std::string>()));
using JwtClaimValue = decltype(std::declval<JwtClaim>().to_json());
using JwtVerifier = decltype(jwt::verify());

}; // namespace xentara::samples::webService

#if defined (_MSC_VER)
#	pragma warning(pop)
#endif

#ifdef __GNUC__
#	pragma GCC diagnostic pop
#endif