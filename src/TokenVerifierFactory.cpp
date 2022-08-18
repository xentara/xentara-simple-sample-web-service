// Copyright (c) embedded ocean GmbH

#include "AbstractTokenVerification.hpp"
#include "TokenVerifierFactory.hpp"

#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable : 4242)

#endif

#ifdef __GNUC__
#	pragma GCC diagnostic push
#	pragma GCC diagnostic ignored "-Wold-style-cast"
#endif

#include <jwt-cpp/jwt.h>

#if defined(_MSC_VER)
#	pragma warning(pop)
#endif

#ifdef __GNUC__
#	pragma GCC diagnostic pop
#endif

namespace xentara::samples::webService
{
using namespace std::literals;

auto TokenVerifierFactory::factory(std::string_view algorithmName) -> const TokenVerifierFactory *
{
	// Find the verifier for the given algorithm
	const auto factory = kFactories.find(algorithmName);
	
	// If not found return null
	if (factory == kFactories.end())
	{
		return nullptr;
	}

	return &factory->second.get();
}

const std::unordered_map<std::string_view, std::reference_wrapper<const TokenVerifierFactory >>
	TokenVerifierFactory::kFactories ( 
		{
		{ "RS256"sv, std::cref(kRS256) },
		{ "RS256"sv, std::cref(kRS384) },
		{ "RS512"sv, std::cref(kRS512) },

		{ "HS256"sv, std::cref(kHS256) },
		{ "HS384"sv, std::cref(kHS384) },
		{ "HS512"sv, std::cref(kHS512) },

		{ "ES256"sv, std::cref(kES256) },
		{ "ES256K"sv, std::cref(kES256K) },
		{ "ES384"sv, std::cref(kES384) },
		{ "ES512"sv, std::cref(kES512) },

		{ "PS256"sv, std::cref(kPS256) },
		{ "PS384"sv, std::cref(kPS384) },
		{ "PS512"sv, std::cref(kPS512) },

		{ "ED25519"sv, std::cref(kED25519) },
		{ "ED448"sv, std::cref(kED448) }
		});

} // namespace xentara::samples::webService