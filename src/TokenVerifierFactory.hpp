// Copyright (c) embedded ocean GmbH
#pragma once

#include "AbstractTokenVerification.hpp"
#include "JwtCpp.hpp"

#include <string>
#include <string_view>
#include <unordered_map>

#ifdef _MSC_VER
#	pragma warning(push)
#	pragma warning(disable : 4242 )
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

//  Generates Verification verifies for signature algorithms
class TokenVerifierFactory
{
public:
	//  virtual destructor
	virtual ~TokenVerifierFactory() = 0;

	//  Pure virtual function for creating the verifier.
	virtual auto create(const std::string &key) const -> JwtVerifier = 0;

	//  This function creates the TokenVerifierFactrory
	static auto factory(std::string_view algorithmName) -> const TokenVerifierFactory *;

private:
	//  Container with all the signature algorithm verifiers
	static const std::unordered_map<std::string_view, std::reference_wrapper<const TokenVerifierFactory>> kFactories;
};

//   TokenVerifierFactory deconstructor
inline TokenVerifierFactory ::~TokenVerifierFactory() = default;

//  It is used to pass any type of verifiers as TokenVerifierFactory class
namespace
{
	template <class Algorithm>
	class ConcreteTokenVerifierFactory final : public TokenVerifierFactory
	{
	public:
		//  Implementation of the virtual create function for creating verifiers
		auto create(const std::string &key) const -> JwtVerifier override
		{
			//create verifier and add an algorithm available for checking.
			return jwt::verify().allow_algorithm(Algorithm(key));
		}
	};

} // namespace

// Define all the signature verification algorithms
const ConcreteTokenVerifierFactory<jwt::algorithm::rs256> kRS256;
const ConcreteTokenVerifierFactory<jwt::algorithm::rs384> kRS384;
const ConcreteTokenVerifierFactory<jwt::algorithm::rs512> kRS512;

const ConcreteTokenVerifierFactory<jwt::algorithm::hs256> kHS256;
const ConcreteTokenVerifierFactory<jwt::algorithm::hs384> kHS384;
const ConcreteTokenVerifierFactory<jwt::algorithm::hs512> kHS512;

const ConcreteTokenVerifierFactory<jwt::algorithm::es256> kES256;
const ConcreteTokenVerifierFactory<jwt::algorithm::es256k> kES256K;
const ConcreteTokenVerifierFactory<jwt::algorithm::es384> kES384;
const ConcreteTokenVerifierFactory<jwt::algorithm::es512> kES512;

const ConcreteTokenVerifierFactory<jwt::algorithm::ps256> kPS256;
const ConcreteTokenVerifierFactory<jwt::algorithm::ps384> kPS384;
const ConcreteTokenVerifierFactory<jwt::algorithm::ps512> kPS512;

const ConcreteTokenVerifierFactory<jwt::algorithm::ed25519> kED25519;
const ConcreteTokenVerifierFactory<jwt::algorithm::ed448> kED448;

} // namespace xentara::samples::webService