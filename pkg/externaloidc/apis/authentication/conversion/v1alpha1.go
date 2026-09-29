package conversion

import (
	authenticationv1alpha1 "github.com/openshift/api/authentication/v1alpha1"
	"github.com/openshift/oauth-apiserver/pkg/externaloidc/apis/authentication"
)

// ConvertV1alpha1AuthenticationConfigurationToInternal converts the external
// configuration-file API into the representation used by oauth-apiserver.
func ConvertV1alpha1AuthenticationConfigurationToInternal(in *authenticationv1alpha1.AuthenticationConfiguration) *authentication.AuthenticationConfiguration {
	out := &authentication.AuthenticationConfiguration{TypeMeta: in.TypeMeta}
	out.JWT = make([]authentication.JWTAuthenticator, len(in.JWT))
	for i := range in.JWT {
		out.JWT[i] = convertJWTAuthenticator(&in.JWT[i])
	}
	return out
}

func convertJWTAuthenticator(in *authenticationv1alpha1.JWTAuthenticator) authentication.JWTAuthenticator {
	out := authentication.JWTAuthenticator{
		Issuer:                convertIssuer(in.Issuer),
		ClaimMappings:         convertClaimMappings(in.ClaimMappings),
		ClaimValidationRules:  make([]authentication.ClaimValidationRule, len(in.ClaimValidationRules)),
		UserValidationRules:   make([]authentication.UserValidationRule, len(in.UserValidationRules)),
		ExternalClaimsSources: make([]authentication.ExternalClaimsSource, len(in.ExternalClaimsSources)),
	}
	for i := range in.ClaimValidationRules {
		out.ClaimValidationRules[i] = authentication.ClaimValidationRule(in.ClaimValidationRules[i])
	}
	for i := range in.UserValidationRules {
		out.UserValidationRules[i] = authentication.UserValidationRule(in.UserValidationRules[i])
	}
	for i := range in.ExternalClaimsSources {
		out.ExternalClaimsSources[i] = convertExternalClaimsSource(&in.ExternalClaimsSources[i])
	}
	return out
}

func convertIssuer(in *authenticationv1alpha1.Issuer) *authentication.Issuer {
	if in == nil {
		return nil
	}
	return &authentication.Issuer{
		URL:                  in.URL,
		DiscoveryURL:         in.DiscoveryURL,
		CertificateAuthority: in.CertificateAuthority,
		Audiences:            in.Audiences,
		AudienceMatchPolicy:  authentication.AudienceMatchPolicyType(in.AudienceMatchPolicy),
	}
}

func convertClaimMappings(in *authenticationv1alpha1.ClaimMappings) *authentication.ClaimMappings {
	if in == nil {
		return nil
	}
	out := &authentication.ClaimMappings{
		Username: authentication.PrefixedClaimOrExpression(in.Username),
		Groups:   authentication.PrefixedClaimOrExpression(in.Groups),
		UID:      authentication.ClaimOrExpression(in.UID),
		Extra:    make([]authentication.ExtraMapping, len(in.Extra)),
	}
	for i := range in.Extra {
		out.Extra[i] = authentication.ExtraMapping(in.Extra[i])
	}
	return out
}

func convertExternalClaimsSource(in *authenticationv1alpha1.ExternalClaimsSource) authentication.ExternalClaimsSource {
	out := authentication.ExternalClaimsSource{
		Authentication: convertAuthentication(in.Authentication),
		TLS:            convertTLS(in.TLS),
		URL:            convertSourceURL(in.URL),
		Mappings:       make([]authentication.SourcedClaimMapping, len(in.Mappings)),
		Conditions:     make([]authentication.ExternalSourceCondition, len(in.Conditions)),
	}
	for i := range in.Mappings {
		out.Mappings[i] = authentication.SourcedClaimMapping(in.Mappings[i])
	}
	for i := range in.Conditions {
		out.Conditions[i] = authentication.ExternalSourceCondition(in.Conditions[i])
	}
	return out
}

func convertAuthentication(in *authenticationv1alpha1.Authentication) *authentication.Authentication {
	if in == nil {
		return nil
	}
	out := &authentication.Authentication{ClientCredential: convertClientCredential(in.ClientCredential)}
	if in.Type != nil {
		typ := authentication.AuthenticationType(*in.Type)
		out.Type = &typ
	}
	return out
}

func convertClientCredential(in *authenticationv1alpha1.ClientCredentialConfig) *authentication.ClientCredentialConfig {
	if in == nil {
		return nil
	}
	return &authentication.ClientCredentialConfig{
		ClientID:      in.ClientID,
		ClientSecret:  in.ClientSecret,
		TokenEndpoint: in.TokenEndpoint,
		Scopes:        in.Scopes,
		TLS:           convertTLS(in.TLS),
	}
}

func convertTLS(in *authenticationv1alpha1.TLS) *authentication.TLS {
	if in == nil {
		return nil
	}
	return &authentication.TLS{CertificateAuthority: in.CertificateAuthority}
}

func convertSourceURL(in *authenticationv1alpha1.SourceURL) *authentication.SourceURL {
	if in == nil {
		return nil
	}
	return &authentication.SourceURL{Hostname: in.Hostname, PathExpression: in.PathExpression}
}
