package conversion

import (
	"testing"

	authenticationv1alpha1 "github.com/openshift/api/authentication/v1alpha1"
)

func TestConvertV1alpha1AuthenticationConfigurationToInternal(t *testing.T) {
	prefix := ""
	authType := authenticationv1alpha1.AuthenticationTypeClientCredential
	hostname := "claims.example.com"
	pathExpression := "claims.sub"
	certificateAuthority := "ca"
	mappingName := "department"
	mappingExpression := "response.department"
	condition := "claims.groups.exists(group, group == 'employees')"

	in := &authenticationv1alpha1.AuthenticationConfiguration{
		JWT: []authenticationv1alpha1.JWTAuthenticator{{
			Issuer: &authenticationv1alpha1.Issuer{
				URL:                  "https://issuer.example.com",
				DiscoveryURL:         "https://discovery.example.com/.well-known/openid-configuration",
				CertificateAuthority: certificateAuthority,
				Audiences:            []string{"client"},
				AudienceMatchPolicy:  authenticationv1alpha1.AudienceMatchPolicyMatchAny,
			},
			ClaimMappings: &authenticationv1alpha1.ClaimMappings{
				Username: authenticationv1alpha1.PrefixedClaimOrExpression{Claim: "sub", Prefix: &prefix},
				Extra:    []authenticationv1alpha1.ExtraMapping{{Key: "example.com/role", ValueExpression: "claims.role"}},
			},
			ClaimValidationRules: []authenticationv1alpha1.ClaimValidationRule{{Expression: "claims.email_verified == true"}},
			UserValidationRules:  []authenticationv1alpha1.UserValidationRule{{Expression: "!user.username.startsWith('system:')"}},
			ExternalClaimsSources: []authenticationv1alpha1.ExternalClaimsSource{{
				Authentication: &authenticationv1alpha1.Authentication{
					Type: &authType,
					ClientCredential: &authenticationv1alpha1.ClientCredentialConfig{
						ClientID:      "client-id",
						ClientSecret:  "client-secret",
						TokenEndpoint: "https://issuer.example.com/token",
						Scopes:        []string{"openid"},
						TLS:           &authenticationv1alpha1.TLS{CertificateAuthority: &certificateAuthority},
					},
				},
				TLS:        &authenticationv1alpha1.TLS{CertificateAuthority: &certificateAuthority},
				URL:        &authenticationv1alpha1.SourceURL{Hostname: &hostname, PathExpression: &pathExpression},
				Mappings:   []authenticationv1alpha1.SourcedClaimMapping{{Name: &mappingName, Expression: &mappingExpression}},
				Conditions: []authenticationv1alpha1.ExternalSourceCondition{{Expression: &condition}},
			}},
		}},
	}

	out := ConvertV1alpha1AuthenticationConfigurationToInternal(in)
	jwt := out.JWT[0]

	if jwt.Issuer.URL != in.JWT[0].Issuer.URL || jwt.Issuer.AudienceMatchPolicy != "MatchAny" {
		t.Errorf("issuer was not converted: %#v", jwt.Issuer)
	}
	if jwt.ClaimMappings.Username.Prefix != &prefix || jwt.ClaimMappings.Extra[0].Key != "example.com/role" {
		t.Errorf("claim mappings were not converted: %#v", jwt.ClaimMappings)
	}
	if jwt.ClaimValidationRules[0].Expression != in.JWT[0].ClaimValidationRules[0].Expression || jwt.UserValidationRules[0].Expression != in.JWT[0].UserValidationRules[0].Expression {
		t.Errorf("validation rules were not converted: %#v %#v", jwt.ClaimValidationRules, jwt.UserValidationRules)
	}

	source := jwt.ExternalClaimsSources[0]
	if source.Authentication.ClientCredential.TokenEndpoint != "https://issuer.example.com/token" || *source.Authentication.Type != "ClientCredential" {
		t.Errorf("external source authentication was not converted: %#v", source.Authentication)
	}
	if source.TLS.CertificateAuthority != &certificateAuthority || source.URL.Hostname != &hostname || source.Mappings[0].Name != &mappingName || source.Conditions[0].Expression != &condition {
		t.Errorf("external source was not converted: %#v", source)
	}
}
