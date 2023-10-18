using ComponentSpace.OpenID.Configuration;
using ComponentSpace.OpenID.Configuration.Resolver;
using ComponentSpace.OpenID.Exceptions;

namespace ExampleOpenIDProvider
{
    public static class ConfigurationExamples
    {
        // This method demonstrates loading OpenID configuration programmatically rather than through
        // appsettings.json or another JSON configuration file.
        // This is useful if configuration is stored in a custom database, for example, and is relatively static.
        // The OpenID configuration is registered by calling:
        // builder.Services.AddOpenIDProvider(config => ConfigurationExamples.ConfigureOpenID(config));
        public static void ConfigureOpenID(OpenIDConfigurations openIDConfigurations)
        {
            openIDConfigurations.Configurations = new OpenIDConfiguration[]
            {
                new OpenIDConfiguration()
                {
                    ProviderConfiguration = new ProviderConfiguration()
                    {
                        ProviderMetadata = new ProviderMetadata()
                        {
                            Issuer = "https://ExampleOpenIDProvider",
                            AuthorizationEndpoint = "/openid/authorize",
                            TokenEndpoint = "/openid/token",
                            UserinfoEndpoint = "/openid/userinfo",
                            JwksUri = "/openid/keys",
                            EndSessionEndpoint = "/openid/logout",
                            ScopesSupported = new string[] { "openid" },
                            ResponseTypesSupported = new string[] { "code", "id_token", "id_token token", "code id_token", "code token", "code id_token token" },
                            ResponseModesSupported = new string[] { "query", "fragment", "form_post" },
                            GrantTypesSupported = new string[] { "authorization_code", "implicit", "refresh_token", "client_credentials" },
                            SubjectTypesSupported = new string[] { "public" },
                            IdTokenSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                            IdTokenEncryptionAlgValuesSupported = new string[] { "A128KW", "A192KW", "A256KW", "dir", "RSA1_5", "RSA-OAEP" },
                            IdTokenEncryptionEncValuesSupported = new string[] { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" },
                            UserinfoSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                            UserinfoEncryptionAlgValuesSupported = new string[] { "A128KW", "A192KW", "A256KW", "dir", "RSA1_5", "RSA-OAEP" },
                            UserinfoEncryptionEncValuesSupported = new string[] { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" },
                            RequestObjectSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                            RequestObjectEncryptionAlgValuesSupported = new string[] { "A128KW", "A192KW", "A256KW", "dir", "RSA1_5", "RSA-OAEP" },
                            RequestObjectEncryptionEncValuesSupported = new string[] { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" },
                            TokenEndpointAuthMethodsSupported = new string[] { "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none" },
                            TokenEndpointAuthSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                            DisplayValuesSupported = new string[] { "page", "popup", "touch", "wap" },
                            ClaimsSupported = new string[] { "amr", "aud", "email", "exp", "family_name", "given_name", "iat", "idp", "iss", "jti", "middle_name", "name", "nbf", "nonce", "preferred_username", "sub", "ver" },
                            CodeChallengeMethodsSupported = new string[] { "plain", "S256" },
                            RequestParameterSupported = true,
                            RequestUriParameterSupported = true
                        },
                        ProviderCertificates = new Certificate[]
                        {
                            new Certificate()
                            {
                                FileName = "certificates/op.pfx",
                                Password = "password"
                            }
                        }
                    },
                    ClientConfigurations = new ClientConfiguration[]
                    {
                        new ClientConfiguration()
                        {
                            Description = "Blazor WASM",
                            ClientID = "CFTapaLooboloAasQvjOYFPlf4Hjhmur",
                            RedirectUris = new string [] { "https://localhost:44361/authentication/login-callback" },
                            PostLogoutRedirectUris = new string [] { "https://localhost:44361/authentication/logout-callback" }
                        },
                        new ClientConfiguration()
                        {
                            Description = "Example OpenID Client",
                            ClientID = "wLpJpHADUqEmmAltrZX87yUMz8lgweWs",
                            ClientSecret = "P41HXh7SptRM6rV4xjgdVmUkXssibunr",
                            RedirectUris = new string [] { "https://localhost:44389/signin-oidc" },
                            PostLogoutRedirectUris = new string [] { "https://localhost:44389/signout-callback-oidc" },
                            ClientCertificates = new Certificate[]
                            {
                                new Certificate()
                                {
                                    FileName = "certificates/client.cer",
                                }
                            }
                        },
                        new ClientConfiguration()
                        {
                            Description = "Client Credentials Flow Example",
                            ClientID = "PQLEh6VrcK57QtGWE3BL0AU0ohgTjS16",
                            ClientSecret = "t9udSQFM3Ipdj4AzW5ci5Kt0obe92YrM"
                        },
                        new ClientConfiguration()
                        {
                            Description = "Resource Owner Password Flow Example",
                            ClientID = "CXRjYezwlXPG1A8Aw1ZxG1atrQu2Mwxg",
                            ClientSecret = "53Unwfbluvk1LYHm7Kf8LE1oKIFm4aee"
                        }
                    }
                }
            };
        }

        // This class demonstrates loading OpenID configuration dynamically using a configuration resolver.
        // Hard-coded configuration is returned in this example but more typically configuration would be read from a custom database.
        // The ConfigurationName property specifies the configuration to use in a multi-tenancy application but is not used in this example.
        // The configuration resolver is registered by calling:
        // builder.Services.AddOpenIDProvider().AddConfigurationResolver<ConfigurationExamples.ConfigurationResolver>();
        public class ConfigurationResolver : IConfigurationResolver
        {
            public string? ConfigurationName { get; set; }

            public Task<ProviderConfiguration> GetProviderConfigurationAsync()
            {
                return Task.FromResult(new ProviderConfiguration()
                {
                    ProviderMetadata = new ProviderMetadata()
                    {
                        Issuer = "https://ExampleOpenIDProvider",
                        AuthorizationEndpoint = "/openid/authorize",
                        TokenEndpoint = "/openid/token",
                        UserinfoEndpoint = "/openid/userinfo",
                        JwksUri = "/openid/keys",
                        EndSessionEndpoint = "/openid/logout",
                        ScopesSupported = new string[] { "openid" },
                        ResponseTypesSupported = new string[] { "code", "id_token", "id_token token", "code id_token", "code token", "code id_token token" },
                        ResponseModesSupported = new string[] { "query", "fragment", "form_post" },
                        GrantTypesSupported = new string[] { "authorization_code", "implicit", "refresh_token", "client_credentials" },
                        SubjectTypesSupported = new string[] { "public" },
                        IdTokenSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                        IdTokenEncryptionAlgValuesSupported = new string[] { "A128KW", "A192KW", "A256KW", "dir", "RSA1_5", "RSA-OAEP" },
                        IdTokenEncryptionEncValuesSupported = new string[] { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" },
                        UserinfoSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                        UserinfoEncryptionAlgValuesSupported = new string[] { "A128KW", "A192KW", "A256KW", "dir", "RSA1_5", "RSA-OAEP" },
                        UserinfoEncryptionEncValuesSupported = new string[] { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" },
                        RequestObjectSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                        RequestObjectEncryptionAlgValuesSupported = new string[] { "A128KW", "A192KW", "A256KW", "dir", "RSA1_5", "RSA-OAEP" },
                        RequestObjectEncryptionEncValuesSupported = new string[] { "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512" },
                        TokenEndpointAuthMethodsSupported = new string[] { "client_secret_basic", "client_secret_post", "client_secret_jwt", "private_key_jwt", "none" },
                        TokenEndpointAuthSigningAlgValuesSupported = new string[] { "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512" },
                        DisplayValuesSupported = new string[] { "page", "popup", "touch", "wap" },
                        ClaimsSupported = new string[] { "amr", "aud", "email", "exp", "family_name", "given_name", "iat", "idp", "iss", "jti", "middle_name", "name", "nbf", "nonce", "preferred_username", "sub", "ver" },
                        CodeChallengeMethodsSupported = new string[] { "plain", "S256" },
                        RequestParameterSupported = true,
                        RequestUriParameterSupported = true
                    },
                    ProviderCertificates = new Certificate[]
                    {
                        new Certificate()
                        {
                            FileName = "certificates/op.pfx",
                            Password = "password"
                        }
                    }
                });
            }

            public Task<ClientConfiguration> GetClientConfigurationAsync(string? clientID)
            {
                switch (clientID)
                {
                    case "CFTapaLooboloAasQvjOYFPlf4Hjhmur":
                        return Task.FromResult(new ClientConfiguration()
                        {
                            Description = "Blazor WASM",
                            ClientID = "CFTapaLooboloAasQvjOYFPlf4Hjhmur",
                            ClientSecret = "wZvn0dy7PX8CkkbgqYllDhlfOpqD9xyr",
                            RedirectUris = new string[] { "https://localhost:44361/authentication/login-callback" },
                            PostLogoutRedirectUris = new string[] { "https://localhost:44361/authentication/logout-callback" }
                        });

                    case "wLpJpHADUqEmmAltrZX87yUMz8lgweWs":
                        return Task.FromResult(new ClientConfiguration()
                        {
                            Description = "Example OpenID Client",
                            ClientID = "wLpJpHADUqEmmAltrZX87yUMz8lgweWs",
                            ClientSecret = "P41HXh7SptRM6rV4xjgdVmUkXssibunr",
                            RedirectUris = new string[] { "https://localhost:44389/signin-oidc" },
                            PostLogoutRedirectUris = new string[] { "https://localhost:44389/signout-callback-oidc" },
                            ClientCertificates = new Certificate[]
                            {
                                new Certificate()
                                {
                                    FileName = "certificates/client.cer",
                                }
                            }
                        });

                    case "PQLEh6VrcK57QtGWE3BL0AU0ohgTjS16":
                        return Task.FromResult(new ClientConfiguration()
                        {
                            Description = "Client Credentials Flow Example",
                            ClientID = "PQLEh6VrcK57QtGWE3BL0AU0ohgTjS16",
                            ClientSecret = "t9udSQFM3Ipdj4AzW5ci5Kt0obe92YrM"
                        });

                    case "CXRjYezwlXPG1A8Aw1ZxG1atrQu2Mwxg":
                        return Task.FromResult(new ClientConfiguration()
                        {
                            Description = "Resource Owner Password Flow Example",
                            ClientID = "CXRjYezwlXPG1A8Aw1ZxG1atrQu2Mwxg",
                            ClientSecret = "53Unwfbluvk1LYHm7Kf8LE1oKIFm4aee"
                        });

                    default:
                        throw new InvalidClientException();
                }
            }
        }
    }
}
