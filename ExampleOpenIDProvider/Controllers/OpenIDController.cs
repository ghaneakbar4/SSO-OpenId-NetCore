using ComponentSpace.OpenID;
using ComponentSpace.OpenID.Exceptions;
using ComponentSpace.OpenID.Security;
using ExampleOpenIDProvider.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using System.Security.Claims;

namespace ExampleOpenIDProvider.Controllers
{
    public class OpenIDController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        private readonly IOpenIDProvider _openIDProvider;

        private readonly IIDGenerator _idGenerator;

        private readonly OpenIDUserContext _openIDUserContext;

        public OpenIDController(IConfiguration configuration, 
                                IOpenIDProvider openIDProvider, 
                                IIDGenerator idGenerator,
                                OpenIDUserContext openIDUserContext)
        {
            _configuration = configuration;
            _openIDProvider = openIDProvider;
            _idGenerator = idGenerator;
            _openIDUserContext = openIDUserContext;
        }

        [Route(".well-known/openid-configuration")]
        [ResponseCache(Duration = 600, Location = ResponseCacheLocation.Any)]
        public async Task<IActionResult> GetMetadataAsync()
        {
            // Return the OpenID provider's metadata.
            return await _openIDProvider.GetMetadataAsync();
        }

        [Route("openid/keys")]
        [ResponseCache(Duration = 600, Location = ResponseCacheLocation.Any)]
        public async Task<IActionResult> GetKeysAsync()
        {
            // Return the OpenID provider's keys.
            return await _openIDProvider.GetKeysAsync();
        }

        [Route("openid/authorize")]
        public async Task<IActionResult> AuthorizeAsync()
        {
            try
            {
                // Receive and process the OpenID authentication request.
                var authenticationRequest = await _openIDProvider.ReceiveAuthnRequestAsync();

                // If the user is authenticated but login is required, re-authenticate the user.
                // Otherwise, send an authentication response.
                // If the user isn't authenticated but login isn't permitted, send an error response.
                // Otherwise, authenticate the user.
                if (User.Identity is not null && User.Identity.IsAuthenticated)
                {
                    if (authenticationRequest.Prompt == OpenIDConstants.PromptModes.Login)
                    {
                        return Redirect("/Identity/Account/Logout/Initiate?returnUrl=/openid/login");
                    }

                    return await SendAuthnResponseAsync(authenticationRequest.ClientID!);
                }
                else
                {
                    if (authenticationRequest.Prompt == OpenIDConstants.PromptModes.None)
                    {
                        throw new LoginRequiredException();
                    }

                    return RedirectToAction("Login", new { ClientID = authenticationRequest.ClientID });
                }
            }

            catch (Exception exception)
            {
                // Send an authentication error response to the client.
                return await _openIDProvider.SendAuthnErrorResponseAsync(exception);
            }
        }

        [Route("openid/token")]
        [ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
        public async Task<IActionResult> TokenAsync()
        {
            // Return the OpenID tokens.
            return await _openIDProvider.GetTokensAsync(GetRefreshTokenResultAsync, GetClientCredentialsResultAsync, GetUserCredentialsResultAsync);
        }

        [Route("openid/userinfo")]
        public async Task<IActionResult> UserInfoAsync()
        {
            // Return the user information.
            return await _openIDProvider.GetUserInfoAsync();
        }

        [Route("openid/introspect")]
        public async Task<IActionResult> IntrospectTokenAsync()
        {
            // Introspect the token.
            return await _openIDProvider.IntrospectTokenAsync();
        }

        [Authorize(AuthenticationSchemes = "Identity.Application")]
        [Route("openid/login")]
        public async Task<IActionResult> LoginAsync(string clientID)
        {
            // Now that the user has been authenticated, send an authentication response to the client.
            return await SendAuthnResponseAsync(clientID);
        }

        [Route("openid/logout")]
        public async Task<IActionResult> LogoutAsync()
        {
            // Remove any refresh tokens associated with this user.
            if (User.Identity is not null)
            {
                var nameIdentifier = User.FindFirst(ClaimTypes.NameIdentifier);

                if (nameIdentifier is not null && nameIdentifier.Value is not null)
                {
                    var openIDUsers = _openIDUserContext.OpenIDUsers?.Where(u => u.Subject == nameIdentifier.Value);

                    if (openIDUsers is not null && openIDUsers.Count() > 0)
                    {
                        _openIDUserContext.OpenIDUsers?.RemoveRange(openIDUsers);
                        await _openIDUserContext.SaveChangesAsync();
                    }
                }
            }

            // Receive and process the OpenID logout request.
            await _openIDProvider.ReceiveLogoutRequestAsync();

            if (User.Identity is not null && User.Identity.IsAuthenticated)
            {
                // Logout locally.
                return Redirect("/Identity/Account/Logout/Initiate?returnUrl=/openid/logout-callback");
            }

            // Send a logout response to the client.
            return await LogoutCallbackAsync();
        }

        [Route("openid/logout-callback")]
        public async Task<IActionResult> LogoutCallbackAsync()
        {
            // Now that the user is logged out, send a logout response to the client.
            return await _openIDProvider.SendLogoutResponseAsync();
        }

        private async Task<IActionResult> SendAuthnResponseAsync(string clientID)
        {
            try
            {
                // Confirm the user has been authenticated.
                if (User.Identity is null)
                {
                    throw new Exception("The user isn't logged in.");
                }

                var nameIdentifier = User.FindFirst(ClaimTypes.NameIdentifier);

                if (nameIdentifier is null || nameIdentifier.Value is null)
                {
                    throw new Exception("The name identifier is missing.");
                }

                // Create some claims based off the user identity to include in the identity token or user info.
                var claims = new List<Claim>();

                if (User.Identity.Name is not null)
                {
                    claims.Add(new Claim(OpenIDConstants.ClaimNames.Name, User.Identity.Name));
                    claims.Add(new Claim(OpenIDConstants.ClaimNames.PreferredUsername, User.Identity.Name));
                }

                var userClaim = User.FindFirst(ClaimTypes.GivenName);

                if (userClaim is not null)
                {
                    claims.Add(new Claim(OpenIDConstants.ClaimNames.GivenName, userClaim.Value));
                }

                userClaim = User.FindFirst(ClaimTypes.Surname);

                if (userClaim is not null)
                {
                    claims.Add(new Claim(OpenIDConstants.ClaimNames.FamilyName, userClaim.Value));
                }

                userClaim = User.FindFirst(ClaimTypes.Email);

                if (userClaim is not null)
                {
                    claims.Add(new Claim(OpenIDConstants.ClaimNames.Email, userClaim.Value));
                }

                // The JWT access token can be used by the application for API authorization purposes, if required.
                // The scp claim is used when performing the "required scope" authorization check. 
                var jwtClaims = new List<Claim>()
                {
                    new Claim(ClaimConstants.Scp, LicenseController.GetLicenseScope)
                };

                var accessTokenExpiresAt = GetUtcAccessTokenExpiresAt();

                var accessToken = await _openIDProvider.CreateJwtAccessTokenAsync(clientID, _configuration["JWT:Audience"], nameIdentifier.Value, LicenseController.GetLicenseScope, jwtClaims, accessTokenExpiresAt);

                // Refresh tokens are optional but if supported the application is responsible for their control and lifetime.
                var refreshToken = _idGenerator.Generate();

                var openIDUser = new OpenIDUser()
                {
                    RefreshToken = refreshToken,
                    ClientID = clientID,
                    Subject = nameIdentifier.Value,
                    UtcExpiresAt = DateTime.UtcNow.Add(OpenIDConstants.Defaults.RefreshTokenExpiry)
                };

                await _openIDUserContext.AddAsync(openIDUser);
                await _openIDUserContext.SaveChangesAsync();

                // Send an authentication response to the client.
                return await _openIDProvider.SendAuthnResponseAsync(nameIdentifier.Value, claims, accessToken, refreshToken, accessTokenExpiresAt);
            }

            catch (Exception exception)
            {
                // Send an authentication error response to the client.
                return await _openIDProvider.SendAuthnErrorResponseAsync(exception);
            }
        }

        // This delegate is only required if the refresh_token grant type is supported.
        private async Task<RefreshTokenResult> GetRefreshTokenResultAsync(string clientID, string refreshToken)
        {
            var refreshTokenResult = new RefreshTokenResult();

            // Lookup the refresh token in the database ensuring it hasn't expired and that it's for the specified client.
            var openIDUser = _openIDUserContext.OpenIDUsers?.SingleOrDefault(u => u.RefreshToken == refreshToken);

            if (openIDUser is null)
            {
                throw new InvalidRequestException("The refresh token is unknown.");
            }

            if (openIDUser.UtcExpiresAt is not null && DateTime.UtcNow >= openIDUser.UtcExpiresAt)
            {
                throw new InvalidRequestException("The refresh token has expired.");
            }

            if (openIDUser.ClientID != clientID)
            {
                throw new InvalidClientException("The client ID is incorrect.");
            }

            var jwtClaims = new List<Claim>()
            {
                new Claim(ClaimConstants.Scp, LicenseController.GetLicenseScope)
            };

            // Create a JWT access token and roll over the refresh token.
            var accessTokenExpiresAt = GetUtcAccessTokenExpiresAt();

            var accessToken = await _openIDProvider.CreateJwtAccessTokenAsync(clientID, _configuration["JWT:Audience"], openIDUser.Subject, LicenseController.GetLicenseScope, jwtClaims, accessTokenExpiresAt);

            refreshToken = _idGenerator.Generate();

            refreshTokenResult.AccessToken = accessToken;
            refreshTokenResult.RefreshToken = refreshToken;
            refreshTokenResult.UtcAccessTokenExpiresAt = accessTokenExpiresAt;

            // Remember the new refresh token.
            openIDUser.RefreshToken = refreshToken;
            openIDUser.UtcExpiresAt = DateTime.UtcNow.Add(OpenIDConstants.Defaults.RefreshTokenExpiry);

            await _openIDUserContext.SaveChangesAsync();

            return refreshTokenResult;
        }

        // This delegate is only required if the client_credentials grant type is supported.
        private async Task<ClientCredentialsResult> GetClientCredentialsResultAsync(string clientID, string? scope)
        {
            var clientCredentialsResult = new ClientCredentialsResult();

            // Create a JWT access token.
            var jwtClaims = new List<Claim>()
            {
                new Claim(ClaimConstants.Scp, LicenseController.GetLicenseScope)
            };

            var accessTokenExpiresAt = GetUtcAccessTokenExpiresAt();

            var accessToken = await _openIDProvider.CreateJwtAccessTokenAsync(clientID, _configuration["JWT:Audience"], null, LicenseController.GetLicenseScope, jwtClaims, accessTokenExpiresAt);

            clientCredentialsResult.AccessToken = accessToken;
            clientCredentialsResult.UtcAccessTokenExpiresAt = accessTokenExpiresAt;

            return clientCredentialsResult;
        }

        // This delegate is only required if the password grant type is supported.
        private async Task<UserCredentialsResult> GetUserCredentialsResultAsync(string clientID, string? userName, string? userPassword, string? scope)
        {
            var userCredentialsResult = new UserCredentialsResult();

            // Authenticate the user - details not shown.

            // Create a JWT access token.
            var jwtClaims = new List<Claim>()
            {
                new Claim(ClaimConstants.Scp, LicenseController.GetLicenseScope)
            };

            var accessTokenExpiresAt = GetUtcAccessTokenExpiresAt();

            var accessToken = await _openIDProvider.CreateJwtAccessTokenAsync(clientID, _configuration["JWT:Audience"], null, LicenseController.GetLicenseScope, jwtClaims, accessTokenExpiresAt);

            userCredentialsResult.AccessToken = accessToken;
            userCredentialsResult.UtcAccessTokenExpiresAt = accessTokenExpiresAt;

            return userCredentialsResult;
        }

        private DateTime? GetUtcAccessTokenExpiresAt()
        {
            // For testing purposes, the JWT access token expiration may be shortened.
            //return DateTime.UtcNow.AddSeconds(30);

            // Use the default expiration of 30 minutes.
            return null;
        }
    }
}
