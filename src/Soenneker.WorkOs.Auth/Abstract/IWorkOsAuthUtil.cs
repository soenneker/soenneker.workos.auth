using System.IdentityModel.Tokens.Jwt;
using System.Threading;
using System.Threading.Tasks;
using Soenneker.WorkOs.Auth.Models;
using Soenneker.WorkOs.OpenApiClient.Models;

namespace Soenneker.WorkOs.Auth.Abstract;

/// <summary>
/// Provides reusable WorkOS AuthKit authorization, PKCE, token exchange, session, and logout operations.
/// </summary>
public interface IWorkOsAuthUtil
{
    /// <summary>
    /// Generates a cryptographically random OAuth state value.
    /// </summary>
    string CreateState(int byteLength = 32);

    /// <summary>
    /// Generates a PKCE verifier and its S256 challenge.
    /// </summary>
    WorkOsPkcePair CreatePkcePair(int verifierByteLength = 64);

    /// <summary>
    /// Creates the S256 challenge for a PKCE verifier.
    /// </summary>
    string CreateCodeChallenge(string codeVerifier);

    /// <summary>
    /// Returns whether a value satisfies the RFC 7636 verifier syntax and length constraints.
    /// </summary>
    bool IsValidPkceValue(string? value);

    /// <summary>
    /// Compares a verifier with an S256 challenge in fixed time.
    /// </summary>
    bool MatchesCodeChallenge(string codeVerifier, string expectedChallenge);

    /// <summary>
    /// Generates state and PKCE values and builds a WorkOS authorization URL.
    /// </summary>
    WorkOsAuthorizationRedirect CreateAuthorizationRedirect(WorkOsAuthorizationRequest request);

    /// <summary>
    /// Builds a WorkOS authorization URL from caller-managed state and PKCE values.
    /// </summary>
    string BuildAuthorizationUrl(WorkOsAuthorizationRequest request, string state, string codeChallenge);

    /// <summary>
    /// Exchanges an authorization code for a WorkOS session.
    /// </summary>
    ValueTask<UserlandAuthenticateResponse> AuthenticateAuthorizationCode(string code, string codeVerifier,
        WorkOsRequestContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Exchanges a refresh token for a WorkOS session, optionally scoped to an organization.
    /// </summary>
    ValueTask<UserlandAuthenticateResponse> AuthenticateRefreshToken(string refreshToken, string? organizationId = null,
        WorkOsRequestContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Revokes a WorkOS session by identifier.
    /// </summary>
    ValueTask RevokeSession(string sessionId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Refreshes a session to discover its identifier and then revokes it. Returns false when the token has no session claim.
    /// </summary>
    ValueTask<bool> RevokeSessionFromRefreshToken(string refreshToken, WorkOsRequestContext? context = null,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Builds a browser logout URL for a known WorkOS session identifier.
    /// </summary>
    string BuildLogoutUrl(string sessionId, string returnUrl);

    /// <summary>
    /// Refreshes a session to discover its identifier and builds a browser logout URL, or returns null when no session claim exists.
    /// </summary>
    ValueTask<string?> BuildLogoutUrlFromRefreshToken(string refreshToken, string returnUrl,
        WorkOsRequestContext? context = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Reads a JWT without validating it. Authentication middleware must validate tokens before authorization decisions are made.
    /// </summary>
    JwtSecurityToken ReadAccessToken(string accessToken);

    /// <summary>
    /// Reads the <c>sid</c> claim from an access token without validating the token.
    /// </summary>
    string? GetSessionId(string accessToken);
}
