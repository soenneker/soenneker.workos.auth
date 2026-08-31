using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Soenneker.Extensions.Task;
using Soenneker.Extensions.ValueTask;
using Soenneker.WorkOs.Auth.Abstract;
using Soenneker.WorkOs.Auth.Models;
using Soenneker.WorkOs.Auth.Options;
using Soenneker.WorkOs.OpenApiClient;
using Soenneker.WorkOs.OpenApiClient.Models;
using Soenneker.WorkOs.OpenApiClientUtil.Abstract;

namespace Soenneker.WorkOs.Auth;

public sealed class WorkOsAuthUtil : IWorkOsAuthUtil
{
    private static readonly JwtSecurityTokenHandler _tokenHandler = new();

    private readonly IWorkOsOpenApiClientUtil _clientUtil;
    private readonly WorkOsAuthOptions _options;

    public WorkOsAuthUtil(IWorkOsOpenApiClientUtil clientUtil, IOptions<WorkOsAuthOptions> options)
    {
        _clientUtil = clientUtil;
        _options = options.Value;
    }

    public string CreateState(int byteLength = 32)
    {
        if (byteLength is < 16 or > 128)
            throw new ArgumentOutOfRangeException(nameof(byteLength), byteLength,
                "State entropy must be between 16 and 128 bytes.");

        return Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(byteLength));
    }

    public WorkOsPkcePair CreatePkcePair(int verifierByteLength = 64)
    {
        if (verifierByteLength is < 32 or > 96)
            throw new ArgumentOutOfRangeException(nameof(verifierByteLength), verifierByteLength,
                "PKCE verifier entropy must be between 32 and 96 bytes so its encoded length remains within RFC 7636 limits.");

        string verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(verifierByteLength));
        return new WorkOsPkcePair(verifier, CreateCodeChallenge(verifier));
    }

    public string CreateCodeChallenge(string codeVerifier)
    {
        if (!IsValidPkceValue(codeVerifier))
            throw new ArgumentException("The PKCE verifier must contain 43-128 RFC 7636 unreserved characters.",
                nameof(codeVerifier));

        return Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(codeVerifier)));
    }

    public bool IsValidPkceValue(string? value)
    {
        return value is { Length: >= 43 and <= 128 } && value.All(static character =>
            char.IsAsciiLetterOrDigit(character) || character is '-' or '.' or '_' or '~');
    }

    public bool MatchesCodeChallenge(string codeVerifier, string expectedChallenge)
    {
        if (!IsValidPkceValue(codeVerifier) || !IsValidPkceValue(expectedChallenge))
            return false;

        byte[] actual = Encoding.ASCII.GetBytes(CreateCodeChallenge(codeVerifier));
        byte[] expected = Encoding.ASCII.GetBytes(expectedChallenge);
        return actual.Length == expected.Length && CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    public WorkOsAuthorizationRedirect CreateAuthorizationRedirect(WorkOsAuthorizationRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        string state = CreateState();
        WorkOsPkcePair pkce = CreatePkcePair();
        string url = BuildAuthorizationUrl(request, state, pkce.CodeChallenge);
        return new WorkOsAuthorizationRedirect(url, state, pkce.CodeVerifier, pkce.CodeChallenge);
    }

    public string BuildAuthorizationUrl(WorkOsAuthorizationRequest request, string state, string codeChallenge)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(state);

        if (!IsValidPkceValue(codeChallenge))
            throw new ArgumentException("The PKCE challenge must contain 43-128 RFC 7636 unreserved characters.",
                nameof(codeChallenge));

        RequireAbsoluteUri(request.RedirectUri, nameof(request.RedirectUri));
        RequireAbsoluteUri(_options.AuthorizeUrl, nameof(_options.AuthorizeUrl));

        var parameters = new Dictionary<string, string?>();

        foreach ((string key, string? value) in request.AdditionalParameters)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(key);
            parameters[key] = value;
        }

        parameters["client_id"] = GetClientId();
        parameters["provider"] = string.IsNullOrWhiteSpace(request.Provider) ? "authkit" : request.Provider;
        parameters["redirect_uri"] = request.RedirectUri;
        parameters["response_type"] = "code";
        parameters["state"] = state;
        parameters["code_challenge"] = codeChallenge;
        parameters["code_challenge_method"] = "S256";

        if (!string.IsNullOrWhiteSpace(request.LoginHint))
            parameters["login_hint"] = request.LoginHint;

        return QueryHelpers.AddQueryString(_options.AuthorizeUrl, parameters);
    }

    public async ValueTask<UserlandAuthenticateResponse> AuthenticateAuthorizationCode(string code, string codeVerifier,
        WorkOsRequestContext? context = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);

        if (!IsValidPkceValue(codeVerifier))
            throw new ArgumentException("The PKCE verifier must contain 43-128 RFC 7636 unreserved characters.",
                nameof(codeVerifier));

        WorkOsOpenApiClient client = await _clientUtil.Get(cancellationToken).NoSync();
        var request = new UserlandSessionsControllerAuthenticate0Request
        {
            ClientId = GetClientId(),
            ClientSecret = GetClientSecret(),
            Code = code,
            CodeVerifier = codeVerifier,
            GrantType = AuthorizationCodeGrantType.AuthorizationCode,
            IpAddress = NormalizeOptional(context?.IpAddress),
            UserAgent = NormalizeOptional(context?.UserAgent)
        };

        return await client.User_management.Authenticate.PostAsync(request, cancellationToken: cancellationToken)
                           .NoSync() ??
               throw new InvalidOperationException("WorkOS authorization code exchange returned an empty response.");
    }

    public async ValueTask<UserlandAuthenticateResponse> AuthenticateRefreshToken(string refreshToken,
        string? organizationId = null, WorkOsRequestContext? context = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(refreshToken);
        WorkOsOpenApiClient client = await _clientUtil.Get(cancellationToken).NoSync();
        var request = new UserlandSessionsControllerAuthenticate0Request
        {
            ClientId = GetClientId(),
            ClientSecret = GetClientSecret(),
            RefreshToken = refreshToken,
            OrganizationId = NormalizeOptional(organizationId),
            IpAddress = NormalizeOptional(context?.IpAddress),
            UserAgent = NormalizeOptional(context?.UserAgent)
        };
        request.AdditionalData["grant_type"] = "refresh_token";

        return await client.User_management.Authenticate.PostAsync(request, cancellationToken: cancellationToken)
                           .NoSync() ??
               throw new InvalidOperationException("WorkOS refresh token exchange returned an empty response.");
    }

    public async ValueTask RevokeSession(string sessionId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        WorkOsOpenApiClient client = await _clientUtil.Get(cancellationToken).NoSync();

        Stream? response = await client.User_management.Sessions.Revoke.PostAsync(
            new UserlandRevokeSessionDto { SessionId = sessionId }, cancellationToken: cancellationToken).NoSync();

        if (response is not null)
            await response.DisposeAsync().NoSync();
    }

    public async ValueTask<bool> RevokeSessionFromRefreshToken(string refreshToken,
        WorkOsRequestContext? context = null, CancellationToken cancellationToken = default)
    {
        UserlandAuthenticateResponse response = await AuthenticateRefreshToken(refreshToken, context: context,
            cancellationToken: cancellationToken).NoSync();
        string? sessionId = GetSessionId(response.AccessToken ?? "");

        if (string.IsNullOrWhiteSpace(sessionId))
            return false;

        await RevokeSession(sessionId, cancellationToken).NoSync();
        return true;
    }

    public string BuildLogoutUrl(string sessionId, string returnUrl)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        RequireAbsoluteUri(returnUrl, nameof(returnUrl));
        RequireAbsoluteUri(_options.ClientBaseUrl, nameof(_options.ClientBaseUrl));

        return QueryHelpers.AddQueryString($"{_options.ClientBaseUrl.TrimEnd('/')}/user_management/sessions/logout",
            new Dictionary<string, string?>
            {
                ["session_id"] = sessionId,
                ["return_to"] = returnUrl
            });
    }

    public async ValueTask<string?> BuildLogoutUrlFromRefreshToken(string refreshToken, string returnUrl,
        WorkOsRequestContext? context = null, CancellationToken cancellationToken = default)
    {
        UserlandAuthenticateResponse response = await AuthenticateRefreshToken(refreshToken, context: context,
            cancellationToken: cancellationToken).NoSync();
        string? sessionId = GetSessionId(response.AccessToken ?? "");
        return string.IsNullOrWhiteSpace(sessionId) ? null : BuildLogoutUrl(sessionId, returnUrl);
    }

    public JwtSecurityToken ReadAccessToken(string accessToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(accessToken);
        return _tokenHandler.ReadJwtToken(accessToken);
    }

    public string? GetSessionId(string accessToken)
    {
        if (string.IsNullOrWhiteSpace(accessToken))
            return null;

        return ReadAccessToken(accessToken).Claims.FirstOrDefault(static claim => claim.Type == "sid")?.Value;
    }

    private string GetClientId()
    {
        if (!string.IsNullOrWhiteSpace(_options.ClientId))
            return _options.ClientId;

        throw new InvalidOperationException("WorkOS ClientId is required.");
    }

    private string? GetClientSecret() => NormalizeOptional(_options.ClientSecret);

    private static string? NormalizeOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : value;

    private static void RequireAbsoluteUri(string value, string parameterName)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out _))
            throw new ArgumentException("The value must be an absolute URI.", parameterName);
    }
}
