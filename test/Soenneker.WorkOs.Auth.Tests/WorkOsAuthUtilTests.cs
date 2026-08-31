using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.WebUtilities;
using Soenneker.WorkOs.Auth.Abstract;
using Soenneker.WorkOs.Auth.Models;
using Soenneker.Tests.HostedUnit;

namespace Soenneker.WorkOs.Auth.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public sealed class WorkOsAuthUtilTests : HostedUnitTest
{
    private readonly IWorkOsAuthUtil _util;

    public WorkOsAuthUtilTests(Host host) : base(host)
    {
        _util = Resolve<IWorkOsAuthUtil>(true);
    }

    [Test]
    public async Task Pkce_pair_is_valid_and_matches()
    {
        WorkOsPkcePair pair = _util.CreatePkcePair();

        await Assert.That(_util.IsValidPkceValue(pair.CodeVerifier)).IsTrue();
        await Assert.That(_util.IsValidPkceValue(pair.CodeChallenge)).IsTrue();
        await Assert.That(_util.MatchesCodeChallenge(pair.CodeVerifier, pair.CodeChallenge)).IsTrue();
        await Assert.That(_util.MatchesCodeChallenge(_util.CreatePkcePair().CodeVerifier, pair.CodeChallenge)).IsFalse();
    }

    [Test]
    public async Task State_is_random_and_url_safe()
    {
        string first = _util.CreateState();
        string second = _util.CreateState();

        await Assert.That(first).IsNotEqualTo(second);
        await Assert.That(first).DoesNotContain("+");
        await Assert.That(first).DoesNotContain("/");
        await Assert.That(first).DoesNotContain("=");
    }

    [Test]
    public async Task Authorization_redirect_contains_oauth_and_pkce_parameters()
    {
        var request = new WorkOsAuthorizationRequest
        {
            RedirectUri = "https://example.com/auth/callback",
            LoginHint = "person@example.com"
        };
        request.AdditionalParameters["organization_id"] = "org_123";
        request.AdditionalParameters["client_id"] = "attacker";
        request.AdditionalParameters["redirect_uri"] = "https://attacker.example/callback";
        request.AdditionalParameters["state"] = "attacker";
        request.AdditionalParameters["code_challenge"] = "attacker";
        request.AdditionalParameters["code_challenge_method"] = "plain";

        WorkOsAuthorizationRedirect redirect = _util.CreateAuthorizationRedirect(request);
        var uri = new System.Uri(redirect.Url);
        var query = QueryHelpers.ParseQuery(uri.Query);

        await Assert.That(uri.GetLeftPart(System.UriPartial.Path))
                    .IsEqualTo("https://api.workos.com/user_management/authorize");
        await Assert.That(query["client_id"].ToString()).IsEqualTo("client_test");
        await Assert.That(query["redirect_uri"].ToString()).IsEqualTo(request.RedirectUri);
        await Assert.That(query["state"].ToString()).IsEqualTo(redirect.State);
        await Assert.That(query["code_challenge"].ToString()).IsEqualTo(redirect.CodeChallenge);
        await Assert.That(query["code_challenge_method"].ToString()).IsEqualTo("S256");
        await Assert.That(query["response_type"].ToString()).IsEqualTo("code");
        await Assert.That(query["login_hint"].ToString()).IsEqualTo(request.LoginHint);
        await Assert.That(query["organization_id"].ToString()).IsEqualTo("org_123");
    }

    [Test]
    public async Task Logout_url_contains_session_and_return_url()
    {
        string logoutUrl = _util.BuildLogoutUrl("session_123", "https://example.com/signed-out");
        var uri = new System.Uri(logoutUrl);
        var query = QueryHelpers.ParseQuery(uri.Query);

        await Assert.That(uri.GetLeftPart(System.UriPartial.Path))
                    .IsEqualTo("https://api.workos.com/user_management/sessions/logout");
        await Assert.That(query["session_id"].ToString()).IsEqualTo("session_123");
        await Assert.That(query["return_to"].ToString()).IsEqualTo("https://example.com/signed-out");
    }

    [Test]
    public async Task Session_id_is_read_from_unvalidated_access_token()
    {
        var token = new JwtSecurityToken(claims: [new Claim("sid", "session_123"), new Claim("sub", "user_123")]);
        string accessToken = new JwtSecurityTokenHandler().WriteToken(token);

        await Assert.That(_util.GetSessionId(accessToken)).IsEqualTo("session_123");
    }
}
