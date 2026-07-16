namespace Soenneker.WorkOs.Auth.Models;

/// <summary>
/// Contains an authorization URL and the ephemeral values that the caller must preserve until callback processing.
/// </summary>
public sealed record WorkOsAuthorizationRedirect(string Url, string State, string CodeVerifier, string CodeChallenge);
