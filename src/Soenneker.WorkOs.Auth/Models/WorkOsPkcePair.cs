namespace Soenneker.WorkOs.Auth.Models;

/// <summary>
/// Contains a PKCE verifier and its S256 challenge.
/// </summary>
public sealed record WorkOsPkcePair(string CodeVerifier, string CodeChallenge);
