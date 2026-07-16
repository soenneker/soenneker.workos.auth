namespace Soenneker.WorkOs.Auth.Models;

/// <summary>
/// Carries optional request metadata forwarded during WorkOS token exchanges.
/// </summary>
public sealed record WorkOsRequestContext(string? IpAddress = null, string? UserAgent = null);
