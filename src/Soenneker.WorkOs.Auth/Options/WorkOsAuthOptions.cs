namespace Soenneker.WorkOs.Auth.Options;

/// <summary>
/// Configures WorkOS authentication endpoints and application credentials.
/// </summary>
public sealed class WorkOsAuthOptions
{
    /// <summary>
    /// Gets or sets the WorkOS client identifier.
    /// </summary>
    public string ClientId { get; set; } = "";

    /// <summary>
    /// Gets or sets the optional WorkOS client secret sent during token exchanges.
    /// </summary>
    public string? ClientSecret { get; set; }

    /// <summary>
    /// Gets or sets the authorization endpoint used to start an AuthKit sign-in.
    /// </summary>
    public string AuthorizeUrl { get; set; } = "https://api.workos.com/user_management/authorize";

    /// <summary>
    /// Gets or sets the WorkOS API base URL used when constructing browser logout URLs.
    /// </summary>
    public string ClientBaseUrl { get; set; } = "https://api.workos.com";
}
