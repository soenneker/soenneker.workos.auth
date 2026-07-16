using System.Collections.Generic;

namespace Soenneker.WorkOs.Auth.Models;

/// <summary>
/// Describes a WorkOS authorization redirect.
/// </summary>
public sealed class WorkOsAuthorizationRequest
{
    /// <summary>
    /// Gets or sets the absolute callback URI registered with WorkOS.
    /// </summary>
    public string RedirectUri { get; set; } = "";

    /// <summary>
    /// Gets or sets an optional login hint, such as an email address.
    /// </summary>
    public string? LoginHint { get; set; }

    /// <summary>
    /// Gets or sets the provider query value. The default is <c>authkit</c>.
    /// </summary>
    public string Provider { get; set; } = "authkit";

    /// <summary>
    /// Gets additional query parameters appended after the standard OAuth and PKCE parameters.
    /// Existing parameter names are overwritten.
    /// </summary>
    public IDictionary<string, string?> AdditionalParameters { get; } = new Dictionary<string, string?>();
}
