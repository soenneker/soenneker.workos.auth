[![](https://img.shields.io/nuget/v/soenneker.workos.auth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.workos.auth/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.workos.auth/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.workos.auth/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.workos.auth.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.workos.auth/)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.WorkOs.Auth
### Reusable WorkOS AuthKit authorization, PKCE, token exchange, session, and logout utilities

## Installation

```
dotnet add package Soenneker.WorkOs.Auth
```

## Registration

```csharp
using Soenneker.WorkOs.Auth.Registrars;

services.AddWorkOsAuthUtilAsScoped(options =>
{
    options.ClientId = configuration["WorkOs:ClientId"]!;
    options.ClientSecret = configuration["WorkOs:ClientSecret"];
});
```

The registrar also registers `Soenneker.WorkOs.OpenApiClientUtil`. Configure its existing `WorkOs:ApiKey` and HTTP-client settings normally.

## Start an authorization flow

```csharp
using Soenneker.WorkOs.Auth.Models;

WorkOsAuthorizationRedirect redirect = authUtil.CreateAuthorizationRedirect(new WorkOsAuthorizationRequest
{
    RedirectUri = "https://example.com/auth/workos/callback",
    LoginHint = "person@example.com"
});

// Persist redirect.State and redirect.CodeVerifier until the callback,
// then redirect the browser to redirect.Url.
```

## Exchange the callback code

```csharp
UserlandAuthenticateResponse session = await authUtil.AuthenticateAuthorizationCode(
    code,
    savedCodeVerifier,
    new WorkOsRequestContext(remoteIpAddress, userAgent),
    cancellationToken);
```

The utility also supports refresh-token exchanges, session revocation, browser logout URL generation, PKCE verification, and unvalidated access-token reading.
Applications remain responsible for state persistence, cookies, redirect allowlists, JWT validation, local user provisioning, and authorization policy.
