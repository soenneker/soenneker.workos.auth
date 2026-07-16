using System;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Soenneker.WorkOs.Auth.Abstract;
using Soenneker.WorkOs.Auth.Options;
using Soenneker.WorkOs.OpenApiClientUtil.Registrars;

namespace Soenneker.WorkOs.Auth.Registrars;

/// <summary>
/// A utility for managing authentication/authorization in WorkOS
/// </summary>
public static class WorkOsAuthUtilRegistrar
{
    /// <summary>
    /// Adds <see cref="IWorkOsAuthUtil"/> as a singleton service. <para/>
    /// </summary>
    public static IServiceCollection AddWorkOsAuthUtilAsSingleton(this IServiceCollection services,
        Action<WorkOsAuthOptions>? configure = null)
    {
        AddOptions(services, configure);
        services.AddWorkOsOpenApiClientUtilAsSingleton()
                .TryAddSingleton<IWorkOsAuthUtil, WorkOsAuthUtil>();

        return services;
    }

    /// <summary>
    /// Adds <see cref="IWorkOsAuthUtil"/> as a scoped service. <para/>
    /// </summary>
    public static IServiceCollection AddWorkOsAuthUtilAsScoped(this IServiceCollection services,
        Action<WorkOsAuthOptions>? configure = null)
    {
        AddOptions(services, configure);
        services.AddWorkOsOpenApiClientUtilAsScoped()
                .TryAddScoped<IWorkOsAuthUtil, WorkOsAuthUtil>();

        return services;
    }

    private static void AddOptions(IServiceCollection services, Action<WorkOsAuthOptions>? configure)
    {
        services.AddOptions<WorkOsAuthOptions>();

        if (configure is not null)
            services.Configure(configure);
    }
}
