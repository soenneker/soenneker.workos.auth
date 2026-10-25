using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Kiota.Abstractions;
using Soenneker.Tests.HostedUnit;
using Soenneker.WorkOs.Auth.Abstract;
using Soenneker.WorkOs.Auth.Models;
using Soenneker.WorkOs.OpenApiClient;
using Soenneker.WorkOs.OpenApiClient.Models;
using Soenneker.WorkOs.OpenApiClientUtil.Abstract;

namespace Soenneker.WorkOs.Auth.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
[NotInParallel]
public sealed class WorkOsTokenExchangeTests(Host host) : HostedUnitTest(host)
{
    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(true, true)]
    public async Task Token_exchange_sends_flat_request_and_reads_tokens(bool refresh, bool scoped, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(15));
        CancellationToken token = timeout.Token;
        using var portReservation = new TcpListener(IPAddress.Loopback, 0);
        portReservation.Start();
        int port = ((IPEndPoint)portReservation.LocalEndpoint).Port;
        portReservation.Stop();
        using var listener = new HttpListener();
        listener.Prefixes.Add($"http://127.0.0.1:{port}/");
        listener.Start();

        IWorkOsAuthUtil auth = Resolve<IWorkOsAuthUtil>(true);
        WorkOsOpenApiClient client = await Resolve<IWorkOsOpenApiClientUtil>(true).Get(token);
        // The generated client exposes no endpoint setter. Redirect only its URL template
        // parameter so the real DI services, request adapter, and serializers remain in use.
        var parameters = (Dictionary<string, object>)typeof(BaseRequestBuilder)
            .GetProperty("PathParameters", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        var adapter = (IRequestAdapter)typeof(BaseRequestBuilder)
            .GetProperty("RequestAdapter", BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(client)!;
        object originalBaseUrl = parameters["baseurl"];
        string originalAdapterBaseUrl = adapter.BaseUrl;
        parameters["baseurl"] = $"http://127.0.0.1:{port}";
        adapter.BaseUrl = $"http://127.0.0.1:{port}";
        try
        {
            var context = new WorkOsRequestContext { IpAddress = "127.0.0.1", UserAgent = "token-exchange-test" };
            string verifier = new('a', 43);
            Task<UserlandAuthenticateResponse> exchange = (refresh
                ? auth.AuthenticateRefreshToken("refresh_test", scoped ? "org_test" : null, context, token)
                : auth.AuthenticateAuthorizationCode("code_test", verifier, context, token)).AsTask();
            Task<HttpListenerContext> incoming = listener.GetContextAsync().WaitAsync(token);
            if (await Task.WhenAny(incoming, exchange) == exchange)
                await exchange;
            HttpListenerContext received = await incoming;
            string method = received.Request.HttpMethod;
            string path = received.Request.Url!.AbsolutePath;
            using var reader = new StreamReader(received.Request.InputStream);
            string body = await reader.ReadToEndAsync(token);
            byte[] response = Encoding.UTF8.GetBytes("""{"access_token":"access_test","refresh_token":"rotated_test"}""");
            received.Response.ContentType = "application/json";
            received.Response.ContentLength64 = response.Length;
            await received.Response.OutputStream.WriteAsync(response, token);
            received.Response.Close();
            UserlandAuthenticateResponse result = await exchange.WaitAsync(token);

            await Assert.That(method).IsEqualTo("POST");
            await Assert.That(path).IsEqualTo("/user_management/authenticate");
            using JsonDocument json = JsonDocument.Parse(body);
            JsonElement root = json.RootElement;
            await Assert.That(root.GetProperty("client_id").GetString()).IsEqualTo("client_test");
            await Assert.That(root.GetProperty("client_secret").GetString()).IsEqualTo("secret_test");
            await Assert.That(root.GetProperty("grant_type").GetString()).IsEqualTo(refresh ? "refresh_token" : "authorization_code");
            await Assert.That(root.GetProperty("ip_address").GetString()).IsEqualTo("127.0.0.1");
            await Assert.That(root.GetProperty("user_agent").GetString()).IsEqualTo("token-exchange-test");
            if (refresh)
            {
                await Assert.That(root.GetProperty("refresh_token").GetString()).IsEqualTo("refresh_test");
                await Assert.That(root.TryGetProperty("code", out _)).IsFalse();
                if (scoped)
                    await Assert.That(root.GetProperty("organization_id").GetString()).IsEqualTo("org_test");
                else
                    await Assert.That(root.TryGetProperty("organization_id", out _)).IsFalse();
            }
            else
            {
                await Assert.That(root.GetProperty("code").GetString()).IsEqualTo("code_test");
                await Assert.That(root.GetProperty("code_verifier").GetString()).IsEqualTo(verifier);
                await Assert.That(root.TryGetProperty("refresh_token", out _)).IsFalse();
            }
            await Assert.That(result.AccessToken).IsEqualTo("access_test");
            await Assert.That(result.RefreshToken).IsEqualTo("rotated_test");
        }
        finally
        {
            parameters["baseurl"] = originalBaseUrl;
            adapter.BaseUrl = originalAdapterBaseUrl;
        }
    }
}
