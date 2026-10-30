using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Primitives;
using WinRemote.Http;

var passed = 0;
const string local = "10.246.73.20";
const string client = "10.246.73.21";
const string authority = local + ":8443";
const string sameOrigin = "https://" + authority;
var endpoint = new HttpTransportShape.ExpectedEndpoint(local, client, 8443);

DefaultHttpContext Build(string path = "/api/input", string method = "POST")
{
    var ctx = new DefaultHttpContext();
    ctx.Request.Scheme = "https";
    ctx.Request.Method = method;
    ctx.Request.Host = new HostString(local, 8443);
    ctx.Request.Headers["Origin"] = sameOrigin;
    ctx.Request.Path = path;
    ctx.Connection.LocalIpAddress = IPAddress.Parse(local);
    ctx.Connection.RemoteIpAddress = IPAddress.Parse(client);
    ctx.Connection.LocalPort = 8443;
    ctx.Features.Get<IHttpRequestFeature>()!.RawTarget = path;
    return ctx;
}

void Check(string name, bool expected, Action<DefaultHttpContext>? mutate = null,
    HttpTransportShape.ExpectedEndpoint? useEndpoint = null, string path = "/api/input",
    string method = "POST")
{
    var ctx = Build(path, method);
    mutate?.Invoke(ctx);
    var observed = HttpTransportShape.Examine(ctx, useEndpoint ?? endpoint);
    if (observed.Observed != expected)
        throw new Exception("HTTP transport " + name + ": " + observed.Reason);
    Console.WriteLine("PASS HTTP transport " + name + ": " + observed.Reason);
    passed++;
}

Check("exact HTTPS private socket and same-origin API", true);
Check("exact WSS route transport, not authorization", true, path: "/ws/terminal", method: "GET");
Check("screen WS route transport, not authorization", true, path: "/ws/screen", method: "GET");
Check("files API route transport", true, path: "/api/files", method: "POST");
Check("insecure HTTP denied", false, c => c.Request.Scheme = "http");
Check("non-matching physical local IP denied", false,
    c => c.Connection.LocalIpAddress = IPAddress.Parse(client));
Check("missing physical local IP denied", false, c => c.Connection.LocalIpAddress = null);
Check("wrong local port denied", false, c => c.Connection.LocalPort = 8080);
Check("wrong remote IPv4 denied", false,
    c => c.Connection.RemoteIpAddress = IPAddress.Parse("10.246.73.22"));
Check("missing remote IP denied", false, c => c.Connection.RemoteIpAddress = null);
Check("IPv6 peer denied", false,
    c => c.Connection.RemoteIpAddress = IPAddress.IPv6Loopback);
Check("mismatched Host denied", false, c => c.Request.Headers.Host = "attacker.invalid");
Check("missing Host denied", false, c => c.Request.Headers.Remove("Host"));
Check("multiple Host headers denied", false,
    c => c.Request.Headers.Host = new StringValues(new[] { authority, "attacker.invalid" }));
Check("cross-site Origin denied", false,
    c => c.Request.Headers["Origin"] = "https://attacker.invalid");
Check("null Origin denied", false, c => c.Request.Headers["Origin"] = "null");
Check("missing Origin denied", false, c => c.Request.Headers.Remove("Origin"));
Check("multiple Origin headers denied", false,
    c => c.Request.Headers["Origin"] = new StringValues(new[] { sameOrigin, "https://attacker.invalid" }));
Check("Forwarded denied", false, c => c.Request.Headers["Forwarded"] = "for=10.246.73.21");
Check("X-Forwarded-For denied", false, c => c.Request.Headers["X-Forwarded-For"] = client);
Check("X-Forwarded-Proto denied", false, c => c.Request.Headers["X-Forwarded-Proto"] = "https");
Check("X-Original-Host denied", false, c => c.Request.Headers["X-Original-Host"] = authority);
Check("X-Real-IP denied", false, c => c.Request.Headers["X-Real-IP"] = client);
Check("query containing token denied", false, c => c.Request.QueryString = new QueryString("?ticket=secret"));
Check("non-empty PathBase denied", false, c => c.Request.PathBase = "/proxy");
Check("raw target missing denied", false,
    c => c.Features.Get<IHttpRequestFeature>()!.RawTarget = "");
Check("raw path normalization rejected", false,
    c => c.Features.Get<IHttpRequestFeature>()!.RawTarget = "/api/../api/input");
Check("raw path percent encoding rejected", false,
    c => c.Features.Get<IHttpRequestFeature>()!.RawTarget = "/api/%69nput");
Check("non-allowlisted route denied", false, path: "/api/admin");
Check("API over GET denied", false, method: "GET");
Check("WS over POST denied", false, path: "/ws/terminal", method: "POST");
Check("invalid localhost listener expectation denied", false,
    useEndpoint: new HttpTransportShape.ExpectedEndpoint("127.0.0.1", client, 8443));
Check("wildcard local listener expectation denied", false,
    useEndpoint: new HttpTransportShape.ExpectedEndpoint("0.0.0.0", client, 8443));
Check("public client expectation denied", false,
    useEndpoint: new HttpTransportShape.ExpectedEndpoint(local, "8.8.8.8", 8443));
Check("duplicate local/client address denied", false,
    useEndpoint: new HttpTransportShape.ExpectedEndpoint(local, local, 8443));
Check("port 443 not permitted by MVP policy", false,
    useEndpoint: new HttpTransportShape.ExpectedEndpoint(local, client, 443));
if (HttpTransportShape.Examine(null, endpoint).Observed ||
    HttpTransportShape.Examine(Build(), null).Observed)
    throw new Exception("Null context/endpoint must be denied");
passed++;
Console.WriteLine("PASS HTTP transport null context and endpoint denied");
Console.WriteLine("HttpTransportShape: " + passed + " checks passed (in-memory only, no listener).");
