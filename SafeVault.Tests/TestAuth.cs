using NUnit.Framework;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Linq;
using System.Threading.Tasks;
using System;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuth
{
    private record Reg(string Username, string Email, string Password, string? Role);
    private record Login(string Username, string Password);

    private static StringContent JsonBody(object o) =>
        new(JsonSerializer.Serialize(o), Encoding.UTF8, "application/json");

    private static string Unique(string prefix) =>
        $"{prefix}_{Guid.NewGuid():N}".Substring(0, 15);

    [Test]
    public async Task Unauthorized_User_Cannot_Access_Admin()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var resp = await client.GetAsync("/admin/dashboard");
        Assert.AreEqual(401, (int)resp.StatusCode);
    }

    [Test]
    public async Task User_Role_Gets_403_On_Admin()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var u = Unique("user");
        var reg = await client.PostAsync("/auth/register",
            JsonBody(new Reg(u, $"{u}@e.com", "Password123!", "User")));
        Assert.IsTrue(reg.IsSuccessStatusCode, "Registro User debe ser OK.");

        var login = await client.PostAsync("/auth/login", JsonBody(new Login(u, "Password123!")));
        Assert.IsTrue(login.IsSuccessStatusCode, "Login User debe ser OK.");

        var cookie = login.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.FirstOrDefault(v => v.StartsWith("safevault.auth="))
            : null;
        Assert.IsNotNull(cookie, "Debe devolver cookie de autenticación.");
        var bare = cookie!.Split(';')[0];

        var req = new HttpRequestMessage(HttpMethod.Get, "/admin/dashboard");
        req.Headers.Add("Cookie", bare);
        var adminResp = await client.SendAsync(req);

        Assert.AreEqual(403, (int)adminResp.StatusCode, "User no debe acceder a Admin (403).");
    }

    [Test]
    public async Task Admin_Role_Can_Access_Admin()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var u = Unique("admin");
        var reg = await client.PostAsync("/auth/register",
            JsonBody(new Reg(u, $"{u}@e.com", "Password123!", "Admin")));
        Assert.IsTrue(reg.IsSuccessStatusCode, "Registro Admin debe ser OK.");

        var login = await client.PostAsync("/auth/login", JsonBody(new Login(u, "Password123!")));
        Assert.IsTrue(login.IsSuccessStatusCode, "Login Admin debe ser OK.");

        var cookie = login.Headers.TryGetValues("Set-Cookie", out var values)
            ? values.FirstOrDefault(v => v.StartsWith("safevault.auth="))
            : null;
        Assert.IsNotNull(cookie, "Debe devolver cookie de autenticación.");
        var bare = cookie!.Split(';')[0];

        var req = new HttpRequestMessage(HttpMethod.Get, "/admin/dashboard");
        req.Headers.Add("Cookie", bare);
        var adminResp = await client.SendAsync(req);

        Assert.AreEqual(200, (int)adminResp.StatusCode, "Admin debe acceder (200).");
    }

    [Test]
    public async Task Invalid_Login_Returns_401()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var u = Unique("bob");
        var reg = await client.PostAsync("/auth/register",
            JsonBody(new Reg(u, $"{u}@e.com", "Password123!", "User")));
        Assert.IsTrue(reg.IsSuccessStatusCode);

        var bad = await client.PostAsync("/auth/login", JsonBody(new Login(u, "WrongPass")));
        Assert.AreEqual(401, (int)bad.StatusCode, "Login inválido debe ser 401.");
    }
}
