using NUnit.Framework;
using Microsoft.AspNetCore.Mvc.Testing;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System; // <-- necesario para Guid

namespace SafeVault.Tests;

[TestFixture]
public class TestSecurityHardening
{
    private static StringContent JsonBody(object o) =>
        new(JsonSerializer.Serialize(o), Encoding.UTF8, "application/json");

    [Test]
    public async Task Api_Blocks_SQLi_On_GetUser_ByUsername()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var resp = await client.GetAsync("/users/%27%20OR%201%3D1%20--"); // "' OR 1=1 --"
        Assert.That((int)resp.StatusCode, Is.EqualTo(404), "No debe filtrar ni devolver datos con payload SQLi.");
    }

    [Test]
    public async Task Submit_Blocks_XSS_Payload()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var xss = new { username = "<img src=x onerror=alert(1)>", email = "safe@example.com" };
        var resp = await client.PostAsync("/submit", JsonBody(xss));
        Assert.That((int)resp.StatusCode, Is.EqualTo(400), "XSS debe ser rechazado por validación servidor.");
        var body = await resp.Content.ReadAsStringAsync();
        StringAssert.Contains("No se permiten", body);
    }

    [Test]
    public async Task Register_Blocks_XSS_In_Username()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var payload = new { Username = "<script>alert(1)</script>", Email = "x@x.com", Password = "Password123!", Role = "User" };
        var resp = await client.PostAsync("/auth/register", JsonBody(payload));
        Assert.That((int)resp.StatusCode, Is.EqualTo(400), "Registro con XSS debe fallar.");
        var body = await resp.Content.ReadAsStringAsync();
        StringAssert.Contains("No se permiten", body);
    }

    [Test]
    public async Task StaticFiles_Send_Security_Headers()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        var resp = await client.GetAsync("/webform.html");
        Assert.That(resp.Headers.Contains("X-Content-Type-Options"), Is.True);
        Assert.That(resp.Headers.Contains("Referrer-Policy"), Is.True);
        Assert.That(resp.Headers.Contains("X-Frame-Options"), Is.True);
    }

    [Test]
    public async Task Submit_Response_Is_Structural_Json_Not_Message_String()
    {
        await using var app = new WebApplicationFactory<Program>();
        using var client = app.CreateClient();

        // 🔑 Username único para no gatillar UNIQUE en runs consecutivos
        var u = $"hardening_{Guid.NewGuid():N}".Substring(0, 20);

        var ok = await client.PostAsync("/submit", JsonBody(new { username = u, email = "h@test.com" }));
        Assert.That((int)ok.StatusCode, Is.EqualTo(200));

        var text = await ok.Content.ReadAsStringAsync();
        StringAssert.Contains("\"saved\":", text);
        StringAssert.Contains($"\"username\":\"{u}\"", text);
        StringAssert.DoesNotContain("Saved user", text);
    }
}
