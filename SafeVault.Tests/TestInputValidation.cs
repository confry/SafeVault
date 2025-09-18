using NUnit.Framework;
using Microsoft.Data.Sqlite;
using System.Threading.Tasks;

// Usa los namespaces del proyecto web
using Security;
using Data;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void TestForXSS_IsRejected()
    {
        var payload = new UserInput("<script>alert(1)</script>", "x@x.com");
        var (ok, errors, _) = InputValidator.Validate(payload);

        Assert.IsFalse(ok, "La validación debe fallar con <script>.");
        StringAssert.Contains("No se permiten etiquetas HTML", string.Join(", ", errors));
    }

    [Test]
    public void TestForXSS_ValidInputPasses()
    {
        var payload = new UserInput("alice.smith", "alice@example.com");
        var (ok, errors, clean) = InputValidator.Validate(payload);

        Assert.IsTrue(ok, "Entrada válida debe pasar.");
        Assert.IsEmpty(errors);
        Assert.AreEqual("alice.smith", clean.Username);
        Assert.AreEqual("alice@example.com", clean.Email);
    }

    [Test]
    public async Task TestForSQLInjection_ParamsBlockAttack()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();

        var repo = new UserRepository(conn);
        await repo.CreateSchemaAsync();
        await repo.InsertAsync("alice", "alice@example.com");

        var attack = "' OR 1=1 --";
        var victim = await repo.GetByUsernameAsync(attack);

        Assert.IsNull(victim, "La consulta parametrizada no debe devolver resultados para el payload de SQLi.");
    }

    [Test]
    public async Task TestForSQLInjection_ExactMatchOnly()
    {
        using var conn = new SqliteConnection("Data Source=:memory:");
        await conn.OpenAsync();

        var repo = new UserRepository(conn);
        await repo.CreateSchemaAsync();
        await repo.InsertAsync("bob", "bob@example.com");

        var found = await repo.GetByUsernameAsync("bob");
        Assert.IsNotNull(found);
        Assert.AreEqual("bob", found?.Username);

        var notFound = await repo.GetByUsernameAsync("bob --");
        Assert.IsNull(notFound, "Cadenas maliciosas similares no deben hacer match si hay parámetros.");
    }
}
