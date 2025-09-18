using Microsoft.Data.Sqlite;
using System.Threading.Tasks;

namespace Data;

public class UserRepository
{
    private readonly SqliteConnection _conn;
    public UserRepository(SqliteConnection conn) => _conn = conn;

    // Para tests de Act.1
    public async Task CreateSchemaAsync()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID       INTEGER PRIMARY KEY AUTOINCREMENT,
                Username     TEXT    NOT NULL UNIQUE,
                Email        TEXT    NOT NULL,
                PasswordHash TEXT    NOT NULL,
                Role         TEXT    NOT NULL DEFAULT 'User'
            );
            """;
        await cmd.ExecuteNonQueryAsync();
    }

    // Para tests de Act.1 (inserta usuario dummy)
    public async Task InsertAsync(string username, string email)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($u, $e, $ph, $r);
            """;
        cmd.Parameters.AddWithValue("$u", username);
        cmd.Parameters.AddWithValue("$e", email);
        cmd.Parameters.AddWithValue("$ph", BCrypt.Net.BCrypt.HashPassword("placeholder"));
        cmd.Parameters.AddWithValue("$r", "User");
        await cmd.ExecuteNonQueryAsync();
    }

    // Usado por login/tests
    public async Task<(long UserID, string Username, string Email, string PasswordHash, string Role)?>
        GetByUsernameAsync(string username)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "SELECT UserID, Username, Email, PasswordHash, Role FROM Users WHERE Username = $u;";
        cmd.Parameters.AddWithValue("$u", username);

        using var r = await cmd.ExecuteReaderAsync();
        if (!await r.ReadAsync()) return null;

        return (r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4));
    }

    // Usado por /auth/register
    public async Task CreateUserAsync(string username, string email, string passwordHash, string role)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO Users (Username, Email, PasswordHash, Role)
            VALUES ($u, $e, $ph, $r);
            """;
        cmd.Parameters.AddWithValue("$u", username);
        cmd.Parameters.AddWithValue("$e", email);
        cmd.Parameters.AddWithValue("$ph", passwordHash);
        cmd.Parameters.AddWithValue("$r", role);
        await cmd.ExecuteNonQueryAsync();
    }
}
