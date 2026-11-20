using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml;

public class SafeController
{
    public async Task Index(DB db, Conn conn, HttpClient client)
    {
        var sqlName = Request.Query["name"];
        var nick = Request.Query["nick"];
        var cmd = new SqlCommand("SELECT * FROM Users WHERE name = @name", conn);
        cmd.Parameters.AddWithValue("@name", "static");

        Process.Start("notepad.exe");

        var text = File.ReadAllText(Path.Combine("/var/www", "index.html"));

        var body = await client.GetStringAsync("https://status.internal/health");

        return Redirect("/home");

        searcher.Filter = "(uid=*)";

        doc.SelectNodes("//users");

        doc.LoadXml("<root/>");

        var sha = SHA256.Create();

        var staticJson = "{\"a\":1}";
        var user = JsonSerializer.Deserialize<User>(staticJson);

        var code = RandomNumberGenerator.GetInt32(1000000);

        Response.Headers.Add("X-Frame-Options", "DENY");

        var value = await CSharpScript.EvaluateAsync<int>("1+2");


        Response.Write(HttpUtility.HtmlEncode(nick));
    }
}
