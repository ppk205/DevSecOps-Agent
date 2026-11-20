using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

public class VulnController
{
    public async Task Index(DB db, Conn conn, HttpClient client)
    {
        var sqlName = Request.Query["name"];
        var cmd = new SqlCommand("SELECT * FROM Users WHERE name = '" + sqlName + "'", conn);

        var bin = Request.Query["bin"];
        Process.Start(bin);

        var nick = Request.Query["nick"];
        Response.Write("Hi " + nick);

        var docName = Request.Query["doc"];
        var text = File.ReadAllText(Path.Combine("/var/www", docName));

        var target = Request.Query["url"];
        var body = await client.GetStringAsync(target);

        var nextUrl = Request.Query["next"];
        return Redirect(nextUrl);

        var uid = Request.Query["uid"];
        searcher.Filter = "(uid=" + uid + ")";

        var xpName = Request.Query["xp"];
        doc.SelectNodes("//user[name='" + xpName + "']");

        var xmlIn = Request.Form["xml"];
        doc.LoadXml(xmlIn);

        var md5 = MD5.Create();

        var payload = Request.Form["payload"];
        var bf = new BinaryFormatter();
        var bytes = Convert.FromBase64String(payload);
        var stream = new MemoryStream(bytes);
        var obj = bf.Deserialize(stream);

        var r = new Random();
        var code = r.Next();

        var hv = Request.Query["v"];
        Response.Headers.Add("X-Next", hv);

        var expr = Request.Query["e"];
        var value = await CSharpScript.EvaluateAsync<int>(expr);
    }

    public IActionResult Greet([FromQuery] string who)
    {
        Response.Write("Hi " + who);
        return Ok();
    }
}
