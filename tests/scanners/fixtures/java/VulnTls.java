import javax.net.ssl.HttpsURLConnection;
public class VulnTls {
  void f() { HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true); }
}
