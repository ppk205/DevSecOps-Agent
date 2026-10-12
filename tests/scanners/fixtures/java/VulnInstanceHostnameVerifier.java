import javax.net.ssl.HttpsURLConnection;

public class VulnInstanceHostnameVerifier {
  void f(HttpsURLConnection connection) {
    connection.setHostnameVerifier((hostname, session) -> true);
  }
}
