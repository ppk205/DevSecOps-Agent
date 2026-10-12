import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class VulnHostnameVerifier {
  void f() {
    HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) { return true; }
    });
  }
}
