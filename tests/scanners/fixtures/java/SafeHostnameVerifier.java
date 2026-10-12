import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

public class SafeHostnameVerifier {
  void f(HttpsURLConnection connection) {
    HostnameVerifier verifier = HttpsURLConnection.getDefaultHostnameVerifier();
    connection.setHostnameVerifier((hostname, session) -> verifier.verify(hostname, session));
    HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
      public boolean verify(String hostname, SSLSession session) {
        return verifier.verify(hostname, session);
      }
    });
  }
}
