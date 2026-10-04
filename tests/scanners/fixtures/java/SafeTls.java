import java.security.SecureRandom;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;

public class SafeTls {
  void f() throws Exception {
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, null, new SecureRandom());
    HttpsURLConnection.setDefaultHostnameVerifier(HttpsURLConnection.getDefaultHostnameVerifier());
  }
}
