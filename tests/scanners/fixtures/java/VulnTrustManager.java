import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class VulnTrustManager {
  void f() throws Exception {
    TrustManager[] managers = new TrustManager[] { new X509TrustManager() {
      public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
      public void checkClientTrusted(X509Certificate[] chain, String authType) {}
      public void checkServerTrusted(X509Certificate[] chain, String authType) {}
    }};
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, managers, null);
  }
}
