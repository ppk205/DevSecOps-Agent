import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class SafeTrustManager {
  void f() throws Exception {
    TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    factory.init((KeyStore) null);
    X509TrustManager delegate = (X509TrustManager) factory.getTrustManagers()[0];
    TrustManager[] managers = new TrustManager[] { new X509TrustManager() {
      public X509Certificate[] getAcceptedIssuers() { return delegate.getAcceptedIssuers(); }
      public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
      }
      public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
      }
    }};
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(null, managers, null);
  }
}
