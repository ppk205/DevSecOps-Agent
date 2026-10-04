import javax.crypto.spec.SecretKeySpec;
public class VulnKey {
  void f() { new SecretKeySpec("key".getBytes(), "DES"); }
}
