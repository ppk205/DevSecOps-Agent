import javax.crypto.Cipher;
public class VulnCipher {
  void f() throws Exception { Cipher.getInstance("DES"); }
}
