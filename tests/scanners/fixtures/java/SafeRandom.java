import java.security.SecureRandom;
public class SafeRandom {
  int f() { return new SecureRandom().nextInt(); }
}
