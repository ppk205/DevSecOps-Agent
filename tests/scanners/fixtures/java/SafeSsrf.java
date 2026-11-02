import java.net.URL;
public class SafeSsrf {
  void f() throws Exception {
    new URL("https://example.com/static").openConnection();
  }
}
