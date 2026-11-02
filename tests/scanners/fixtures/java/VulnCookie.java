import javax.servlet.http.Cookie;
public class VulnCookie {
  void f(String v) {
    Cookie c = new Cookie("session", v);
    c.setSecure(false);
  }
}
