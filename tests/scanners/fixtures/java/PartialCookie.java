import javax.servlet.http.Cookie;
public class PartialCookie {
  void f(String v) {
    Cookie c = new Cookie("session", v);
    c.setSecure(true);
  }
}
