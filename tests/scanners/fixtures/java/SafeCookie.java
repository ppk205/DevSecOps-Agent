import javax.servlet.http.Cookie;
public class SafeCookie {
  void f(String v) {
    Cookie c = new Cookie("session", v);
    c.setSecure(true);
    c.setHttpOnly(true);
  }
}
