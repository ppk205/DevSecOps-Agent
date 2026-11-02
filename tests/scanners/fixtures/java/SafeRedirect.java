import javax.servlet.http.HttpServletResponse;
public class SafeRedirect {
  void f(HttpServletResponse r) throws Exception {
    r.sendRedirect("/home");
  }
}
