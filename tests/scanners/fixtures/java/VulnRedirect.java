import javax.servlet.http.*;
public class VulnRedirect {
  void f(HttpServletRequest q, HttpServletResponse r) throws Exception {
    r.sendRedirect(q.getParameter("next"));
  }
}
