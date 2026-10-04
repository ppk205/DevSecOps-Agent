import javax.servlet.http.*;
public class VulnXss {
  void doGet(HttpServletRequest q, HttpServletResponse r) throws Exception {
    r.getWriter().write(q.getParameter("name"));
  }
}
