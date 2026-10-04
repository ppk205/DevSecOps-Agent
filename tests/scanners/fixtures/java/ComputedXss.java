import javax.servlet.http.*;
public class ComputedXss {
  void f(HttpServletRequest q, HttpServletResponse r) throws Exception {
    r.getWriter().write(gson.toJson(q.getParameter("name")));
  }
}
