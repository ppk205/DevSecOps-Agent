import javax.servlet.http.HttpServletRequest;
public class VulnReflect {
  void f(HttpServletRequest q) throws Exception {
    Class.forName(q.getParameter("cls"));
  }
}
