import javax.servlet.http.HttpServletRequest;
public class VulnProc {
  void f(HttpServletRequest q) throws Exception {
    new ProcessBuilder(q.getParameter("cmd")).start();
  }
}
