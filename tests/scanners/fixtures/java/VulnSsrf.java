import java.net.URL;
import javax.servlet.http.HttpServletRequest;
public class VulnSsrf {
  void f(HttpServletRequest q) throws Exception {
    new URL(q.getParameter("url")).openConnection();
  }
}
