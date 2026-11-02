import javax.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
public class VulnLog {
  void f(HttpServletRequest q, Logger log) {
    log.info("user=" + q.getParameter("u"));
  }
}
