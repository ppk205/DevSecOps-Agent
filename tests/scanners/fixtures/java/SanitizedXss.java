import javax.servlet.http.*;
import org.apache.commons.text.StringEscapeUtils;
public class SanitizedXss {
  void f(HttpServletRequest q, HttpServletResponse r, StringEscapeUtils s) throws Exception {
    r.getWriter().write(s.escapeHtml4(q.getParameter("name")));
  }
}
