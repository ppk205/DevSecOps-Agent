import javax.servlet.http.HttpServletRequest;
import javax.xml.xpath.XPath;
public class VulnXpath {
  void f(HttpServletRequest q, XPath xp) throws Exception {
    xp.evaluate("//user[name='" + q.getParameter("n") + "']", null);
  }
}
