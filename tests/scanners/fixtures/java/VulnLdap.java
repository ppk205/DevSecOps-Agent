import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
public class VulnLdap {
  void f(HttpServletRequest q, DirContext ctx) throws Exception {
    ctx.search("ou=users", "(uid=" + q.getParameter("u") + ")", new SearchControls());
  }
}
