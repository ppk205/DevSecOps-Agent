import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.servlet.http.HttpServletRequest;
import org.springframework.ldap.filter.EqualsFilter;
public class SanitizedLdap {
  void f(HttpServletRequest q, DirContext ctx) throws Exception {
    EqualsFilter filter = new EqualsFilter("uid", q.getParameter("u"));
    ctx.search("ou=users", filter.encode(), new SearchControls());
  }
}
