import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
public class SafeLdap {
  void f(DirContext ctx) throws Exception {
    ctx.search("ou=users", "(uid=static)", new SearchControls());
  }
}
