import javax.servlet.http.HttpServletResponse;
public class VulnCors {
  void f(HttpServletResponse r) { r.addHeader("Access-Control-Allow-Origin", "*"); }
}
