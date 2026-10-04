import javax.servlet.http.*;
public class StaticJson {
  void f(HttpServletResponse res) throws Exception {
    res.getWriter().write("{\"error\": \"Too many requests\"}");
  }
}
