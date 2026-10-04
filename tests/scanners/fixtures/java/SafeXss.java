import javax.servlet.http.*;
public class SafeXss {
  String esc(String s) { return s.replace("<", "&lt;"); }
}
