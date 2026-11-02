import javax.xml.xpath.XPath;
public class SafeXpath {
  void f(XPath xp) throws Exception {
    xp.evaluate("//users/user", null);
  }
}
