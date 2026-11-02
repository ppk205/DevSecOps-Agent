import javax.xml.parsers.SAXParserFactory;
public class SafeSax {
  void f() throws Exception {
    SAXParserFactory factory = SAXParserFactory.newInstance();
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    factory.newSAXParser();
  }
}
