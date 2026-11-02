import javax.xml.parsers.SAXParserFactory;
import org.xml.sax.InputSource;
public class VulnSax {
  void f(InputSource s) throws Exception {
    SAXParserFactory.newInstance().newSAXParser().parse(s.getByteStream());
  }
}
