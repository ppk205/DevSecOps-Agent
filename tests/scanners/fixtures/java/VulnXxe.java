import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
public class VulnXxe {
  void f(InputSource s) throws Exception {
    DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(s.getByteStream());
  }
}
