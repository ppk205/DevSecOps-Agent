import java.io.ObjectInputStream;
public class VulnDeserialize {
  void f(ObjectInputStream in) throws Exception { in.readObject(); }
}
