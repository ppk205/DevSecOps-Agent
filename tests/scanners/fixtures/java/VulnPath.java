import java.io.File;
public class VulnPath {
  void f(String n) { new File("/data/" + n); }
}
