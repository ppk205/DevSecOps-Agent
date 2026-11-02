import java.nio.file.Paths;
public class VulnNio {
  void f(String n) {
    Paths.get("/data/" + n);
  }
}
