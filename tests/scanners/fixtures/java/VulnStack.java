public class VulnStack {
  void f() {
    try {
      risky();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
  void risky() {}
}
