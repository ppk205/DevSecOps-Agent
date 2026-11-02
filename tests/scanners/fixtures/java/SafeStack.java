public class SafeStack {
  void f() {
    try {
      risky();
    } catch (Exception e) {
      throw new RuntimeException("failed");
    }
  }
  void risky() {}
}
