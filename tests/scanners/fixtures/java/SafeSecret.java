public class SafeSecret {
  void f() {
    String password = System.getenv("APP_PASSWORD");
  }
}
