public class UnrelatedInit {
  void init(Object key, Object managers, Object random) {}
  boolean verify(String name, Object session) { return true; }
  void checkServerTrusted(Object chain, String authType) {}
  void f() { init(null, null, null); }
}
