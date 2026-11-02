public class SafeProc {
  void f() throws Exception {
    new ProcessBuilder("ls", "-l").start();
  }
}
