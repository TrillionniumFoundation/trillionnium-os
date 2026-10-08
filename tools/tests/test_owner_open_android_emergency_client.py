"""Run actual Java client mechanics without a phone, broker or model."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
JAVA = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/client/src/org/trillionnium/owneropen"
ADDRESS = '''package android.net; public final class LocalSocketAddress {
 public enum Namespace { ABSTRACT } public LocalSocketAddress(String n,Namespace s){} }'''
SOCKET = r'''
package android.net;
import java.io.*; import java.nio.charset.StandardCharsets; import java.util.concurrent.*;
public final class LocalSocket implements AutoCloseable {
 public static final LinkedBlockingQueue<Endpoint> queue=new LinkedBlockingQueue<>();
 private final Endpoint endpoint; private boolean created;
 public LocalSocket(){endpoint=queue.remove();}
 public void setSoTimeout(int millis)throws IOException{if(!created)throw new IOException("socket not created");}
 public void connect(LocalSocketAddress address)throws IOException {
  created=true;
  if(endpoint.blockConnect) { endpoint.entered.countDown();
   try{if(!endpoint.closed.await(10,TimeUnit.SECONDS))throw new IOException("deadline did not close connect");}
   catch(InterruptedException e){throw new IOException(e);}throw new IOException("closed connect"); }
 }
 public InputStream getInputStream(){created=true;return endpoint.input;}
 public OutputStream getOutputStream(){created=true;return endpoint.output;}
 public void shutdownInput()throws IOException{endpoint.shutdownInput=true;endpoint.release.countDown();endpoint.closed.countDown();}
 public void shutdownOutput()throws IOException{endpoint.shutdownOutput=true;endpoint.closed.countDown();}
 public void close()throws IOException{endpoint.closed.countDown();}
 public static final class Endpoint {
  public final ByteArrayOutputStream output=new ByteArrayOutputStream();
  public final CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1),closed=new CountDownLatch(1);
  public boolean shutdownInput,shutdownOutput; public final boolean blockConnect; public final InputStream input;
  public Endpoint(String response,boolean blockRead,boolean blockConnect) {
   this.blockConnect=blockConnect; byte[] raw=response.getBytes(StandardCharsets.UTF_8);
   input=new InputStream(){int offset;
    public int read()throws IOException {
     if(blockRead){entered.countDown();try{release.await();}catch(InterruptedException e){throw new IOException(e);}}
     if(closed.getCount()==0)throw new IOException("closed stream");
     return offset==raw.length?-1:raw[offset++];
    }};
  }
  public String written(){return output.toString(StandardCharsets.UTF_8);}
 }
}
'''
HARNESS = r'''
import android.net.LocalSocket;
import java.io.IOException;
import java.util.concurrent.*;
import org.trillionnium.owneropen.*;
public class EmergencyClientHarness {
 static void require(boolean value,String why){if(!value)throw new AssertionError(why);}
 static final String REPLY="{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"kind\":\"emergency.result\",\"process_quiescence\":\"unknown\"}\n";
 static OwnerOpenClient client(){return new OwnerOpenClient(new OwnerOpenClient.Listener(){public void onFrame(String s){}public void onDisconnected(String s){}});}
 public static void main(String[] arguments)throws Exception {
  OwnerOpenClient client=client();
  try {
   if(arguments[0].equals("priority-fence")) {
    LocalSocket.Endpoint ordinary=new LocalSocket.Endpoint("{\"kind\":\"broker.hello.ack\"}\n",true,false);
    LocalSocket.Endpoint stop=new LocalSocket.Endpoint(REPLY,false,false);
    LocalSocket.Endpoint status=new LocalSocket.Endpoint(REPLY,false,false);
    LocalSocket.queue.add(ordinary);LocalSocket.queue.add(stop);LocalSocket.queue.add(status);
    ExecutorService thread=Executors.newSingleThreadExecutor();
    Future<?> connecting=thread.submit(()->{try{client.connect();throw new AssertionError("inhibited connect succeeded");}catch(IOException expected){}});
    require(ordinary.entered.await(2,TimeUnit.SECONDS),"ordinary hello not blocked");
    require(ordinary.written().contains("\"kind\":\"ingress.connect\""),"ordinary first frame missing");
    long start=System.nanoTime();client.emergencyControl("stop-host-fixture",true);
    require(System.nanoTime()-start<1_000_000_000L,"emergency queued behind ordinary lock");
    require(stop.written().contains("\"kind\":\"emergency.stop\"")&&stop.written().contains("\"explicit_user\":true"),"stop not explicit control");
    ordinary.release.countDown();connecting.get(2,TimeUnit.SECONDS);thread.shutdownNow();
    try{client.startTurn("s","t","u","effect");throw new AssertionError("dispatch admitted");}catch(IOException expected){}
    try{client.connect();throw new AssertionError("reconnect admitted");}catch(IOException expected){}
    client.emergencyControl("stop-host-fixture",false);
    require(status.written().contains("\"kind\":\"emergency.status\"")&&!status.written().contains("emergency.stop"),"status replays stop");
    require(!ordinary.written().contains("turn.start"),"normal semantic effect leaked");
   } else if(arguments[0].equals("whole-request-deadline")) {
    LocalSocket.Endpoint blocked=new LocalSocket.Endpoint(REPLY,false,true);LocalSocket.queue.add(blocked);
    long start=System.nanoTime();
    try{client.emergencyControl("stop-host-fixture",true);throw new AssertionError("blocked connect succeeded");}catch(IOException expected){}
    long elapsed=System.nanoTime()-start;
    require(elapsed>=4_500_000_000L&&elapsed<7_000_000_000L,"whole-request deadline missing");
    require(blocked.closed.getCount()==0&&blocked.shutdownInput&&blocked.shutdownOutput&&LocalSocket.queue.isEmpty(),"deadline retried connection");
    try{client.connect();throw new AssertionError("failure cleared inhibit");}catch(IOException expected){}
   } else if(arguments[0].equals("oversized-reply-no-retry")) {
    LocalSocket.Endpoint oversized=new LocalSocket.Endpoint("x".repeat(4096)+"\n",false,false);LocalSocket.queue.add(oversized);
    try{client.emergencyControl("stop-host-fixture",true);throw new AssertionError("oversized reply accepted");}catch(IOException expected){}
    require(LocalSocket.queue.isEmpty()&&oversized.closed.getCount()==0,"oversized reply caused retry/leak");
    require(oversized.written().lines().count()==1,"emergency sent more than once");
    try{client.startTurn("s","t","u","effect");throw new AssertionError("unknown reply cleared inhibit");}catch(IOException expected){}
   } else throw new AssertionError("unknown scenario");
  } finally {client.shutdown();}
 }
}
'''


class OwnerOpenAndroidEmergencyClientTest(unittest.TestCase):
    def test_actual_client_priority_deadline_and_unknown_outcome(self):
        javac, java = shutil.which("javac"), shutil.which("java")
        self.assertTrue(javac and java, "JDK required for actual emergency client behavior")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "android/net").mkdir(parents=True)
            (folder / "android/net/LocalSocket.java").write_text(SOCKET)
            (folder / "android/net/LocalSocketAddress.java").write_text(ADDRESS)
            (folder / "EmergencyClientHarness.java").write_text(HARNESS)
            result = subprocess.run([javac, "-d", str(folder / "classes"),
                str(JAVA / "OwnerOpenClient.java"), str(JAVA / "OwnerOpenFrame.java"),
                *map(str, folder.rglob("*.java"))], capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            for scenario in ("priority-fence", "whole-request-deadline", "oversized-reply-no-retry"):
                with self.subTest(scenario=scenario):
                    result = subprocess.run([java, "-cp", str(folder / "classes"),
                        "EmergencyClientHarness", scenario], capture_output=True, text=True, timeout=12)
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
