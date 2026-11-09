"""Execute the production native control with real host files and sockets.

The property service is a host stub. These results never qualify Android init,
SELinux, its service cgroup, or cancellation of a physical phone's effects.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "android-integration/working-tree/vendor/trillionnium/owner-open/native"

HARNESS = r'''
#include <atomic>
#include <cassert>
#include <filesystem>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <unistd.h>
#include <sys/wait.h>
static std::atomic<int> stop_calls{0};
static bool property_ok = true;
static bool ready = true;
static pid_t owned_child = -1;
extern "C" int __system_property_set(const char* name, const char* value) {
  if (std::string_view(name) != "sys.trillionnium.owner_open.stop" ||
      std::string_view(value) != "1") return -1;
  ++stop_calls;
  if (owned_child > 0) kill(owned_child, SIGTERM);
  return property_ok ? 0 : -1;
}
extern "C" int __system_property_get(const char*, char* value) {
  value[0] = ready ? '1' : '0'; value[1] = 0; return 1;
}
static std::mutex slow_mutex;
static std::condition_variable slow_condition;
static bool slow_fsync=false,fsync_entered=false,fsync_released=false;
static int FixtureFsync(int fd) {
 { std::unique_lock<std::mutex> lock(slow_mutex);
   if(slow_fsync){fsync_entered=true;slow_condition.notify_all();slow_condition.wait(lock,[]{return fsync_released;});}
 }
 return ::fsync(fd);
}
#define fsync FixtureFsync
#define main ProductionIngressMain
#include "owner_open_ingress_proxy.cpp"
#undef main
#undef fsync

using trillionnium::owner_open::EmergencyInhibit;
using trillionnium::owner_open::InhibitObservation;
static std::string request(const char* kind) {
  return std::string("{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"")
       + kind + "\",\"operation_id\":\"stop-host-fixture\""
       + (std::string_view(kind) == "emergency.stop" ? ",\"explicit_user\":true}" : "}");
}
static Json::Value reply(const ControlRequest& control, const EmergencyInhibit& store) {
  Json::Value value;
  assert(ParseJsonObject(ControlReply(control, store, RequestInitStop), &value));
  assert(value["process_quiescence"] == "unknown");
  assert(value["prior_effect_outcome"] == "unknown");
  assert(value["automatic_redispatch"].isBool() && !value["automatic_redispatch"].asBool());
  return value;
}
int main(int argc, char** argv) {
  assert(argc == 2);
  char pattern[] = "/tmp/owner-open-control-host-XXXXXX";
  char* directory = mkdtemp(pattern); assert(directory != nullptr);
  const std::string state(directory);
  const std::string leaf = state + "/emergency-stop";
  const EmergencyInhibit store(state.c_str(), getuid(), getgid());
  ControlRequest stop{}, status{};
  assert(ParseControl(request("emergency.stop"), &stop));
  assert(ParseControl(request("emergency.status"), &status));
  const std::string scenario(argv[1]);
  if (scenario == "status-wire-roundtrip") {
    std::cout << ControlReply(status, store, RequestInitStop);
    g_inhibited = true;
    std::cout << ControlReply(status, store, RequestInitStop);
    assert(stop_calls == 0);
  } else if (scenario == "wire-roundtrip") {
    std::string line;
    int count = 0;
    for (const auto kind : {ControlKind::Connect, ControlKind::Stop, ControlKind::Status}) {
      assert(std::getline(std::cin, line));
      ControlRequest actual{}; assert(ParseControl(line, &actual));
      assert(actual.kind == kind);
      if (kind != ControlKind::Connect) assert(actual.operation_id == "stop-host-fixture");
      ++count;
    }
    assert(count == 3 && !std::getline(std::cin, line));
  } else if (scenario == "strict-frames") {
    const std::string valid = request("emergency.stop");
    for (const char* addition : {",\"kind\":\"emergency.stop\"", ",\"version\":1",
         ",\"explicit_user\":true", ",\"unknown\":false"}) {
      std::string bad = valid.substr(0, valid.size()-1) + addition + "}";
      assert(!ParseControl(bad, &stop));
    }
    for (const char* field : {"\"version\":1", "\"explicit_user\":true"}) {
      std::string bad = valid;
      const auto where = bad.find(field); assert(where != std::string::npos);
      bad.replace(where, strlen(field), std::string_view(field).starts_with("\"version") ?
                  "\"version\":true" : "\"explicit_user\":false");
      assert(!ParseControl(bad, &stop));
    }
    for (const std::string& bad : {valid + "{}", std::string("\xef\xbb\xbf") + valid,
         std::string("[]"), std::string(4097, 'x'), request("emergency.resume"),
         std::string("{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"emergency.stop\",\"operation_id\":\"\",\"explicit_user\":true}")})
      assert(!ParseControl(bad, &stop));
    assert(ParseControl("{\"kind\":\"ingress.connect\",\"version\":1,\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\"}", &stop));
    assert(stop.kind == ControlKind::Connect);
    assert(stop_calls == 0 && store.Observe() == InhibitObservation::Absent);
  } else if (scenario == "durable-restart-dedup") {
    const auto result = reply(stop, store);
    assert(result["durable_inhibit_confirmed"].asBool());
    assert(result["stop_requested"].asBool() && stop_calls == 1);
    struct stat metadata{}; assert(lstat(leaf.c_str(), &metadata) == 0);
    assert(metadata.st_uid == getuid() && metadata.st_gid == getgid());
    assert((metadata.st_mode & 07777) == 0600 && metadata.st_nlink == 1);
    g_inhibited = false;  // A fresh ingress process must observe the disk fence.
    { std::lock_guard<std::mutex> lock(g_admission); assert(!NormalAdmissionAllowed(store)); }
    assert(!reply(stop, store)["stop_requested"].asBool() && stop_calls == 1);
    assert(reply(status, store)["inhibit_observation"] == "present" && stop_calls == 1);
    g_stop_attempts.clear();  // A fresh ingress process still never submits from status.
    reply(status, store); assert(stop_calls == 1);
    ControlRequest explicit_new = stop; explicit_new.operation_id = "stop-explicit-new";
    assert(reply(explicit_new, store)["stop_requested"].asBool() && stop_calls == 2);
  } else if (scenario == "concurrent-stop") {
    std::vector<std::thread> peers;
    for (int i=0; i<32; ++i) peers.emplace_back([&]{
      assert(reply(stop, store)["durable_inhibit_confirmed"].asBool());
    });
    for (auto& peer : peers) peer.join();
    assert(stop_calls == 1 && g_inhibited && store.Observe() == InhibitObservation::Present);
  } else if (scenario == "slow-fsync-cancellation-fence") {
    slow_fsync=true;
    std::thread stopper([&]{reply(stop,store);});
    { std::unique_lock<std::mutex> lock(slow_mutex);
      assert(slow_condition.wait_for(lock,std::chrono::seconds(2),[]{return fsync_entered;})); }
    assert(stop_calls == 1 && g_inhibited);
    int sockets[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,sockets)==0);
    const unsigned char frame[]="forbidden";
    const auto before=Clock::now();
    assert(!WriteAdmitted(sockets[0],frame,sizeof(frame)-1,Clock::now()+std::chrono::seconds(1),store));
    assert(Clock::now()-before<std::chrono::milliseconds(100));
    assert(reply(status,store)["dispatch_inhibited"].asBool());
    { std::lock_guard<std::mutex> lock(slow_mutex);fsync_released=true;slow_condition.notify_all(); }
    stopper.join();close(sockets[0]);close(sockets[1]);
  } else if (scenario == "in-flight-fence") {
    int sockets[2]; assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    const unsigned char frame[] = "effect-frame\n";
    assert(WriteAdmitted(sockets[0], frame, sizeof(frame)-1, Clock::now()+std::chrono::seconds(1), store));
    std::atomic<bool> finished{false};
    std::thread sender([&]{ while (!finished.load()) {
      if (!WriteAdmitted(sockets[0], frame, sizeof(frame)-1,
          Clock::now()+std::chrono::seconds(1), store)) break;
    }});
    reply(stop, store);
    for (int i=0; i<64; ++i)
      assert(!WriteAdmitted(sockets[0], frame, sizeof(frame)-1,
             Clock::now()+std::chrono::seconds(1), store));
    finished = true; sender.join(); close(sockets[0]); close(sockets[1]);
    // Already forwarded prefixes remain unknown; this test asserts no new
    // admitted write after the durable stop response, not rollback of a prefix.
  } else if (scenario == "crash-partial-leaf") {
    const int fd = open(leaf.c_str(), O_CREAT|O_EXCL|O_WRONLY, 0600);
    assert(fd >= 0); close(fd); // Crash between creation and write/fsync.
    assert(store.Observe() == InhibitObservation::Present);
    { std::lock_guard<std::mutex> lock(g_admission); assert(!NormalAdmissionAllowed(store)); }
    assert(reply(status, store)["inhibit_observation"] == "present" && stop_calls == 0);
  } else if (scenario == "symlink-refusal") {
    assert(symlink("/dev/null", leaf.c_str()) == 0);
    assert(store.Observe() == InhibitObservation::Present);
    assert(!reply(stop, store)["durable_inhibit_confirmed"].asBool());
    { std::lock_guard<std::mutex> lock(g_admission); assert(!NormalAdmissionAllowed(store)); }
    struct stat metadata{}; assert(lstat(leaf.c_str(), &metadata) == 0 && S_ISLNK(metadata.st_mode));
  } else if (scenario == "state-refusal") {
    assert(chmod(state.c_str(), 0755) == 0);
    assert(store.Observe() == InhibitObservation::Unknown);
    assert(!reply(stop, store)["durable_inhibit_confirmed"].asBool());
    assert(stop_calls == 1 && g_inhibited);
    { std::lock_guard<std::mutex> lock(g_admission); assert(!NormalAdmissionAllowed(store)); }
  } else if (scenario == "stop-property-failure") {
    property_ok = false;
    const auto result = reply(stop, store);
    assert(result["durable_inhibit_confirmed"].asBool() && !result["stop_requested"].asBool());
    assert(g_inhibited && stop_calls == 1);
    assert(!reply(stop,store)["stop_requested"].asBool() && stop_calls==1);
    property_ok=true;
    ControlRequest explicit_new=stop;explicit_new.operation_id="stop-explicit-retry";
    assert(reply(explicit_new,store)["stop_requested"].asBool() && stop_calls==2);
  } else if (scenario == "mechanical-capacity-no-eviction") {
    for (std::size_t index=0; index<kMaximumStopAttempts; ++index)
      g_stop_attempts.insert("stop-admitted-" + std::to_string(index));
    const auto refused = reply(stop,store);
    assert(refused["request_attempt"] == "capacity_refused");
    assert(!refused["stop_requested"].asBool() && stop_calls==0 && g_inhibited);
    assert(refused["durable_inhibit_confirmed"].asBool());
    assert(g_stop_attempts.size()==kMaximumStopAttempts);
    ControlRequest duplicate=stop;duplicate.operation_id="stop-admitted-0";
    assert(reply(duplicate,store)["request_attempt"]=="duplicate_in_this_ingress_process");
    assert(stop_calls==0 && g_stop_attempts.size()==kMaximumStopAttempts);
  } else if (scenario == "unready-control") {
    ready = false;
    { std::lock_guard<std::mutex> lock(g_admission); assert(!NormalAdmissionAllowed(store)); }
    assert(reply(status, store)["inhibit_observation"] == "absent" && stop_calls == 0);
    assert(reply(stop, store)["durable_inhibit_confirmed"].asBool() && stop_calls == 1);
  } else if (scenario == "reserved-control-capacity") {
    for (int i=0; i<kMaximumConnections; ++i) assert(TryAcquireConnection());
    assert(!TryAcquireConnection());
    assert(TryAcquireControlSlot());
    assert(reply(stop, store)["stop_requested"].asBool());
    for (int i=0; i<kMaximumConnections; ++i) ReleaseConnection();
    g_pending_controls.fetch_sub(1);
  } else if (scenario == "host-child-cancellation-hook") {
    owned_child = fork(); assert(owned_child >= 0);
    if (owned_child == 0) { for (;;) pause(); }
    const auto result = reply(stop, store);
    int outcome = 0;
    assert(waitpid(owned_child, &outcome, 0) == owned_child);
    assert(WIFSIGNALED(outcome) && WTERMSIG(outcome) == SIGTERM);
    assert(result["process_quiescence"] == "unknown");
    // Real host child + stub property hook, never an Android cgroup claim.
  } else assert(false);
  std::filesystem::remove_all(state);
}
'''


class OwnerOpenEmergencyControlTest(unittest.TestCase):
    def test_production_native_control_rejection_restart_and_concurrency(self):
        compiler = shutil.which("g++") or shutil.which("clang++")
        self.assertIsNotNone(compiler, "native emergency behavior requires a C++ compiler")
        source = os.environ.get("OWNER_OPEN_JSONCPP_SOURCE")
        args = ["-ljsoncpp"]
        includes = []
        if source:
            folder = Path(source)
            self.assertTrue((folder / "include/json/json.h").is_file())
            includes = ["-I", str(folder / "include")]
            args = [str(folder / "src/lib_json" / name) for name in
                    ("json_reader.cpp", "json_value.cpp", "json_writer.cpp")]
        else:
            includes = ["-I", "/usr/include/jsoncpp"]
            self.assertTrue(Path("/usr/include/jsoncpp/json/json.h").is_file(),
                            "install libjsoncpp-dev or set OWNER_OPEN_JSONCPP_SOURCE")
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / "sys").mkdir()
            (folder / "sys/system_properties.h").write_text(
                '#pragma once\n#define PROP_VALUE_MAX 92\n'
                'extern "C" int __system_property_set(const char*, const char*);\n'
                'extern "C" int __system_property_get(const char*, char*);\n')
            harness = folder / "control.cpp"
            harness.write_text('#include <string_view>\n#include <csignal>\n#include <vector>\n' + HARNESS)
            binary = folder / "control"
            result = subprocess.run([compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pthread", "-D__ANDROID__", "-I", str(folder), "-I", str(NATIVE), *includes,
                str(harness), *args, "-lselinux", "-o", str(binary)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            javac, java = shutil.which("javac"), shutil.which("java")
            self.assertTrue(javac and java, "Java/native wire roundtrip requires JDK")
            codec = folder / "ControlWire.java"
            codec.write_text('import org.trillionnium.owneropen.OwnerOpenFrame; public class ControlWire {'
                'public static void main(String[] args){System.out.println(OwnerOpenFrame.ingressConnect());'
                'System.out.println(OwnerOpenFrame.emergencyControl("stop-host-fixture",true));'
                'System.out.println(OwnerOpenFrame.emergencyControl("stop-host-fixture",false));}}')
            frame = NATIVE.parent / "client/src/org/trillionnium/owneropen/OwnerOpenFrame.java"
            result = subprocess.run([javac, "-d", str(folder / "java"), str(frame), str(codec)],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            wire = subprocess.run([java, "-cp", str(folder / "java"), "ControlWire"],
                                  capture_output=True, text=True, timeout=5)
            self.assertEqual(wire.returncode, 0, wire.stderr)
            roundtrip = subprocess.run([str(binary), "wire-roundtrip"], input=wire.stdout,
                                      capture_output=True, text=True, timeout=5)
            self.assertEqual(roundtrip.returncode, 0, roundtrip.stderr)
            print("actual Java -> native first-frame Connect/Stop/Status PASS", flush=True)
            reverse_codec = folder / "StatusWire.java"
            reverse_codec.write_text(r'''import java.io.*;
import org.trillionnium.owneropen.OwnerOpenFrame;
public class StatusWire {
 public static void main(String[] args)throws Exception {
  BufferedReader input=new BufferedReader(new InputStreamReader(System.in));
  String absent=input.readLine(),fenced=input.readLine();
  if(!OwnerOpenFrame.controlStatusAllowsInitialization(absent,"stop-host-fixture"))
   throw new AssertionError("actual native absent/unfenced status rejected");
  for(String invalid:new String[]{fenced,
      absent.replace("\"operation_id\":\"stop-host-fixture\"","\"operation_id\":\"different\""),
      absent.replace("\"version\":1","\"version\":true"),
      absent.substring(0,absent.length()-1)+",\"dispatch_inhibited\":false}",
      absent.substring(0,absent.length()-1)+",\"unknown\":false}"})
   if(OwnerOpenFrame.controlStatusAllowsInitialization(invalid,"stop-host-fixture"))
    throw new AssertionError("untrusted initialization status admitted");
  if(input.readLine()!=null)throw new AssertionError("extra native output");
  System.out.println("actual native -> Java exact status plus fence/correlation/type/duplicate/extra refusals PASS");
 }
}''')
            result = subprocess.run([javac, "-cp", str(folder / "java"),
                "-d", str(folder / "java"), str(reverse_codec)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            status_wire = subprocess.run([str(binary), "status-wire-roundtrip"],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(status_wire.returncode, 0, status_wire.stderr)
            reverse = subprocess.run([java, "-cp", str(folder / "java"), "StatusWire"],
                input=status_wire.stdout, capture_output=True, text=True, timeout=5)
            self.assertEqual(reverse.returncode, 0, reverse.stderr)
            print(reverse.stdout, end="", flush=True)
            for scenario in ("strict-frames", "durable-restart-dedup", "concurrent-stop",
                "in-flight-fence", "slow-fsync-cancellation-fence", "crash-partial-leaf", "symlink-refusal", "state-refusal",
                "stop-property-failure", "mechanical-capacity-no-eviction", "unready-control", "reserved-control-capacity",
                "host-child-cancellation-hook"):
                with self.subTest(scenario=scenario):
                    result = subprocess.run([str(binary), scenario], capture_output=True,
                                            text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    print("actual native " + scenario + " PASS", flush=True)


if __name__ == "__main__":
    unittest.main()
