"""Actual native accept/Pump with host Unix peers and isolated root-owned state.

Requires explicit trusted-host opt-in and passwordless sudo. Only fixture child processes change UID. The
Android peer SELinux label and property service are explicit host substitutes;
this proves neither phone reachability nor Android policy/cgroup qualification.
Production source is copied byte-for-byte except four fixed fixture addresses.
"""
from pathlib import Path
import json
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
#include <condition_variable>
#include <mutex>
#include <fstream>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <json/json.h>
#include <selinux/selinux.h>
#include <csignal>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
static bool fixture_ready=true;
static bool fixture_hold_hello=false;
static std::mutex fixture_storage_mutex;
static std::condition_variable fixture_storage_condition;
static bool fixture_slow_fsync=false,fixture_fsync_entered=false,fixture_fsync_released=false;
static int FixtureFsync(int fd){
 {std::unique_lock<std::mutex> lock(fixture_storage_mutex);if(fixture_slow_fsync){fixture_fsync_entered=true;fixture_storage_condition.notify_all();fixture_storage_condition.wait(lock,[]{return fixture_fsync_released;});}}
 return ::fsync(fd);
}
static pid_t fixture_broker=-1;
static const char* fixture_audit=FIXTURE_AUDIT;
extern "C" int __system_property_get(const char*,char* value){value[0]=fixture_ready?'1':'0';value[1]=0;return 1;}
extern "C" int __system_property_set(const char* name,const char* value){
 if(std::string_view(name)!="sys.trillionnium.owner_open.stop"||std::string_view(value)!="1")return -1;
 std::ofstream(fixture_audit,std::ios::app)<<"init-stop-requested\n";
 if(fixture_broker>0)kill(-fixture_broker,SIGTERM); // Owned host fixture group only.
 return 0;
}
static int FixturePeerContext(int fd,char** output){
 ucred peer{};socklen_t size=sizeof(peer);
 if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)!=0)return -1;
 // Explicit Android-label substitute; actual PID/UID/GID remain kernel values.
 *output=strdup(peer.uid==10002 ? "u:r:untrusted_app:s0:c512,c768" :
                                  "u:r:trillionnium_owner_open_client:s0:c512,c768");
 return *output?0:-1;
}
#define fsync FixtureFsync
#define getpeercon FixturePeerContext
#define main ProductionIngressMain
#include "ingress-fixture.cpp"
#undef main
#undef getpeercon
#undef fsync

struct Client {pid_t pid;int read;};
static int ConnectAbstract(){
 int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);assert(fd>=0);
 sockaddr_un address{};address.sun_family=AF_UNIX;
 memcpy(address.sun_path+1,kAbstractName.data(),kAbstractName.size());
 const auto bytes=static_cast<socklen_t>(offsetof(sockaddr_un,sun_path)+1+kAbstractName.size());
 for(int i=0;i<200;++i){if(connect(fd,reinterpret_cast<sockaddr*>(&address),bytes)==0)return fd;usleep(5000);}
 assert(false);return -1;
}
static Client LaunchClient(uid_t uid,std::string first,bool keep_normal=false){
 int result[2];assert(pipe(result)==0);pid_t pid=fork();assert(pid>=0);
 if(pid==0){
  close(result[0]);assert(setgid(uid)==0&&setuid(uid)==0);assert(prctl(PR_SET_PDEATHSIG,SIGKILL)==0);
  int fd=ConnectAbstract();
  const auto deadline=Clock::now()+std::chrono::seconds(7);
  WriteAll(fd,reinterpret_cast<const unsigned char*>(first.data()),first.size(),deadline);
  std::string line;bool received=ReadLine(fd,&line,deadline);
  if(received)assert(write(result[1],line.data(),line.size())==static_cast<ssize_t>(line.size()));
  else assert(write(result[1],"REFUSED\n",8)==8);
  if(keep_normal){
   assert(received&&line.find("broker.hello.ack")!=std::string::npos);
   static constexpr char effect[]="{\"kind\":\"host-fixture-bytes\"}\n";
   assert(WriteAll(fd,reinterpret_cast<const unsigned char*>(effect),sizeof(effect)-1,deadline));
   assert(!ReadLine(fd,&line,Clock::now()+std::chrono::seconds(10)));
   assert(write(result[1],"EOF\n",4)==4);
  }
  close(fd);close(result[1]);_exit(0);
 }
 close(result[1]);return {pid,result[0]};
}
static std::string ClientLine(Client client){
 std::string line;char c=0;while(read(client.read,&c,1)==1){line.push_back(c);if(c=='\n')return line;}
 assert(false);return {};
}
static void Reap(Client client){int status=0;assert(waitpid(client.pid,&status,0)==client.pid);assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);close(client.read);}
static std::string Control(const char* kind,const char* id="stop-real-host-fixture"){
 return std::string("{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"")+kind+
    "\",\"operation_id\":\""+id+"\""+(std::string_view(kind)=="emergency.stop"?",\"explicit_user\":true}\n":"}\n");
}
static pid_t StartIngress(){pid_t pid=fork();assert(pid>=0);if(pid==0){assert(prctl(PR_SET_PDEATHSIG,SIGKILL)==0);_exit(ProductionIngressMain());}return pid;}
static void StopIngress(pid_t pid){assert(kill(pid,SIGKILL)==0);int status;assert(waitpid(pid,&status,0)==pid);}
static void BrokerPeer(int fd){
 std::string line;assert(ReadLine(fd,&line,Clock::now()+std::chrono::seconds(5)));
 Json::Value hello;assert(ParseJsonObject(line,&hello));
 if(fixture_hold_hello){std::ofstream(fixture_audit,std::ios::app)<<"broker-hello-waiting\n";for(;;)pause();}
 ucred peer{};assert(ReadPeerCredentials(fd,&peer));
 Json::Value ack(Json::objectValue);ack["schema"]=std::string(kWireSchema);ack["kind"]="broker.hello.ack";
 ack["automatic_redispatch"]=false;ack["broker_id"]=std::string(kBrokerId);ack["client_id"]=hello["client_id"];
 ack["broker_epoch"]=std::string(32,'a');ack["token_epoch"]=std::string(32,'b');ack["descriptor_sha256"]=std::string(64,'c');
 ack["host_hello_ack"]["kind"]="hello.ack";ack["host_hello_ack"]["payload"]=Json::Value(Json::objectValue);
 ack["peer"]["pid"]=peer.pid;ack["peer"]["uid"]=peer.uid;ack["peer"]["gid"]=peer.gid;
 Json::StreamWriterBuilder writer;writer["indentation"]="";line=Json::writeString(writer,ack)+"\n";
 assert(WriteAll(fd,reinterpret_cast<const unsigned char*>(line.data()),line.size(),Clock::now()+std::chrono::seconds(5)));
 std::ofstream(fixture_audit,std::ios::app)<<"normal-authenticated\n";
 assert(ReadLine(fd,&line,Clock::now()+std::chrono::seconds(7)));
 assert(line=="{\"kind\":\"host-fixture-bytes\"}\n");
 // No Host/Core/model/effect emulation: consume known transport fixture bytes.
 for(;;)pause();
}
static pid_t StartBroker(){
 std::filesystem::create_directory(std::string(kState)+"/broker");chmod((std::string(kState)+"/broker").c_str(),0700);
 {int token=open(kToken,O_CREAT|O_EXCL|O_WRONLY,0600);assert(token>=0);std::string value(64,'d');value+='\n';assert(write(token,value.data(),value.size())==static_cast<ssize_t>(value.size()));close(token);}
 int listener=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);assert(listener>=0);sockaddr_un address{};address.sun_family=AF_UNIX;
 snprintf(address.sun_path,sizeof(address.sun_path),"%s",kUpstream);assert(bind(listener,reinterpret_cast<sockaddr*>(&address),sizeof(address))==0);assert(listen(listener,64)==0);
 pid_t pid=fork();assert(pid>=0);
 if(pid==0){assert(prctl(PR_SET_PDEATHSIG,SIGKILL)==0);assert(setsid()==getpid());for(;;){int fd=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);assert(fd>=0);std::thread(BrokerPeer,fd).detach();}}
 close(listener);return pid;
}
int main(int argc,char** argv){
 assert(argc==2&&geteuid()==0);std::filesystem::remove_all(kState);
 std::filesystem::remove(fixture_audit);
 if(std::string_view(argv[1])=="cleanup")return 0;
 std::filesystem::create_directory(kState);assert(chmod(kState,0700)==0);
 const std::string scenario(argv[1]);
 int uid_denied_count=0,context_denied_count=0,eof_count=0;Json::Value counter_stages(Json::arrayValue);
 auto capture_counters=[&](const char* stage){Json::Value v(Json::objectValue);v["stage"]=stage;v["normal_reserved"]=g_connections.load();v["pending_controls"]=g_pending_controls.load();counter_stages.append(v);};

 if(scenario=="pump-peer-first-frame"){
  const pid_t ingress=StartIngress();
  for(uid_t uid : {0u,9999u,10002u}){auto denied=LaunchClient(uid,Control("emergency.stop"));assert(ClientLine(denied)=="REFUSED\n");Reap(denied);if(uid==10002)++context_denied_count;else ++uid_denied_count;}
  auto malformed=LaunchClient(10001,"{\"kind\":\"broker.hello\"}\n");assert(ClientLine(malformed)=="REFUSED\n");Reap(malformed);
  assert(!std::filesystem::exists(std::string(kState)+"/emergency-stop"));
  auto accepted=LaunchClient(10001,Control("emergency.stop"));const auto reply=ClientLine(accepted);Reap(accepted);
  assert(reply.find("\"durable_inhibit_confirmed\":true")!=std::string::npos);
  assert(reply.find("\"process_quiescence\":\"unknown\"")!=std::string::npos);StopIngress(ingress);
 }else if(scenario=="pump-unready-control"){
  fixture_ready=false;const pid_t ingress=StartIngress();
  auto ordinary=LaunchClient(10001,"{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"ingress.connect\"}\n");assert(ClientLine(ordinary)=="REFUSED\n");Reap(ordinary);
  auto status=LaunchClient(10001,Control("emergency.status"));assert(ClientLine(status).find("\"inhibit_observation\":\"absent\"")!=std::string::npos);Reap(status);
  auto stop=LaunchClient(10001,Control("emergency.stop"));assert(ClientLine(stop).find("\"stop_requested\":true")!=std::string::npos);Reap(stop);StopIngress(ingress);
 }else if(scenario=="pump-normal-stop-eof-reserved"){
  fixture_broker=StartBroker();const pid_t ingress=StartIngress();std::vector<Client> ordinary;
  for(int i=0;i<kMaximumConnections;++i){auto client=LaunchClient(10001,"{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"ingress.connect\"}\n",true);assert(ClientLine(client).find("broker.hello.ack")!=std::string::npos);ordinary.push_back(client);}
  auto stop=LaunchClient(10001,Control("emergency.stop"));assert(ClientLine(stop).find("\"stop_requested\":true")!=std::string::npos);Reap(stop);
  for(auto client:ordinary){assert(ClientLine(client)=="EOF\n");Reap(client);++eof_count;}
  int status;assert(waitpid(fixture_broker,&status,0)==fixture_broker&&WIFSIGNALED(status));fixture_broker=-1;
  StopIngress(ingress);
  const pid_t replacement=StartIngress();
  auto old=LaunchClient(10001,"{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"ingress.connect\"}\n");assert(ClientLine(old)=="REFUSED\n");Reap(old);
  auto read=LaunchClient(10001,Control("emergency.status"));assert(ClientLine(read).find("\"request_attempt\":\"status_only\"")!=std::string::npos);Reap(read);StopIngress(replacement);
 }else if(scenario=="pump-broker-auth-race-slow-storage-counters"){
  fixture_hold_hello=true;fixture_broker=StartBroker();int listener=Listen();assert(listener>=0);
  auto ordinary=LaunchClient(10001,"{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"ingress.connect\"}\n");
  int fd=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);assert(fd>=0);ucred peer{};assert(AllowedPeer(fd,&peer)&&peer.uid==10001&&TryAcquireControlSlot());
  std::thread normal(Pump,fd,peer);
  auto deadline=Clock::now()+std::chrono::seconds(3);bool waiting=false;
  while(Clock::now()<deadline){std::ifstream in(fixture_audit);std::string line;while(std::getline(in,line))if(line=="broker-hello-waiting")waiting=true;if(waiting)break;usleep(5000);}
  assert(waiting&&g_connections==1&&g_pending_controls==0);capture_counters("broker_hello_pending");
  fixture_slow_fsync=true;auto stop=LaunchClient(10001,Control("emergency.stop"));
  fd=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);assert(fd>=0&&AllowedPeer(fd,&peer)&&TryAcquireControlSlot());std::thread stopping(Pump,fd,peer);
  {std::unique_lock<std::mutex> lock(fixture_storage_mutex);assert(fixture_storage_condition.wait_for(lock,std::chrono::seconds(3),[]{return fixture_fsync_entered;}));}
  assert(g_inhibited&&g_pending_controls==1);normal.join();assert(g_connections==0&&g_pending_controls==1);capture_counters("stop_requested_storage_still_blocked");
  assert(ClientLine(ordinary)=="REFUSED\n");Reap(ordinary);
  auto fresh=LaunchClient(10001,"{\"schema\":\"org.trillionnium.owner-open.ingress-control.v1\",\"version\":1,\"kind\":\"ingress.connect\"}\n");
  fd=accept4(listener,nullptr,nullptr,SOCK_CLOEXEC);assert(fd>=0&&AllowedPeer(fd,&peer)&&TryAcquireControlSlot());
  std::thread refused(Pump,fd,peer);assert(ClientLine(fresh)=="REFUSED\n");Reap(fresh);refused.join();assert(g_connections==0&&g_pending_controls==1);
  {std::lock_guard<std::mutex> lock(fixture_storage_mutex);fixture_fsync_released=true;fixture_storage_condition.notify_all();}
  assert(ClientLine(stop).find("\"durable_inhibit_confirmed\":true")!=std::string::npos);Reap(stop);stopping.join();assert(g_connections==0&&g_pending_controls==0);capture_counters("all_direct_pumps_collected");
  int status;assert(waitpid(fixture_broker,&status,0)==fixture_broker&&WIFSIGNALED(status));fixture_broker=-1;close(listener);
 }else assert(false);
 int attempts=0,authenticated=0;{std::ifstream in(fixture_audit);std::string line;while(std::getline(in,line)){if(line=="init-stop-requested")++attempts;if(line=="normal-authenticated")++authenticated;}}
 Json::Value result(Json::objectValue);result["scenario"]=scenario;result["property_attempts_observed"]=attempts;result["normal_authenticated_observed"]=authenticated;result["normal_eofs_observed"]=eof_count;result["kernel_uid_threshold_denials_observed"]=uid_denied_count;result["stub_peer_context_denials_observed"]=context_denied_count;result["counter_stages"]=counter_stages;result["counter_observation"]=scenario=="pump-broker-auth-race-slow-storage-counters"?"same_process_direct_pump":"not_observed_in_ingress_child";result["phone_qualified"]=false;Json::StreamWriterBuilder writer;writer["indentation"]="";std::cout<<Json::writeString(writer,result)<<"\n";
 std::filesystem::remove_all(kState);
}
'''


class OwnerOpenEmergencyPumpTest(unittest.TestCase):
    def test_actual_accept_peer_credentials_first_frame_and_upstream_eof(self):
        if os.environ.get("OWNER_OPEN_RUN_TRUSTED_ROOT_PUMP") != "1":
            self.skipTest("manual trusted-host root fixture is excluded from ordinary source/CI matrix")
        sudo = shutil.which("sudo")
        if not sudo or subprocess.run([sudo, "-n", "true"], capture_output=True).returncode:
            self.skipTest("isolated root-owned host fixture requires passwordless sudo")
        compiler = shutil.which("g++") or shutil.which("clang++")
        self.assertTrue(compiler)
        source = os.environ.get("OWNER_OPEN_JSONCPP_SOURCE")
        if source:
            dependency = Path(source)
            includes = ["-I", str(dependency / "include")]
            libraries = [str(dependency / "src/lib_json" / name) for name in
                         ("json_reader.cpp", "json_value.cpp", "json_writer.cpp")]
        else:
            self.assertTrue(Path("/usr/include/jsoncpp/json/json.h").is_file())
            includes, libraries = ["-I", "/usr/include/jsoncpp"], ["-ljsoncpp"]
        with tempfile.TemporaryDirectory(prefix="owner-open-pump-host-") as temporary:
            folder = Path(temporary)
            fixture_source = (NATIVE / "owner_open_ingress_proxy.cpp").read_text()
            replacements = {
                '"/data/trillionnium/owner-open/state"': json.dumps(str(folder / "fixture-state")),
                '"/data/trillionnium/owner-open/state/broker/owner-open.sock"': json.dumps(str(folder / "fixture-state/broker/owner-open.sock")),
                '"/data/trillionnium/owner-open/state/broker/owner-open.token"': json.dumps(str(folder / "fixture-state/broker/owner-open.token")),
                '"trillionnium_owner_open"': json.dumps("fixture_" + folder.name),
            }
            for old, new in replacements.items():
                self.assertEqual(fixture_source.count(old), 1)
                fixture_source = fixture_source.replace(old, new)
            (folder / "ingress-fixture.cpp").write_text(fixture_source)
            (folder / "sys").mkdir()
            (folder / "sys/system_properties.h").write_text(
                '#pragma once\n#define PROP_VALUE_MAX 92\n'
                'extern "C" int __system_property_set(const char*,const char*);\n'
                'extern "C" int __system_property_get(const char*,char*);\n')
            (folder / "pump.cpp").write_text('#include <string_view>\n#include <vector>\n'
                '#include <fcntl.h>\n#include <iostream>\n' + '#define FIXTURE_AUDIT ' + json.dumps(str(folder / "stop-audit")) + '\n' + HARNESS)
            binary = folder / "pump"
            result = subprocess.run([compiler, "-std=c++20", "-Wall", "-Wextra", "-Werror",
                "-pthread", "-D__ANDROID__", "-I", str(folder), "-I", str(NATIVE), *includes,
                str(folder / "pump.cpp"), *libraries, "-lselinux", "-o", str(binary)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stderr)
            try:
                for scenario in ("pump-peer-first-frame", "pump-unready-control", "pump-normal-stop-eof-reserved", "pump-broker-auth-race-slow-storage-counters"):
                    with self.subTest(scenario=scenario):
                        result = subprocess.run([sudo, "-n", str(binary), scenario],
                            capture_output=True, text=True, timeout=30)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        print(result.stdout.strip())
            finally:
                subprocess.run([sudo, "-n", str(binary), "cleanup"], capture_output=True, timeout=5)
                # The root-written fixture audit is outside the root-owned state
                # leaf, so the owning temporary directory can unlink it normally.


if __name__ == "__main__":
    unittest.main()
