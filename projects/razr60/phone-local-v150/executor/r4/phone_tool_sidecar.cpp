// Phone-local tool transport. Model text never enters this endpoint as shell:
// reviewed typed mappers construct commands; native r5 still owns tool admission.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <poll.h>
#include <stdexcept>
#include <string>
#include <sys/file.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include "json.hpp"
#include "hash/hash.h"
using J=nlohmann::json;
using Clock=std::chrono::steady_clock;
static constexpr size_t MAX_REQUEST=262144,MAX_COMMAND=131072,MAX_OUTPUT=8*1024*1024,MAX_RESPONSE=12*1024*1024;
static std::mutex effect_mutex;
static std::atomic<unsigned> workers{0};
static volatile sig_atomic_t stopping=0;
static int actions_fd=-1;
static std::atomic<bool> recovery_required{false};
static std::string instance,shell_path="/system/bin/sh";
static uid_t fixture_uid=static_cast<uid_t>(-1);
#ifdef HEPTA_TESTING
static std::atomic<unsigned> fixture_prelock_delays{0};
#endif
static int64_t now_ms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}
static void stop_signal(int){stopping=1;}
static std::string digest(const std::string&s){return hash_sha256_hex(s.data(),s.size());}
static bool hexstr(const std::string&s,size_t n){return s.size()==n&&s.find_first_not_of("0123456789abcdef")==std::string::npos;}
static void require(bool ok,const char*msg){if(!ok)throw std::runtime_error(msg);}
static std::string b64(const std::string&s){
 static const char*t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
 std::string o;o.reserve((s.size()+2)/3*4);unsigned v=0;int bits=-6;
 for(unsigned char c:s){v=(v<<8)|c;bits+=8;while(bits>=0){o.push_back(t[(v>>bits)&63]);bits-=6;}}
 if(bits>-6)o.push_back(t[((v<<8)>>(bits+8))&63]);while(o.size()%4)o.push_back('=');return o;
}
static bool write_all(int fd,const void*p,size_t n){
 const char*b=static_cast<const char*>(p);while(n){ssize_t k=write(fd,b,n);if(k<0&&errno==EINTR)continue;if(k<=0)return false;b+=k;n-=k;}return true;
}
static bool read_all(int fd,void*p,size_t n){
 char*b=static_cast<char*>(p);while(n){ssize_t k=read(fd,b,n);if(k<0&&errno==EINTR)continue;if(k<=0)return false;b+=k;n-=k;}return true;
}
static void send_json(int fd,const J&j){
 std::string s=j.dump();if(s.size()>MAX_RESPONSE)return;unsigned char h[4]={(unsigned char)(s.size()>>24),(unsigned char)(s.size()>>16),(unsigned char)(s.size()>>8),(unsigned char)s.size()};
 if(write_all(fd,h,4))write_all(fd,s.data(),s.size());
}
static J receive_json(int fd){
 unsigned char h[4];require(read_all(fd,h,4),"incomplete_request_header");
 size_t n=((size_t)h[0]<<24)|((size_t)h[1]<<16)|((size_t)h[2]<<8)|h[3];require(n>0&&n<=MAX_REQUEST,"request_size_limit");
 std::string s(n,'\0');require(read_all(fd,s.data(),n),"incomplete_request_body");return J::parse(s);
}
static std::string read_at(int dir,const char*name,size_t cap){
 int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)throw std::runtime_error("stored_file_unavailable");
 struct stat st{};if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1||st.st_size<0||(size_t)st.st_size>cap){close(fd);throw std::runtime_error("stored_file_invalid");}
 std::string s((size_t)st.st_size,'\0');bool ok=read_all(fd,s.data(),s.size());close(fd);require(ok,"stored_file_incomplete");return s;
}
static bool exists_at(int dir,const char*name){struct stat st{};return fstatat(dir,name,&st,AT_SYMLINK_NOFOLLOW)==0;}
static void atomic_receipt(int dir,const J&r){
 std::string s=r.dump();const char*tmp="receipt.pending";
 int fd=openat(dir,tmp,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);require(fd>=0,"receipt_temp_create_failed");
 bool ok=write_all(fd,s.data(),s.size())&&fsync(fd)==0;close(fd);require(ok,"receipt_write_failed");
 require(renameat(dir,tmp,dir,"receipt.json")==0,"receipt_publish_failed");require(fsync(dir)==0,"receipt_directory_sync_failed");
}
static J envelope(J receipt,bool duplicate=false,bool include=false,int dir=-1){
 J o={{"version",1},{"protocol","hepta_phone_local_v150"},{"duplicate",duplicate},{"receipt",receipt}};
 if(include&&dir>=0&&receipt.value("terminal",false)){
  auto a=read_at(dir,"stdout.bin",MAX_OUTPUT),b=read_at(dir,"stderr.bin",MAX_OUTPUT);require(a.size()+b.size()<=MAX_OUTPUT,"stored_output_limit");
  require(digest(a)==receipt.value("stdout_sha256","")&&digest(b)==receipt.value("stderr_sha256",""),"stored_output_hash_mismatch");
  o["stdout_b64"]=b64(a);o["stderr_b64"]=b64(b);
 }return o;
}
static J inspect_action(const std::string&id,const std::string&sha,bool include,bool duplicate){
 int d=openat(actions_fd,id.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
 if(d<0)return envelope({{"action_id",id},{"state","not_found"},{"terminal",false},{"effect_started",false}},duplicate);
 try{
  J intent=J::parse(read_at(d,"intent.json",MAX_REQUEST));require(intent.value("action_id","")==id,"stored_action_identity_mismatch");
  if(!sha.empty()&&intent.value("command_sha256","")!=sha){close(d);return envelope({{"action_id",id},{"state","rejected"},{"error","action_id_payload_mismatch"},{"terminal",false},{"effect_started",false}},duplicate);}
  J r=exists_at(d,"receipt.json")?J::parse(read_at(d,"receipt.json",MAX_REQUEST)):intent;
  if(!r.value("terminal",false)&&r.value("server_instance","")!=instance){r["state"]="indeterminate";r["error"]="server_restarted_before_terminal";r["can_redispatch"]=false;}
  J o=envelope(r,duplicate,include,d);close(d);return o;
 }catch(...){close(d);throw;}
}
static bool disconnected(int fd){struct pollfd p{fd,POLLRDHUP|POLLHUP|POLLERR,0};if(poll(&p,1,0)>0&&(p.revents&(POLLRDHUP|POLLHUP|POLLERR)))return true;char c;ssize_t k=recv(fd,&c,1,MSG_PEEK|MSG_DONTWAIT);return k==0||(k<0&&errno!=EAGAIN&&errno!=EWOULDBLOCK&&errno!=EINTR);}
static bool group_absent(pid_t p){return kill(-p,0)<0&&errno==ESRCH;}
static void signal_owned(pid_t pid,int sig,bool group){if(group)kill(-pid,sig);else kill(pid,sig);}
static void reap_group(pid_t pgid){int st;while(waitpid(-pgid,&st,WNOHANG)>0){}}
struct ChildGuard { pid_t pid; bool dismissed=false; ~ChildGuard(){if(dismissed)return;kill(-pid,SIGKILL);kill(pid,SIGKILL);int st;for(int i=0;i<200;i++){pid_t w=waitpid(pid,&st,WNOHANG);if(w==pid||(w<0&&errno==ECHILD))break;usleep(10000);}reap_group(pid);} };
static J execute_action(int sock,const J&q,uid_t peer){
 std::string id=q.at("action_id").get<std::string>(),sha=q.at("command_sha256").get<std::string>(),cmd=q.at("command").get<std::string>();
 require(hexstr(id,32)&&hexstr(sha,64),"invalid_action_identity");require(!cmd.empty()&&cmd.size()<=MAX_COMMAND&&cmd.find('\0')==std::string::npos,"invalid_command");
 require(digest(cmd)==sha,"command_sha256_mismatch");require(q.at("timeout_ms").is_number_integer(),"invalid_timeout_type");auto timeout64=q.at("timeout_ms").get<int64_t>();require(timeout64>=1&&timeout64<=60000,"invalid_timeout");int timeout=(int)timeout64;
 if(exists_at(actions_fd,id.c_str()))return inspect_action(id,sha,false,true);
 if(recovery_required)return envelope({{"action_id",id},{"state","recovery_required"},{"error","unresolved_prior_intent"},{"terminal",false},{"effect_started",false}});
 #ifdef HEPTA_TESTING
 if(q.value("_fixture_prelock_delay_ms",0)>0){fixture_prelock_delays++;usleep(std::min(q.value("_fixture_prelock_delay_ms",0),2000)*1000);}
#endif
 std::unique_lock<std::mutex> lock(effect_mutex,std::try_to_lock);
 if(!lock.owns_lock())return envelope({{"action_id",id},{"state","busy"},{"terminal",false},{"effect_started",false}});
 if(recovery_required.load())return envelope({{"action_id",id},{"state","recovery_required"},{"error","unresolved_prior_intent"},{"terminal",false},{"effect_started",false}});
 if(mkdirat(actions_fd,id.c_str(),0700)!=0){if(errno==EEXIST)return inspect_action(id,sha,false,true);throw std::runtime_error("action_directory_create_failed");}
 int d=openat(actions_fd,id.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);require(d>=0,"action_directory_open_failed");
 J r={{"version",1},{"action_id",id},{"command_sha256",sha},{"timeout_ms",timeout},{"server_instance",instance},{"peer_uid",peer},{"created_unix_ms",now_ms()},{"state","intent"},{"terminal",false},{"effect_started",false},{"dispatch_count",0},{"can_redispatch",false}};
 std::string intent=r.dump();int fi=openat(d,"intent.json",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
 if(fi<0){close(d);throw std::runtime_error("intent_exclusive_create_failed");}
 bool intent_ok=write_all(fi,intent.data(),intent.size())&&fsync(fi)==0;close(fi);
 bool directory_ok=intent_ok&&fsync(d)==0;int parent_sync_rc=-1;
 if(directory_ok){
#ifdef HEPTA_TESTING
  if(q.value("_fixture_parent_fsync_fail",false)){errno=EIO;parent_sync_rc=-1;}else
#endif
  parent_sync_rc=fsync(actions_fd);
 }
 if(!directory_ok||parent_sync_rc!=0){close(d);recovery_required=true;throw std::runtime_error("intent_durability_failed");}
 r["intent_parent_sync_complete"]=true;
 int logs[2]={-1,-1},out[2]={-1,-1},err[2]={-1,-1},started[2]={-1,-1};
 logs[0]=openat(d,"stdout.bin",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);logs[1]=openat(d,"stderr.bin",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
 if(logs[0]<0||logs[1]<0||pipe2(out,O_CLOEXEC)||pipe2(err,O_CLOEXEC)||pipe2(started,O_CLOEXEC)){recovery_required=true;throw std::runtime_error("tool_io_setup_failed");}
 int nullfd=open("/dev/null",O_RDONLY|O_CLOEXEC);require(nullfd>=0,"null_input_open_failed");
 auto begin=Clock::now();pid_t pid=fork();
 if(pid==0){
  close(out[0]);close(err[0]);close(started[0]);
  if(setsid()<0)_exit(126);
#ifdef HEPTA_TESTING
  if(q.value("_fixture_child_handshake_delay_ms",0)>0)usleep(std::min(q.value("_fixture_child_handshake_delay_ms",0),2000)*1000);
  if(q.value("_fixture_omit_handshake",false))_exit(126);
#endif
  if(dup2(nullfd,0)<0||dup2(out[1],1)<0||dup2(err[1],2)<0)_exit(126);
  char s='S';if(write(started[1],&s,1)!=1)_exit(126);close(started[1]);close(out[1]);close(err[1]);close(nullfd);
  execl(shell_path.c_str(),shell_path.c_str(),"-c",cmd.c_str(),(char*)nullptr);_exit(127);
 }
 close(nullfd);close(out[1]);close(err[1]);close(started[1]);
 if(pid<0){recovery_required=true;throw std::runtime_error("tool_fork_failed");}
 ChildGuard child_guard{pid};
 int reads[2]={out[0],err[0]};for(int f:reads)fcntl(f,F_SETFL,fcntl(f,F_GETFL)|O_NONBLOCK);fcntl(started[0],F_SETFL,fcntl(started[0],F_GETFL)|O_NONBLOCK);
 r["state"]="running";r["effect_started"]=nullptr;r["pid"]=pid;r["pgid"]=pid;r["dispatch_count"]=1;r["dispatch_started_unix_ms"]=now_ms();
 bool journal_ok=true;try{atomic_receipt(d,r);}catch(...){journal_ok=false;}
 bool group=false,joined=false,eof[2]={false,false},handshake_eof=false,handshake_saved=false;int status=0;std::string data[2],reason;
 auto consume_handshake=[&](){
  while(!handshake_eof){char value;ssize_t n=read(started[0],&value,1);
   if(n==1){if(value=='S'){group=true;r["effect_started"]=true;}else if(reason.empty())reason="setsid_handshake_invalid";continue;}
   if(n==0){handshake_eof=true;break;}if(errno==EINTR)continue;if(errno!=EAGAIN&&errno!=EWOULDBLOCK&&reason.empty())reason="setsid_handshake_read_failed";break;
  }
 };
#ifdef HEPTA_TESTING
 bool fixture_first_wait=true;
#endif
 if(!journal_ok)reason="receipt_write_failed";
 auto kill_at=Clock::time_point{};bool term_sent=false,killed=false;bool client_gone=false;
 while(true){
  consume_handshake();
#ifdef HEPTA_TESTING
  if(fixture_first_wait&&q.value("_fixture_parent_wait_delay_ms",0)>0)usleep(std::min(q.value("_fixture_parent_wait_delay_ms",0),2000)*1000);fixture_first_wait=false;
#endif
  if(!joined){pid_t w=waitpid(pid,&status,WNOHANG);if(w==pid)joined=true;else if(w<0&&errno==ECHILD){reason="child_wait_identity_lost";}}
  if(joined&&!group){consume_handshake();if(group)r["handshake_observed_after_join"]=true;}
  if(group&&!handshake_saved){try{atomic_receipt(d,r);handshake_saved=true;}catch(...){if(reason.empty())reason="receipt_write_failed";}}
  for(int i=0;i<2;i++)if(!eof[i]){
   char buf[16384];size_t drained=0;while(true){ssize_t n=read(reads[i],buf,sizeof(buf));
    if(n==0){eof[i]=true;break;}if(n<0){if(errno==EINTR)continue;if(errno!=EAGAIN&&errno!=EWOULDBLOCK){eof[i]=true;if(reason.empty())reason="output_read_failed";}break;}
    size_t room=MAX_OUTPUT-data[0].size()-data[1].size(),take=std::min(room,(size_t)n);
    if(take){data[i].append(buf,take);if(!write_all(logs[i],buf,take)&&reason.empty())reason="output_persist_failed";}
    if(take<(size_t)n&&reason.empty())reason="output_limit_exceeded";drained+=(size_t)n;if(drained>=65536||take<(size_t)n)break;
   }
  }
  auto now=Clock::now();if(!client_gone&&disconnected(sock))client_gone=true;
  if(reason.empty()&&client_gone)reason="client_disconnected";
  if(reason.empty()&&stopping)reason="server_stopping";
  if(reason.empty()&&std::chrono::duration_cast<std::chrono::milliseconds>(now-begin).count()>=timeout)reason="timeout";
  if(joined&&group){reap_group(pid);if(reason.empty()&&!group_absent(pid))reason="background_descendants";}
  if(!reason.empty()&&!term_sent){signal_owned(pid,SIGTERM,group);term_sent=true;kill_at=now;}
  if(term_sent&&!killed&&now-kill_at>=std::chrono::milliseconds(200)){signal_owned(pid,SIGKILL,group);killed=true;}
  if(joined&&eof[0]&&eof[1]&&group_absent(pid)){if(!group&&reason.empty())reason="setsid_handshake_unobserved";break;}
  if(term_sent&&now-kill_at>=std::chrono::seconds(2))break;
  struct pollfd fds[3]={{eof[0]?-1:reads[0],POLLIN|POLLHUP,0},{eof[1]?-1:reads[1],POLLIN|POLLHUP,0},{sock,POLLRDHUP|POLLHUP|POLLERR,0}};poll(fds,3,10);
 }
 if(!joined){signal_owned(pid,SIGKILL,group);for(int i=0;i<100;i++){pid_t w=waitpid(pid,&status,WNOHANG);if(w==pid){joined=true;break;}usleep(10000);}}
 if(joined&&!group){consume_handshake();if(group)r["handshake_observed_after_join"]=true;}
 if(group){reap_group(pid);for(int i=0;i<100&&!group_absent(pid);i++){kill(-pid,SIGKILL);reap_group(pid);usleep(10000);}}
 bool absent=group_absent(pid);child_guard.dismissed=joined&&absent;
 close(started[0]);for(int i=0;i<2;i++){close(reads[i]);if(fsync(logs[i])!=0&&reason.empty())reason="output_sync_failed";close(logs[i]);}
 r["terminal"]=true;r["waitpid_joined"]=joined;r["process_group_established"]=group;r["process_group_absent"]=absent;
 r["exit_code"]=joined&&WIFEXITED(status)?J(WEXITSTATUS(status)):J(nullptr);r["term_signal"]=joined&&WIFSIGNALED(status)?J(WTERMSIG(status)):J(nullptr);
 r["stdout_bytes"]=data[0].size();r["stderr_bytes"]=data[1].size();r["stdout_sha256"]=digest(data[0]);r["stderr_sha256"]=digest(data[1]);
 r["elapsed_ms"]=std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now()-begin).count();r["completed_unix_ms"]=now_ms();r["client_disconnected"]=client_gone;
 r["state"]=reason.empty()&&group&&joined&&absent?"completed":reason=="timeout"?"timed_out":(reason=="client_disconnected"||reason=="server_stopping")?"cancelled":reason=="output_limit_exceeded"?"output_limit_exceeded":"failed";
 if(!joined||!absent){r["state"]="indeterminate";reason="owned_process_cleanup_incomplete";recovery_required=true;}
 if(!group){r["state"]="indeterminate";r["effect_started"]=nullptr;reason="setsid_handshake_unobserved";recovery_required=true;}r["error"]=reason;
 try{atomic_receipt(d,r);}catch(...){recovery_required=true;close(d);throw;}
 J response=envelope(r,false,true,d);close(d);return response;
}
static void connection(int fd){
 J request;
 try{
  struct ucred cred{};socklen_t len=sizeof(cred);require(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&len)==0,"peer_credentials_unavailable");
  bool allowed=cred.uid==0||cred.uid==2000;
#ifdef HEPTA_TESTING
  allowed=allowed||cred.uid==fixture_uid;
#endif
  require(allowed,"peer_uid_denied");
  struct timeval tv{5,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&tv,sizeof(tv));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&tv,sizeof(tv));
  J q=receive_json(fd);request=q;require(q.is_object()&&q.value("version",0)==1,"invalid_protocol");std::string op=q.at("op");
  if(op=="health"){J health={{"version",1},{"protocol","hepta_phone_local_v150"},{"server_instance",instance},{"state",recovery_required?"recovery_required":"ready"},{"inference_endpoint",false}};
#ifdef HEPTA_TESTING
   health["fixture_prelock_delays"]=fixture_prelock_delays.load();
#endif
   send_json(fd,health);}
  else if(op=="inspect"){std::string id=q.at("action_id"),sha=q.value("command_sha256","");require(hexstr(id,32)&&(sha.empty()||hexstr(sha,64)),"invalid_action_identity");send_json(fd,inspect_action(id,sha,q.value("include_output",false),false));}
  else if(op=="execute")send_json(fd,execute_action(fd,q,cred.uid));
  else throw std::runtime_error("unsupported_operation");
 }catch(const std::exception&e){
  J o={{"version",1},{"protocol","hepta_phone_local_v150"},{"state","rejected"},{"error",e.what()},{"effect_started",false}};
  try{if(request.is_object()&&request.value("op","")=="execute"){std::string id=request.value("action_id","");if(hexstr(id,32)&&exists_at(actions_fd,id.c_str())){o=inspect_action(id,"",false,false);o["transport_error"]=e.what();o["receipt"]["state"]="indeterminate";o["receipt"]["terminal"]=false;o["receipt"]["effect_started"]=nullptr;recovery_required=true;}}}catch(...){o["state"]="indeterminate";o["effect_started"]=nullptr;recovery_required=true;}send_json(fd,o);
 }
 close(fd);workers--;
}
static bool safe_execution_terminal(const J&r){
 const std::string state=r.value("state","");
 const bool terminal_state=state=="completed"||state=="failed"||state=="timed_out"||state=="cancelled"||state=="output_limit_exceeded";
 return r.value("terminal",false)&&terminal_state&&r.contains("effect_started")&&r["effect_started"].is_boolean()&&r["effect_started"]==true
  &&r.value("process_group_established",false)&&r.value("waitpid_joined",false)&&r.value("process_group_absent",false);
}
int main(int argc,char**argv){
 try{
  std::string state,socket_name="hepta_phone_local_v150";
  for(int i=1;i<argc;i++){std::string a=argv[i];require(i+1<argc,"missing_argument_value");std::string v=argv[++i];if(a=="--state-dir")state=v;else if(a=="--socket-name")socket_name=v;
#ifdef HEPTA_TESTING
   else if(a=="--fixture-uid")fixture_uid=(uid_t)std::stoul(v);else if(a=="--fixture-shell")shell_path=v;
#endif
   else throw std::runtime_error("unknown_argument");}
  require(!state.empty()&&state[0]=='/'&&socket_name.size()<100,"invalid_server_configuration");
  umask(0077);if(mkdir(state.c_str(),0700)&&errno!=EEXIST)throw std::runtime_error("state_directory_create_failed");
  int base=open(state.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);require(base>=0,"state_directory_invalid");
  struct stat bst{};require(fstat(base,&bst)==0&&bst.st_uid==geteuid()&&(bst.st_mode&0077)==0,"state_directory_owner_or_mode_invalid");
  char*canonical_raw=realpath(state.c_str(),nullptr);require(canonical_raw!=nullptr,"state_canonical_path_unavailable");std::string canonical=canonical_raw;free(canonical_raw);
  int canonical_fd=open(canonical.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);struct stat cst{};require(canonical_fd>=0&&fstat(canonical_fd,&cst)==0&&bst.st_dev==cst.st_dev&&bst.st_ino==cst.st_ino,"state_canonical_identity_mismatch");close(canonical_fd);
  std::string parent=canonical.substr(0,canonical.find_last_of('/'));if(parent.empty())parent="/";int parent_fd=open(parent.c_str(),O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);require(parent_fd>=0&&fsync(parent_fd)==0,"state_parent_sync_failed");close(parent_fd);
  int lease=openat(base,"server.lock",O_WRONLY|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);require(lease>=0&&flock(lease,LOCK_EX|LOCK_NB)==0,"state_directory_in_use");
  require(mkdirat(base,"actions",0700)==0||errno==EEXIST,"actions_directory_create_failed");actions_fd=openat(base,"actions",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);require(actions_fd>=0,"actions_directory_invalid");
  struct stat ast{};require(fstat(actions_fd,&ast)==0&&ast.st_uid==geteuid()&&(ast.st_mode&0077)==0,"actions_directory_owner_or_mode_invalid");require(fsync(actions_fd)==0&&fsync(base)==0,"actions_parent_sync_failed");
  instance=digest(std::to_string(now_ms())+":"+std::to_string(getpid())+":"+state).substr(0,32);
  DIR*ad=fdopendir(dup(actions_fd));require(ad!=nullptr,"actions_scan_failed");
  while(auto ent=readdir(ad)){std::string id=ent->d_name;if(!hexstr(id,32))continue;try{auto x=inspect_action(id,"",false,false);if(!safe_execution_terminal(x.at("receipt")))recovery_required=true;}catch(...){recovery_required=true;}}
  closedir(ad);require(prctl(PR_SET_CHILD_SUBREAPER,1,0,0,0)==0,"subreaper_setup_failed");
  signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_signal);signal(SIGINT,stop_signal);
  int ls=socket(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0);require(ls>=0,"socket_create_failed");
  struct sockaddr_un un{};un.sun_family=AF_UNIX;memcpy(un.sun_path+1,socket_name.data(),socket_name.size());
  require(bind(ls,(struct sockaddr*)&un,offsetof(struct sockaddr_un,sun_path)+1+socket_name.size())==0,"socket_bind_failed");require(listen(ls,16)==0,"socket_listen_failed");
  std::cout<<J({{"state",recovery_required?"recovery_required":"ready"},{"protocol","hepta_phone_local_v150"},{"server_instance",instance}}).dump()<<std::endl;
  while(!stopping){struct pollfd p{ls,POLLIN,0};if(poll(&p,1,100)<=0)continue;int fd=accept4(ls,nullptr,nullptr,SOCK_CLOEXEC);if(fd<0)continue;if(workers.load()>=16){close(fd);continue;}workers++;std::thread(connection,fd).detach();}
  close(ls);for(int i=0;i<700&&workers.load();i++)usleep(10000);if(workers.load())_exit(2);close(actions_fd);close(lease);close(base);return 0;
 }catch(const std::exception&e){std::cerr<<J({{"state","failed"},{"error",e.what()}}).dump()<<std::endl;return 1;}
}
