from pathlib import Path
import hashlib,json,subprocess
B=Path('/operator-workspace/pocket4/executor-r6-candidate-source03')
O=Path('/operator-workspace/razr60/runtime/executor-r6-cleanup-mock-03');O.mkdir(parents=True,exist_ok=False)
s=(B/'phone_tool_sidecar.cpp').read_text()
guard=next(l for l in s.splitlines() if l.startswith('struct ChildGuard '))
signal=next(l for l in s.splitlines() if l.startswith('static void signal_owned('))
prefix=r'''#include <csignal>
#include <cerrno>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>
#include <utility>
#include <iostream>
static std::vector<std::pair<pid_t,int>> signals;
static int mock_kill(pid_t p,int s){signals.emplace_back(p,s);return 0;}
static pid_t mock_waitpid(pid_t p,int*,int){return p;}
static int mock_usleep(useconds_t){return 0;}
static void reap_group(pid_t){}
#define kill mock_kill
#define waitpid mock_waitpid
#define usleep mock_usleep
'''
suffix=r'''
static int passed=0,total=0;
static void verify(const char*name,const std::vector<std::pair<pid_t,int>>&expected){
 total++;const bool ok=signals==expected;if(ok)passed++;std::cout<<name<<": "<<(ok?"PASS":"FAIL")<<"\n";
}
static void guard_case(const char*name,bool j,bool g,bool lost,bool dismissed,std::vector<std::pair<pid_t,int>> expected){
 signals.clear();{ChildGuard x{424242,j,g,lost};x.dismissed=dismissed;}verify(name,expected);
}
int main(){
 guard_case("joined-without-group-never-signals-PID",true,false,false,false,{});
 guard_case("joined-proven-group-only-signals-group",true,true,false,false,{{-424242,SIGKILL}});
 guard_case("unjoined-owned-child-cleans-possible-group-and-PID",false,false,false,false,{{-424242,SIGKILL},{424242,SIGKILL}});
 guard_case("lost-wait-without-group-never-signals-PID",false,false,true,false,{});
 guard_case("lost-wait-proven-group-only-signals-group",false,true,true,false,{{-424242,SIGKILL}});
 guard_case("dismissed-never-signals",true,true,false,true,{});
 signals.clear();signal_owned(424242,SIGTERM,false,true,false);verify("loop-joined-no-PID-signal",{});
 signals.clear();signal_owned(424242,SIGKILL,false,false,true);verify("loop-lost-wait-no-PID-signal",{});
 signals.clear();signal_owned(424242,SIGKILL,true,true,false);verify("loop-proven-group-signal",{{-424242,SIGKILL}});
 return passed==total?0:1;
}
'''
cpp=prefix+guard+'\n'+signal+'\n'+suffix;(O/'cleanup-mock.cpp').write_text(cpp)
c=subprocess.run(['/usr/bin/c++','-std=c++17','-O1',str(O/'cleanup-mock.cpp'),'-o',str(O/'cleanup-mock')],capture_output=True,timeout=30)
(O/'compile.stdout').write_bytes(c.stdout);(O/'compile.stderr').write_bytes(c.stderr)
if c.returncode:raise RuntimeError(c.stderr.decode())
r=subprocess.run([str(O/'cleanup-mock')],capture_output=True,timeout=5)
(O/'run.stdout').write_bytes(r.stdout);(O/'run.stderr').write_bytes(r.stderr)
R={'schema':'hepta.executor-r6-cleanup-targeted-mock.v1','scope':'Exact current production cleanup code extracted and executed with syscall mocks; zero OS signals/process actions. Tests only joined/lost-wait identity guards, not Android SELinux.','status':'PASS' if r.returncode==0 else 'FAILED','checks':9,'source_sha256':hashlib.sha256(s.encode()).hexdigest(),'extracted_code_sha256':hashlib.sha256((guard+'\n'+signal).encode()).hexdigest(),'compile_rc':c.returncode,'run_rc':r.returncode,'output':r.stdout.decode(),'phone_operations':0,'actual_signals_sent':0}
(O/'RESULT.json').write_text(json.dumps(R,indent=2)+'\n');print(json.dumps(R,indent=2));raise SystemExit(r.returncode)
