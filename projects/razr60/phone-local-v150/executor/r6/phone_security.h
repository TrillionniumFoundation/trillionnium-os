// r6 security boundary: exact SELinux contexts, never UID-only authorization.
#pragma once
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#ifndef SO_PEERSEC
#define SO_PEERSEC 31
#endif
namespace phone_security {
constexpr const char* PARENT_CONTEXT="u:r:trillionnium_owner_open_phone_executor:s0";
constexpr const char* WORKER_CONTEXT="u:r:trillionnium_owner_open_phone_worker:s0";
constexpr const char* BOOTSTRAP_CONTEXT="u:r:trillionnium_owner_open_bootstrap:s0";
constexpr const char* OPERATOR_CONTEXT="u:r:magisk:s0";
constexpr const char* DEFAULT_SOCKET="hepta_phone_executor_v150_r6";
#ifndef HEPTA_WORKER_ENTRY
#define HEPTA_WORKER_ENTRY "/data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-worker-r6"
#endif
constexpr const char* WORKER_ENTRY=HEPTA_WORKER_ENTRY;
inline std::string exact_context(std::string s){
 while(!s.empty()&&(s.back()=='\0'||s.back()=='\n'))s.pop_back();
 if(s.empty()||s.size()>4096||s.find('\0')!=std::string::npos||s.find('\n')!=std::string::npos)throw std::runtime_error("invalid_security_context");
 return s;
}
inline std::string own_context(){
 int f=open("/proc/self/attr/current",O_RDONLY|O_CLOEXEC);
 if(f<0)throw std::runtime_error("own_security_context_unavailable");
 char b[4097];ssize_t n;
 do{n=read(f,b,sizeof(b));}while(n<0&&errno==EINTR);close(f);
 if(n<=0||n>=static_cast<ssize_t>(sizeof(b)))throw std::runtime_error("own_security_context_invalid");
 return exact_context(std::string(b,static_cast<size_t>(n)));
}
inline std::string peer_context(int fd){
 char b[4097];socklen_t n=4096;
 if(getsockopt(fd,SOL_SOCKET,SO_PEERSEC,b,&n)!=0||n==0||n>4096)throw std::runtime_error("peer_security_context_unavailable");
 return exact_context(std::string(b,n));
}
inline bool read_operation_allowed(uid_t uid,const std::string& context){
 return uid==0&&(context==BOOTSTRAP_CONTEXT||context==OPERATOR_CONTEXT);
}
inline bool execute_allowed(uid_t uid,const std::string& context){
 return uid==0&&context==BOOTSTRAP_CONTEXT;
}
inline bool globally_enforcing(){
 int f=open("/sys/fs/selinux/enforce",O_RDONLY|O_CLOEXEC);
 if(f<0)return false;char c=0;ssize_t n=read(f,&c,1);close(f);return n==1&&c=='1';
}
}
