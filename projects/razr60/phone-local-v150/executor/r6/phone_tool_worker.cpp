// Dedicated r6 worker entry. exec transition, credentials and group identity are
// checked before the parent receives its first success handshake. No extra fork.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "phone_security.h"
#include <climits>
#include <csignal>
#include <cstdlib>
#include <grp.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <cstdio>
#include <string>
static int number(const char*s){
 if(!s||!*s)return -1;char*end=nullptr;errno=0;long n=strtol(s,&end,10);
 return errno||!end||*end||n<0||n>INT_MAX?-1:static_cast<int>(n);
}
static void fail(const char*message){
 (void)write(2,message,strlen(message));_exit(125);
}
int main(int argc,char**argv){
 int started=-1,parent=-1;const char*command=nullptr;
#ifdef HEPTA_TESTING
 std::string fixture_context="host_fixture_worker";
#endif
 if(argc<7||argc%2!=1)fail("hepta_worker_arguments_invalid\n");
 for(int i=1;i<argc;i+=2){
  const std::string key=argv[i];
  if(key=="--started-fd"&&started==-1)started=number(argv[i+1]);
  else if(key=="--expected-parent"&&parent==-1)parent=number(argv[i+1]);
  else if(key=="--command"&&command==nullptr)command=argv[i+1];
#ifdef HEPTA_TESTING
  else if(key=="--fixture-context")fixture_context=argv[i+1];
#endif
  else fail("hepta_worker_arguments_invalid\n");
 }
 if(started<3||parent<=1||!command||!*command||strlen(command)>131072)fail("hepta_worker_arguments_invalid\n");
 uid_t ru,eu,su;gid_t rg,eg,sg;
 if(getresuid(&ru,&eu,&su)||getresgid(&rg,&eg,&sg))fail("hepta_worker_credentials_unavailable\n");
#ifndef HEPTA_TESTING
 if(ru!=2000||eu!=2000||su!=2000||rg!=2000||eg!=2000||sg!=2000||getgroups(0,nullptr)!=0)fail("hepta_worker_credentials_invalid\n");
#else
 if(ru!=eu||eu!=su||rg!=eg||eg!=sg)fail("hepta_fixture_credentials_invalid\n");
#endif
 if(getpid()!=getpgrp()||getsid(0)!=getpid()||getppid()!=parent)fail("hepta_worker_group_identity_invalid\n");
 struct stat st{};
 if(fstat(started,&st)||!S_ISFIFO(st.st_mode))fail("hepta_worker_handshake_fd_invalid\n");
 try{
#ifndef HEPTA_TESTING
  if(phone_security::own_context()!=phone_security::WORKER_CONTEXT)fail("hepta_worker_domain_invalid\n");
  if(!phone_security::globally_enforcing())fail("hepta_worker_selinux_not_enforcing\n");
  if(prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=0)fail("hepta_worker_no_new_privs_invalid\n");
#else
  if(fixture_context!="host_fixture_worker")fail("hepta_fixture_worker_domain_invalid\n");
#endif
 }catch(...){fail("hepta_worker_domain_unavailable\n");}
 if(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)!=0||getppid()!=parent)fail("hepta_worker_parent_identity_lost\n");
 const char s='S';if(write(started,&s,1)!=1)_exit(126);close(started);
#ifndef HEPTA_TESTING
 execl("/system/bin/sh","/system/bin/sh","-c",command,(char*)nullptr);
#else
 execl("/bin/sh","/bin/sh","-c",command,(char*)nullptr);
#endif
 fail("hepta_worker_shell_exec_failed\n");
}
