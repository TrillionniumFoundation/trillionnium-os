#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../parent-death-guard.h"

static int checks;
static void require(bool value,const char *name){
    checks++;
    if(!value){fprintf(stderr,"FAIL: %s\n",name);exit(1);}
}
static long long now_ms(void){
    struct timespec value;
    if(clock_gettime(CLOCK_MONOTONIC,&value)!=0)exit(2);
    return (long long)value.tv_sec*1000+value.tv_nsec/1000000;
}
static bool wait_bounded(pid_t pid,int *status,int limit_ms){
    long long deadline=now_ms()+limit_ms;
    do{
        pid_t observed=waitpid(pid,status,WNOHANG);
        if(observed==pid)return true;
        if(observed<0&&errno!=EINTR)return false;
        struct timespec delay={.tv_sec=0,.tv_nsec=10000000};
        nanosleep(&delay,NULL);
    }while(now_ms()<deadline);
    return false;
}
static bool read_bounded(int fd,void *value,size_t size,int limit_ms){
    unsigned char *next=value;
    long long deadline=now_ms()+limit_ms;
    while(size){
        long long left=deadline-now_ms();
        if(left<=0)return false;
        struct pollfd event={.fd=fd,.events=POLLIN};
        int ready=poll(&event,1,(int)left);
        if(ready<0&&errno==EINTR)continue;
        if(ready<=0)return false;
        ssize_t n=read(fd,next,size);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return false;
        next+=n;size-=(size_t)n;
    }
    return true;
}
static bool write_all(int fd,const void *value,size_t size){
    const unsigned char *next=value;
    while(size){
        ssize_t n=write(fd,next,size);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return false;
        next+=n;size-=(size_t)n;
    }
    return true;
}
static void stop_owned(pid_t pid,bool reaped){
    if(pid>0&&!reaped){int status;kill(pid,SIGKILL);(void)wait_bounded(pid,&status,3000);}
}

static void argument_contract(void){
    char *good[]={"runner","--expected-parent-pid","1234","--mode","llm",NULL};
    int count=5;pid_t parent=0;
    require(hepta_take_expected_parent(&count,good,&parent)==0,"valid parent argument");
    require(count==3&&parent==1234&&!strcmp(good[1],"--mode")&&!strcmp(good[2],"llm")&&good[3]==NULL,"only adapter argument removed");
    const char *invalid[]={"","0","1","-2","+2"," 2","2 ","2x","2147483648","9999999999999999999999999"};
    for(size_t i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++){
        char *args[]={"runner","--expected-parent-pid",(char *)invalid[i],"--mode","llm",NULL};
        count=5;parent=0;
        require(hepta_take_expected_parent(&count,args,&parent)<0&&count==5,"invalid PID refused before argv mutation");
    }
    char *missing[]={"runner","--mode","llm",NULL};count=3;
    require(hepta_take_expected_parent(&count,missing,&parent)<0,"missing parent refused");
    char *duplicate[]={"runner","--expected-parent-pid","1234","--expected-parent-pid","1234",NULL};count=5;
    require(hepta_take_expected_parent(&count,duplicate,&parent)<0,"duplicate parent refused");
}

static void wrong_parent_contract(void){
    pid_t child=fork();require(child>=0,"fork wrong-parent child");
    if(child==0){
        alarm(5);
        int rc=hepta_arm_parent_death_guard(getpid());
        int failure=errno,installed=-1;
        if(prctl(PR_GET_PDEATHSIG,&installed,0UL,0UL,0UL)!=0)_exit(81);
        _exit(rc<0&&failure==ESRCH&&installed==0?0:82);
    }
    int status=0;bool reaped=wait_bounded(child,&status,3000);
    stop_owned(child,reaped);
    require(reaped&&WIFEXITED(status)&&WEXITSTATUS(status)==0,"wrong parent rejected before guard setup");
}

struct ready_message {pid_t worker;pid_t expected;int armed;};

/* The test process becomes the orphan's subreaper so SIGKILL is observed with waitpid. */
static bool parent_death_contract(bool dies_before_arm){
    int ready[2],parent_control[2],worker_control[2];
    if(pipe(ready)||pipe(parent_control)||pipe(worker_control))return false;
    pid_t parent=fork();
    if(parent<0)return false;
    if(parent==0){
        alarm(10);
        close(ready[0]);close(parent_control[1]);close(worker_control[1]);
        pid_t expected=getpid(),worker=fork();
        if(worker<0)_exit(83);
        if(worker==0){
            alarm(8);close(parent_control[0]);
            struct ready_message message={.worker=getpid(),.expected=expected,.armed=0};
            if(dies_before_arm){
                if(!write_all(ready[1],&message,sizeof(message)))_exit(84);
                close(ready[1]);
                char command=0;
                if(!read_bounded(worker_control[0],&command,1,6000)||command!='A')_exit(85);
                int rc=hepta_arm_parent_death_guard(expected);
                _exit(rc<0&&errno==ESRCH?0:86);
            }
            close(worker_control[0]);
            if(hepta_arm_parent_death_guard(expected)!=0)_exit(87);
            message.armed=1;
            if(!write_all(ready[1],&message,sizeof(message)))_exit(88);
            close(ready[1]);
            for(;;)pause();
        }
        close(ready[1]);close(worker_control[0]);
        char command=0;
        if(!read_bounded(parent_control[0],&command,1,6000)||command!='X')_exit(89);
        _exit(0); /* A controlled parent exit, never a signal sent directly to its worker. */
    }
    close(ready[1]);close(parent_control[0]);close(worker_control[0]);
    pid_t worker=-1;bool parent_reaped=false,worker_reaped=false,ok=false;int status=0;
    struct ready_message message={0};
    if(!read_bounded(ready[0],&message,sizeof(message),3000))goto finished;
    if(message.worker<=1||message.worker==getpid()||message.worker==parent||message.expected!=parent
            ||message.armed!=(dies_before_arm?0:1))goto finished;
    worker=message.worker;
    if(!write_all(parent_control[1],"X",1))goto finished;
    parent_reaped=wait_bounded(parent,&status,3000);
    if(!parent_reaped||!WIFEXITED(status)||WEXITSTATUS(status)!=0)goto finished;
    if(dies_before_arm&&!write_all(worker_control[1],"A",1))goto finished;
    worker_reaped=wait_bounded(worker,&status,3000);
    ok=worker_reaped&&(dies_before_arm?(WIFEXITED(status)&&WEXITSTATUS(status)==0)
                                     :(WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL));
finished:
    close(ready[0]);close(parent_control[1]);close(worker_control[1]);
    stop_owned(parent,parent_reaped);stop_owned(worker,worker_reaped);
    return ok;
}

int main(void){
    /* Failed readiness should report a failure rather than terminate the test writer with SIGPIPE. */
    require(signal(SIGPIPE,SIG_IGN)!=SIG_ERR,"ignore test pipe SIGPIPE");
    int previous_subreaper=0;
    require(prctl(PR_GET_CHILD_SUBREAPER,&previous_subreaper,0UL,0UL,0UL)==0,"read subreaper state");
    require(prctl(PR_SET_CHILD_SUBREAPER,1UL,0UL,0UL,0UL)==0,"enable test subreaper");
    argument_contract();
    wrong_parent_contract();
    require(parent_death_contract(false),"armed worker exits by SIGKILL when its expected parent exits");
    require(parent_death_contract(true),"parent death before arming is refused without SDK work");
    require(prctl(PR_SET_CHILD_SUBREAPER,(unsigned long)previous_subreaper,0UL,0UL,0UL)==0,"restore subreaper state");
    printf("{\"all_pass\":true,\"assertions\":%d,\"android_or_phone_tested\":false,\"scope\":\"linux_parent_death_guard\"}\n",checks);
    return 0;
}
