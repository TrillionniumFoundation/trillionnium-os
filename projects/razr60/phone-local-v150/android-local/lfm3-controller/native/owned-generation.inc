/* App-owned warm generation containment. Included after the fixed native
 * input/publication helpers. No SDK call is made by the cleanup entry point.
 *
 * Signals use the very same opened /proc/PID directory FD used by openat
 * identity reads. There is no numeric-PID or group TERM/KILL fallback.
 * A separate kill(-bound_pgid, 0) existence query never delivers a signal.
 * Scope is the pinned SDK's inheriting fork/exec behavior, not escaped sessions.
 */
#ifndef HEPTA_OWNED_GENERATION_H
#define HEPTA_OWNED_GENERATION_H
#include <dirent.h>
#include <poll.h>
#include <sys/syscall.h>

#define HG_LIMIT 64
#define HG_PROC_LIMIT 8192
#define HG_PRESENCE_LIMIT 128
#define HG_ID_LIMIT 2048
#define HG_ENV_LIMIT 65536
#define HG_BUDGET_NS UINT64_C(4000000000)
#define HG_TERM_NS UINT64_C(1500000000)
#define HG_EMPTY_NS UINT64_C(100000000)
static const char *hg_env_keys[] = {
    "HEPTA_WORKER_SCOPE_REQUIRED", "HEPTA_WORKER_SCOPE_TASK",
    "HEPTA_WORKER_SCOPE_GENERATION", "HEPTA_WORKER_SCOPE_TOKEN",
    "HEPTA_WORKER_SCOPE_PARENT_START", "HEPTA_WORKER_SCOPE_BOOT"
};
typedef struct {
    char task[33],generation[33],token[33],boot[37];
    unsigned long uid;
    long app_pid,leader_pid,pgid;
    uint64_t app_start,leader_start;
} HgIdentity;
typedef struct {
    int fd; long pid,ppid,pgid; unsigned long uid;
    uint64_t start; char state;
#ifdef HEPTA_OWNED_GENERATION_HOST_TRACE
    bool trace_stat_valid,trace_uid_parsed,trace_uid_equal;
    bool trace_read_seen[4],trace_read_failed[4];
    int trace_read_errno[4];unsigned long trace_uids[4];
#endif
} HgProcess;
typedef struct {
    long pid; uint64_t start; int term_error,kill_error;
    bool term_attempted,kill_attempted;
} HgTarget;
typedef struct {
    long pgid;uint64_t observed;int result,error;
} HgPresence;

typedef struct {
    HgProcess members[HG_LIMIT];size_t count;
    int unknown,escaped,older_unrelated;bool complete;
} HgScan;


/* Host-fixture diagnostics only. Production/phone builds do not define this
 * macro; all HG_TRACE_* statements then preprocess to nothing. No signal,
 * process read, guard, deadline or return value is supplied by this logger. */
#ifdef HEPTA_OWNED_GENERATION_HOST_TRACE
enum { HG_TRACE_STAT=0, HG_TRACE_UID=1, HG_TRACE_ENV=2, HG_TRACE_ARGV=3 };
#define HG_TRACE_BEGIN_STAT(p) do { \
    (p)->trace_stat_valid=false;(p)->trace_uid_parsed=false;(p)->trace_uid_equal=false; \
    memset((p)->trace_read_seen,0,sizeof((p)->trace_read_seen)); \
    memset((p)->trace_read_failed,0,sizeof((p)->trace_read_failed)); \
    memset((p)->trace_read_errno,0,sizeof((p)->trace_read_errno)); \
    memset((p)->trace_uids,0,sizeof((p)->trace_uids)); \
} while(0);
#define HG_TRACE_STAT_PARSED(p) do { (p)->trace_stat_valid=true; } while(0);
#define HG_TRACE_UID_TUPLE(p,v,parsed) do { \
    (p)->trace_uid_parsed=(parsed); \
    if(parsed){memcpy((p)->trace_uids,(v),sizeof((p)->trace_uids)); \
        (p)->trace_uid_equal=(v)[0]==(v)[1]&&(v)[0]==(v)[2]&&(v)[0]==(v)[3];} \
} while(0);
static int hg_trace_read_result(HgProcess *p,int field,int result) {
    int saved=errno;
    p->trace_read_seen[field]=true;p->trace_read_failed[field]=result!=0;p->trace_read_errno[field]=result==0?0:saved;
    errno=saved;return result;
}
#define HG_TRACE_READ(p,field,expression) hg_trace_read_result((p),(field),(expression))
static void hg_trace_unknown(const HgProcess *p,const char *reason,
        const char *stage,const char *kind,int failure_errno) {
    int saved=errno;
    static unsigned records=0,bytes=0;static bool capped=false;
    char row[640],identity[192],uid[192];
    if(p&&p->trace_stat_valid)
        snprintf(identity,sizeof(identity),"\"pid\":%ld,\"stat_valid\":true,\"start_ticks\":%" PRIu64 ",\"pgid\":%ld",
                 p->pid,p->start,p->pgid);
    else if(p)snprintf(identity,sizeof(identity),"\"pid\":%ld,\"stat_valid\":false,\"start_ticks\":null,\"pgid\":null",p->pid);
    else snprintf(identity,sizeof(identity),"\"pid\":null,\"stat_valid\":false,\"start_ticks\":null,\"pgid\":null");
    if(p&&p->trace_uid_parsed)
        snprintf(uid,sizeof(uid),"\"uid_parse_valid\":true,\"uid_values\":[%lu,%lu,%lu,%lu],\"uid_all_equal\":%s",
                 p->trace_uids[0],p->trace_uids[1],p->trace_uids[2],p->trace_uids[3],p->trace_uid_equal?"true":"false");
    else snprintf(uid,sizeof(uid),"\"uid_parse_valid\":false,\"uid_values\":null,\"uid_all_equal\":null");
    int n=snprintf(row,sizeof(row),"HEPTA_HOST_PROC_REJECTION {\"reason\":\"%s\",\"stage\":\"%s\",\"kind\":\"%s\",\"errno\":%d,%s,%s}\n",
                   reason,stage,kind,failure_errno,identity,uid);
    if(n<0||(size_t)n>=sizeof(row)){errno=saved;return;}
    /* Reserve space for one explicit truncation marker. Counts include every
     * attempted output byte, even if the host capture stream itself fails. */
    if(records>=64||bytes+(unsigned)n>16256){
        if(!capped){
            static const char marker[]="HEPTA_HOST_PROC_REJECTION {\"trace_truncated\":true,\"record_limit\":64,\"byte_limit\":16384}\n";
            capped=true;
            if(bytes+sizeof(marker)-1<=16384){fwrite(marker,1,sizeof(marker)-1,stderr);bytes+=(unsigned)sizeof(marker)-1;}
        }
        errno=saved;return;
    }
    records++;bytes+=(unsigned)n;fwrite(row,1,(size_t)n,stderr);errno=saved;
}
static void hg_trace_proc_failure(HgProcess *p,const char *reason,int field) {
    int saved=errno;
    const char *stage=field==HG_TRACE_STAT?"proc_stat":field==HG_TRACE_UID?"proc_status_uid":
                       field==HG_TRACE_ENV?"proc_environ":"proc_cmdline";
    const char *kind=p->trace_read_seen[field]&&p->trace_read_failed[field]?"read_error":"parse_error";
    int error=p->trace_read_seen[field]?p->trace_read_errno[field]:0;
    if(field==HG_TRACE_UID&&p->trace_uid_parsed&&!p->trace_uid_equal){kind="uid_values_differ";error=0;}
    hg_trace_unknown(p,reason,stage,kind,error);errno=saved;
}
static void hg_trace_recheck_failure(HgProcess *p) {
    int saved=errno;
    if(!p->trace_stat_valid)hg_trace_proc_failure(p,"older_identity_recheck",HG_TRACE_STAT);
    else if(!p->trace_uid_parsed||!p->trace_uid_equal||p->trace_read_failed[HG_TRACE_UID])
        hg_trace_proc_failure(p,"older_identity_recheck",HG_TRACE_UID);
    else hg_trace_unknown(p,"older_identity_changed","scope_check","policy_refusal",0);
    errno=saved;
}
#define HG_TRACE_RECHECK_FAILURE(p) hg_trace_recheck_failure((p));
#define HG_TRACE_OPEN_FAILURE(p,error) hg_trace_unknown((p),"process_open","proc_directory","read_error",(error));
#define HG_TRACE_DIRECTORY_FAILURE(stage,error) hg_trace_unknown(NULL,"proc_enumeration",(stage),"read_error",(error));
#define HG_TRACE_PROC_FAILURE(p,reason,field) hg_trace_proc_failure((p),(reason),(field));
#define HG_TRACE_POLICY(p,reason) hg_trace_unknown((p),(reason),"scope_check","policy_refusal",0);
#define HG_TRACE_SCOPE_FAILURE(p,env_ok,argv_ok) do { \
    if(!(env_ok))hg_trace_proc_failure((p),"scope_visibility",HG_TRACE_ENV); \
    else if(!(argv_ok))hg_trace_proc_failure((p),"scope_visibility",HG_TRACE_ARGV); \
    else hg_trace_unknown((p),"same_group_scope_mismatch","scope_check","policy_refusal",0); \
} while(0);
#else
#define HG_TRACE_RECHECK_FAILURE(p)
#define HG_TRACE_BEGIN_STAT(p)
#define HG_TRACE_STAT_PARSED(p)
#define HG_TRACE_UID_TUPLE(p,v,parsed)
#define HG_TRACE_READ(p,field,expression) expression
#define HG_TRACE_OPEN_FAILURE(p,error)
#define HG_TRACE_DIRECTORY_FAILURE(stage,error)
#define HG_TRACE_PROC_FAILURE(p,reason,field)
#define HG_TRACE_POLICY(p,reason)
#define HG_TRACE_SCOPE_FAILURE(p,env_ok,argv_ok)
#endif

static uint64_t hg_now(void) {
    struct timespec t;
    if(clock_gettime(CLOCK_MONOTONIC,&t)!=0||t.tv_sec<0)return 0;
    return (uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
}
static bool hg_decimal(const char *s,uint64_t max,uint64_t *value) {
    if(!s||!*s||strlen(s)>20||(s[0]=='0'&&s[1]))return false;
    uint64_t n=0;
    for(const unsigned char *p=(const unsigned char*)s;*p;p++){
        if(*p<'0'||*p>'9'||n>(max-(uint64_t)(*p-'0'))/10)return false;
        n=n*10+(uint64_t)(*p-'0');
    }
    *value=n;return true;
}
static bool hg_uuid(const char *s) {
    if(!s||strlen(s)!=36)return false;
    for(int i=0;i<36;i++){
        if(i==8||i==13||i==18||i==23){if(s[i]!='-')return false;}
        else if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
    }
    return true;
}
static int hg_read_at(int dir,const char *name,unsigned char *buf,size_t bound,size_t *used) {
    int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return -1;
    size_t n=0;int saved=0;
    while(n<bound){
        ssize_t got=read(fd,buf+n,bound-n);
        if(got<0&&errno==EINTR)continue;
        if(got<0){saved=errno;break;}
        if(!got)break;
        n+=(size_t)got;
    }
    if(!saved&&n==bound){unsigned char extra;ssize_t got;
        do{got=read(fd,&extra,1);}while(got<0&&errno==EINTR);
        if(got!=0)saved=got<0?errno:EOVERFLOW;
    }
    if(close(fd)!=0&&!saved)saved=errno;
    if(saved){errno=saved;return -1;}
    buf[n]=0;*used=n;return 0;
}
static bool hg_boot(char out[37]) {
    unsigned char b[80];size_t n=0;
    if(hg_read_at(AT_FDCWD,"/proc/sys/kernel/random/boot_id",b,79,&n)!=0||n!=37||b[36]!='\n')return false;
    b[36]=0;if(!hg_uuid((char*)b))return false;
    memcpy(out,b,37);return true;
}
static bool hg_proc_stat(HgProcess *p) {
    HG_TRACE_BEGIN_STAT(p)
    unsigned char b[8193];size_t n=0;
    if(HG_TRACE_READ(p,HG_TRACE_STAT,hg_read_at(p->fd,"stat",b,8192,&n))!=0||!n||memchr(b,0,n))return false;
    char *end=strrchr((char*)b,')'),*first=strchr((char*)b,' ');
    if(!end||!first||first>=end||end[1]!=' ')return false;
    *first=0;uint64_t pid;
    if(!hg_decimal((char*)b,INT_MAX,&pid)||pid<=1||pid!=(uint64_t)p->pid)return false;
    char *save=NULL,*part=strtok_r(end+2," \n",&save);int index=0;
    uint64_t pp=0,pg=0,start=0;char state=0;
    while(part&&index<=19){
        if(index==0){if(strlen(part)!=1)return false;state=part[0];}
        else if(index==1){if(!hg_decimal(part,INT_MAX,&pp))return false;}
        else if(index==2){if(!hg_decimal(part,INT_MAX,&pg))return false;}
        else if(index==19){if(!hg_decimal(part,UINT64_MAX,&start)||!start)return false;}
        index++;part=strtok_r(NULL," \n",&save);
    }
    if(index!=20)return false;
    p->ppid=(long)pp;p->pgid=(long)pg;p->start=start;p->state=state;
    HG_TRACE_STAT_PARSED(p)
    return true;
}
static bool hg_proc_uid(HgProcess *p) {
    unsigned char b[16385];size_t n=0;
    if(HG_TRACE_READ(p,HG_TRACE_UID,hg_read_at(p->fd,"status",b,16384,&n))!=0||!n||memchr(b,0,n))return false;
    char *line=(char*)b;int count=0;unsigned long values[4]={0};
    while(line&&*line){
        char *next=strchr(line,'\n');if(next)*next++=0;
        if(!strncmp(line,"Uid:",4)){
            char extra;
            if(sscanf(line+4,"%lu %lu %lu %lu %c",&values[0],&values[1],&values[2],&values[3],&extra)!=4)return false;
            count++;
        }
        line=next;
    }
    HG_TRACE_UID_TUPLE(p,values,count==1)
    if(count!=1||values[0]!=values[1]||values[0]!=values[2]||values[0]!=values[3])return false;
    p->uid=values[0];return true;
}
static int hg_open_process(long pid,HgProcess *p) {
    char path[64];memset(p,0,sizeof(*p));p->fd=-1;p->pid=pid;
    if(pid<=1||snprintf(path,sizeof(path),"/proc/%ld",pid)>=(int)sizeof(path)){errno=EINVAL;return -1;}
    p->fd=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    return p->fd<0?-1:0;
}
static bool hg_identity_bytes(const HgIdentity *id,char *out,size_t bound,size_t *length) {
    int n=snprintf(out,bound,"hepta.worker-generation.v1\n"
        "task_id=%s\nworker_generation=%s\nscope_token=%s\napp_uid=%lu\n"
        "app_pid=%ld\napp_start_ticks=%" PRIu64 "\nleader_pid=%ld\n"
        "leader_start_ticks=%" PRIu64 "\npgid=%ld\nboot_id=%s\n",
        id->task,id->generation,id->token,id->uid,id->app_pid,id->app_start,
        id->leader_pid,id->leader_start,id->pgid,id->boot);
    if(n<=0||(size_t)n>=bound)return false;
    *length=(size_t)n;return true;
}
static bool hg_parse_identity(const unsigned char *bytes,size_t n,HgIdentity *out) {
    if(!n||n>=HG_ID_LIMIT||memchr(bytes,0,n)||bytes[n-1]!='\n')return false;
    char text[HG_ID_LIMIT];memcpy(text,bytes,n);text[n]=0;
    const char *names[]={"task_id=","worker_generation=","scope_token=","app_uid=",
        "app_pid=","app_start_ticks=","leader_pid=","leader_start_ticks=","pgid=","boot_id="};
    char *save=NULL,*part=strtok_r(text,"\n",&save);
    if(!part||strcmp(part,"hepta.worker-generation.v1"))return false;
    memset(out,0,sizeof(*out));
    for(int i=0;i<10;i++){
        part=strtok_r(NULL,"\n",&save);size_t k=strlen(names[i]);
        if(!part||strncmp(part,names[i],k))return false;
        const char *v=part+k;uint64_t number=0;
        if(i<=2){if(!id_ok(v))return false;strcpy(i==0?out->task:i==1?out->generation:out->token,v);}
        else if(i==9){if(!hg_uuid(v))return false;strcpy(out->boot,v);}
        else{
            uint64_t max=(i==5||i==7)?UINT64_MAX:INT_MAX;
            if(!hg_decimal(v,max,&number)||!number)return false;
            if(i==3)out->uid=(unsigned long)number;
            if(i==4)out->app_pid=(long)number;
            if(i==5)out->app_start=number;
            if(i==6)out->leader_pid=(long)number;
            if(i==7)out->leader_start=number;
            if(i==8)out->pgid=(long)number;
        }
    }
    if(strtok_r(NULL,"\n",&save)||out->app_pid<=1||out->leader_pid<=1
        ||out->pgid!=out->leader_pid||out->leader_pid==out->app_pid)return false;
    char canonical_id[HG_ID_LIMIT];size_t canonical_size;
    return hg_identity_bytes(out,canonical_id,sizeof(canonical_id),&canonical_size)
        &&n==canonical_size&&!memcmp(bytes,canonical_id,n);
}
static bool hg_private_directory(const char *path) {
    struct stat s;
    return canonical(path)&&lstat(path,&s)==0&&S_ISDIR(s.st_mode)
        &&s.st_uid==getuid()&&(s.st_mode&0777)==0700;
}
static bool hg_caller(const HgIdentity *id) {
    if(getuid()!=geteuid()||(unsigned long)getuid()!=id->uid||getppid()!=id->app_pid)return false;
    char boot[37];if(!hg_boot(boot)||strcmp(boot,id->boot))return false;
    HgProcess p;bool ok=false;
    if(hg_open_process(id->app_pid,&p)==0){
        ok=hg_proc_stat(&p)&&hg_proc_uid(&p)&&p.start==id->app_start&&p.uid==id->uid;
        close(p.fd);
    }
    return ok&&getppid()==id->app_pid;
}
static bool hg_publish_bytes(const char *path,const char *nonce,const void *bytes,size_t n) {
    Destination d={.dir=-1,.fd=-1};bool ok=false;
    if(reserve_destination(&d,path,nonce))ok=write_all(d.fd,bytes,n)&&publish(&d);
    destination_close(&d);return ok;
}
static bool hepta_owned_generation_enter(const char *directory,const char *generation,
        const char *task,pid_t parent) {
    const char *required=getenv(hg_env_keys[0]);bool any=false;
    for(unsigned i=0;i<sizeof(hg_env_keys)/sizeof(hg_env_keys[0]);i++)if(getenv(hg_env_keys[i]))any=true;
    /* Historical direct-native fixtures have no app scope authority. The current
     * Java adapter always supplies all six initial-environment fields and refuses
     * cleanup without the durable identity, even if a legacy native run exits. */
    if(!any)return true;
    if(!required||strcmp(required,"v1")||!directory||!generation||!task
        ||prctl(PR_GET_DUMPABLE,0,0,0,0)!=1)return false;
    const char *t=getenv(hg_env_keys[1]),*g=getenv(hg_env_keys[2]),*token=getenv(hg_env_keys[3]);
    const char *parent_start=getenv(hg_env_keys[4]),*boot=getenv(hg_env_keys[5]);
    uint64_t start;
    if(!t||!g||!token||strcmp(t,task)||strcmp(g,generation)||!id_ok(token)
        ||!hg_decimal(parent_start,UINT64_MAX,&start)||!start||!hg_uuid(boot))return false;
    HgIdentity id={.uid=(unsigned long)getuid(),.app_pid=(long)parent,.app_start=start};
    strcpy(id.task,task);strcpy(id.generation,generation);strcpy(id.token,token);strcpy(id.boot,boot);
    if(!hg_caller(&id)||!hg_private_directory(directory))return false;
    const char *leaf=strrchr(directory,'/');
    if(!leaf||strcmp(leaf+1,generation))return false;
    long inherited=(long)getpgrp();
    if(getpid()<=1||inherited==(long)getpid()||setpgid(0,0)!=0||getpgrp()!=getpid())return false;
    HgProcess self;bool valid=false;
    if(hg_open_process((long)getpid(),&self)==0){
        valid=hg_proc_stat(&self)&&hg_proc_uid(&self)&&self.uid==id.uid
            &&self.ppid==id.app_pid&&self.pgid==(long)getpid();
        if(valid){id.leader_pid=self.pid;id.leader_start=self.start;id.pgid=self.pgid;}
        close(self.fd);
    }
    if(!valid||!hg_caller(&id))return false;
    char data[HG_ID_LIMIT],path[PATH_MAX];size_t n=0;
    if(!hg_identity_bytes(&id,data,sizeof(data),&n)
        ||snprintf(path,sizeof(path),"%s/worker-generation.identity",directory)>=(int)sizeof(path))return false;
    if(!hg_publish_bytes(path,generation,data,n))return false;
    fprintf(stderr,"HEPTA_OWNED_GENERATION published generation=%s task=%s pid=%ld start=%" PRIu64 " pgid=%ld\n",
        generation,task,id.leader_pid,id.leader_start,id.pgid);
    fflush(stderr);return true;
}
static int hg_env_value(const unsigned char *b,size_t n,const char *key,const char *expected) {
    size_t k=strlen(key),at=0;int found=0;
    while(at<n){
        const unsigned char *end=memchr(b+at,0,n-at);if(!end)return -1;
        size_t len=(size_t)(end-(b+at));
        if(len>k&&!memcmp(b+at,key,k)&&b[at+k]=='='){
            if(found++||len!=k+1+strlen(expected)||memcmp(b+at+k+1,expected,strlen(expected)))return -1;
        }
        at+=len+1;
    }
    return found;
}
static bool hg_environment(HgProcess *p,const HgIdentity *id,bool *exact,bool *tagged) {
    unsigned char b[HG_ENV_LIMIT+1];size_t n=0;*exact=false;*tagged=false;
    if(HG_TRACE_READ(p,HG_TRACE_ENV,hg_read_at(p->fd,"environ",b,HG_ENV_LIMIT,&n))!=0)return false;
    char start[32];snprintf(start,sizeof(start),"%" PRIu64,id->app_start);
    const char *values[]={"v1",id->task,id->generation,id->token,start,id->boot};
    bool all=true;
    for(unsigned i=0;i<6;i++){
        int got=hg_env_value(b,n,hg_env_keys[i],values[i]);
        if(got!=1)all=false;
        if((i==2||i==3)&&got==1)*tagged=true;
    }
    *exact=all;return true;
}
static bool hg_argv_generation(HgProcess *p,const HgIdentity *id,bool *tagged) {
    unsigned char b[HG_ENV_LIMIT+1];size_t n=0;*tagged=false;
    if(HG_TRACE_READ(p,HG_TRACE_ARGV,hg_read_at(p->fd,"cmdline",b,HG_ENV_LIMIT,&n))!=0)return false;
    size_t at=0;bool next=false;
    while(at<n){
        const unsigned char *end=memchr(b+at,0,n-at);if(!end)return false;
        size_t len=(size_t)(end-(b+at));
        if(next){if(len==32&&!memcmp(b+at,id->generation,32))*tagged=true;next=false;}
        if(len==17&&!memcmp(b+at,"--warm-generation",17))next=true;
        at+=len+1;
    }
    return true;
}
static void hg_scan_close(HgScan *s) {
    for(size_t i=0;i<s->count;i++)if(s->members[i].fd>=0)close(s->members[i].fd);
    s->count=0;
}
static HgScan hg_scan(const HgIdentity *id,uint64_t deadline) {
    HgScan scan={.complete=false};DIR *directory=opendir("/proc");
    if(!directory){HG_TRACE_DIRECTORY_FAILURE("opendir_proc",errno) scan.unknown++;return scan;}
    struct dirent *entry;unsigned visited=0;bool enumerated=false;
    for(;;){
        errno=0;entry=readdir(directory);
        if(!entry){if(errno){HG_TRACE_DIRECTORY_FAILURE("readdir_proc",errno) scan.unknown++;}else enumerated=true;break;}
        uint64_t number;
        if(!hg_decimal(entry->d_name,INT_MAX,&number)||number<=1)continue;
        if(++visited>HG_PROC_LIMIT||!hg_now()||hg_now()>=deadline){HG_TRACE_POLICY(NULL,"enumeration_bound") scan.unknown++;break;}
        HgProcess p;
        if(hg_open_process((long)number,&p)!=0){
            /* Even ENOENT after readdir is unresolved in this round. Directory
             * owner is never a real-UID proof: non-dumpable tasks appear root. */
            HG_TRACE_OPEN_FAILURE(&p,errno)
            scan.unknown++;continue;
        }
        bool stat_ok=hg_proc_stat(&p),uid_ok=hg_proc_uid(&p);
        if(!uid_ok){HG_TRACE_PROC_FAILURE(&p,"uid_unresolved",HG_TRACE_UID) scan.unknown++;close(p.fd);continue;}
        if(p.uid!=id->uid){
            if(stat_ok&&p.pgid==id->pgid){HG_TRACE_POLICY(&p,"different_uid_same_group") scan.unknown++;}
            close(p.fd);continue;
        }
        if(!stat_ok){HG_TRACE_PROC_FAILURE(&p,"stat_unresolved",HG_TRACE_STAT) scan.unknown++;close(p.fd);continue;}
        bool same_group=p.pgid==id->pgid;
        if(p.pid==id->leader_pid){HG_TRACE_POLICY(&p,"leader_still_present") scan.unknown++;close(p.fd);continue;}
        /* The exact current App and this helper are independently bound above.
         * They are outside the protected worker group and carry no worker scope. */
        if(!same_group&&((p.pid==id->app_pid&&p.start==id->app_start)
                ||p.pid==(long)getpid())){close(p.fd);continue;}
        if(!same_group&&p.start<id->leader_start){
            /* A held, unchanged process born strictly before this worker cannot
             * be its fork/exec descendant. Same-tick/newer or same-group tasks
             * receive no exclusion, and directory ownership is not used. */
            HgProcess again=p;
            if(hg_proc_stat(&again)&&hg_proc_uid(&again)&&again.pid==p.pid
                    &&again.start==p.start&&again.uid==p.uid&&again.pgid==p.pgid
                    &&again.ppid==p.ppid)scan.older_unrelated++;
            else {HG_TRACE_RECHECK_FAILURE(&again) scan.unknown++;}
            close(p.fd);continue;
        }
        bool exact=false,env_tag=false,arg_tag=false;
        bool env_ok=hg_environment(&p,id,&exact,&env_tag),argv_ok=hg_argv_generation(&p,id,&arg_tag);
        if(!same_group){
            if(!env_ok||!argv_ok){HG_TRACE_SCOPE_FAILURE(&p,env_ok,argv_ok) scan.unknown++;}
            else if(env_tag||arg_tag)scan.escaped++;
            close(p.fd);continue;
        }
        if(p.state=='Z'||p.state=='X'){
            /* Exited but not yet reaped is not full group absence. No signal. */
            HG_TRACE_POLICY(&p,"same_group_exited_not_reaped")
            scan.unknown++;close(p.fd);continue;
        }
        if(!env_ok||!argv_ok||!exact||p.start<id->leader_start||p.pid==id->app_pid
            ||p.pid==(long)getpid()||scan.count>=HG_LIMIT){HG_TRACE_SCOPE_FAILURE(&p,env_ok,argv_ok) scan.unknown++;close(p.fd);continue;}
        scan.members[scan.count++]=p;
    }
    /* readdir errno is sampled independently of the process-file operations. */
    if(enumerated&&visited<=HG_PROC_LIMIT&&hg_now()&&hg_now()<deadline)scan.complete=true;
    closedir(directory);
    return scan;
}
static bool hg_same_held_process(HgProcess *p,const HgIdentity *id) {
    HgProcess again=*p;bool exact=false,tagged=false;
    return hg_proc_stat(&again)&&hg_proc_uid(&again)&&again.pid==p->pid&&again.start==p->start
        &&again.uid==p->uid&&again.uid==id->uid&&again.pgid==p->pgid&&again.pgid==id->pgid
        &&again.state!='Z'&&again.state!='X'
        &&hg_environment(&again,id,&exact,&tagged)&&exact;
}
static int hg_pidfd_signal(int held_proc_fd,int signal_number) {
#if defined(SYS_pidfd_send_signal)
    return (int)syscall(SYS_pidfd_send_signal,held_proc_fd,signal_number,NULL,0U);
#else
    (void)held_proc_fd;(void)signal_number;errno=ENOSYS;return -1;
#endif
}
static bool hg_pidfd_supported(void) {
    HgProcess self;
    if(hg_open_process((long)getpid(),&self)!=0)return false;
    int result=hg_pidfd_signal(self.fd,0),saved=errno;close(self.fd);errno=saved;
    return result==0;
}
/* Signal zero is only an existence/permission query; it never delivers a
 * signal to the group. TERM/KILL remain exclusive held-proc-FD operations. */
static HgPresence hg_group_presence(const HgIdentity *id) {
    HgPresence p={.pgid=id->pgid,.observed=0,.result=-1,.error=EINVAL};
    if(id->pgid<=1||id->pgid!=id->leader_pid||id->pgid==(long)getpgrp())return p;
    errno=0;p.result=kill(-(pid_t)id->pgid,0);p.error=p.result==0?0:errno;
    p.observed=hg_now();return p;
}
static int hg_target_index(HgTarget *targets,size_t *count,const HgProcess *p) {
    for(size_t i=0;i<*count;i++)if(targets[i].pid==p->pid&&targets[i].start==p->start)return (int)i;
    if(*count>=HG_LIMIT)return -1;
    size_t index=(*count)++;targets[index]=(HgTarget){.pid=p->pid,.start=p->start};
    return (int)index;
}
static int hepta_owned_generation_cleanup(int argc,char **argv) {
    if(argc!=12||strcmp(argv[1],"--hepta-owned-generation-cleanup-v1")
        ||prctl(PR_GET_DUMPABLE,0,0,0,0)!=1)return 78;
    for(unsigned i=0;i<6;i++)if(getenv(hg_env_keys[i]))return 78; /* helper is not a worker */
    const char *files=argv[2],*generation=argv[3],*task=argv[4],*token=argv[5],*boot=argv[8];
    const char *expected_sha=argv[9],*nonce=argv[10];uint64_t app_pid,app_start,deadline;
    if(!id_ok(generation)||!id_ok(task)||!id_ok(token)||!id_ok(nonce)||!hg_uuid(boot)
        ||!hg_decimal(argv[6],INT_MAX,&app_pid)||app_pid<=1
        ||!hg_decimal(argv[7],UINT64_MAX,&app_start)||!app_start
        ||!hg_decimal(argv[11],UINT64_MAX,&deadline)||strlen(expected_sha)!=64)return 78;
    for(unsigned i=0;i<64;i++)if(!((expected_sha[i]>='0'&&expected_sha[i]<='9')||(expected_sha[i]>='a'&&expected_sha[i]<='f')))return 78;
    uint64_t began=hg_now();
    if(!began||deadline<=began||deadline-began>HG_BUDGET_NS)return 78;
    char runs[PATH_MAX],directory[PATH_MAX],path[PATH_MAX],receipt_path[PATH_MAX];
    if(snprintf(runs,sizeof(runs),"%s/runs",files)>=(int)sizeof(runs)
        ||snprintf(directory,sizeof(directory),"%s/%s",runs,generation)>=(int)sizeof(directory)
        ||snprintf(path,sizeof(path),"%s/worker-generation.identity",directory)>=(int)sizeof(path)
        ||snprintf(receipt_path,sizeof(receipt_path),"%s/generation-cleanup-%s.json",directory,nonce)>=(int)sizeof(receipt_path)
        ||!hg_private_directory(files)||!hg_private_directory(runs)||!hg_private_directory(directory))return 78;
    Input identity_input={.fd=-1};HgIdentity id;
    if(!read_input(&identity_input,path,HG_ID_LIMIT-1,true)){input_free(&identity_input);return 78;}
    if(!hg_parse_identity(identity_input.bytes,identity_input.size,&id)||strcmp(identity_input.digest,expected_sha)
        ||strcmp(id.task,task)||strcmp(id.generation,generation)||strcmp(id.token,token)
        ||strcmp(id.boot,boot)||id.app_pid!=(long)app_pid||id.app_start!=app_start||!hg_caller(&id)
        ||id.pgid==(long)getpgrp()||id.leader_pid==(long)getpid()
        ||hepta_arm_parent_death_guard((pid_t)app_pid)!=0){input_free(&identity_input);return 78;}
    HgProcess self;uint64_t helper_start=0;long helper_pgid=(long)getpgrp();
    if(hg_open_process((long)getpid(),&self)==0){if(hg_proc_stat(&self))helper_start=self.start;close(self.fd);}
    if(!helper_start){input_free(&identity_input);return 78;}
    bool supported=hg_pidfd_supported(),clean=false,scan_complete=false;
    int unknown=0,escaped=0,remaining=0,empty_reads=0,scans=0,term_attempts=0,kill_attempts=0,older_unrelated=0;
    uint64_t first_empty=0;HgTarget targets[HG_LIMIT]={0};size_t target_count=0;
    HgPresence presence[HG_PRESENCE_LIMIT]={0};size_t presence_count=0;
    const char *failure=supported?"deadline":"pidfd_unsupported_or_denied";
    if(supported)while(hg_now()&&hg_now()<deadline){
        if(!hg_caller(&id)||!input_unchanged(&identity_input)){failure="caller_or_identity_changed";unknown++;break;}
        HgScan scan=hg_scan(&id,deadline);scans++;scan_complete=scan.complete;
        unknown=scan.unknown;escaped=scan.escaped;remaining=(int)scan.count;older_unrelated=scan.older_unrelated;
        if(escaped){failure="escaped_generation_scope";hg_scan_close(&scan);break;}
        if(!scan.complete||unknown){
            /* No signal or empty proof from an incomplete round. A fresh
             * enumeration may omit a transient entry, but the same absolute
             * deadline is never renewed and persistent denial stays unknown. */
            failure="incomplete_process_visibility";first_empty=0;empty_reads=0;
            hg_scan_close(&scan);
            struct timespec retry={.tv_sec=0,.tv_nsec=50000000};
            while(nanosleep(&retry,&retry)<0&&errno==EINTR){if(hg_now()>=deadline)break;}
            continue;
        }
        if(!scan.count){
            if(presence_count>=HG_PRESENCE_LIMIT){
                failure="group_presence_limit";unknown++;hg_scan_close(&scan);break;
            }
            if(!hg_caller(&id)||!input_unchanged(&identity_input)||!hg_now()||hg_now()>=deadline){
                failure="group_probe_owner_or_deadline_changed";unknown++;hg_scan_close(&scan);break;
            }
            HgPresence p=hg_group_presence(&id);presence[presence_count++]=p;
            if(p.result==-1&&p.error==ESRCH&&p.observed){
                empty_reads++;
                if(!first_empty)first_empty=p.observed;
                if(empty_reads>=2&&p.observed-first_empty>=HG_EMPTY_NS){
                    clean=true;failure="none";hg_scan_close(&scan);break;
                }
            }else{
                /* A hidden same-group child still makes this kernel query
                 * report present/denied. Visible emptiness cannot release it. */
                first_empty=0;empty_reads=0;unknown++;
                failure="kernel_group_present_or_unresolved";hg_scan_close(&scan);
                struct timespec retry={.tv_sec=0,.tv_nsec=50000000};
                while(nanosleep(&retry,&retry)<0&&errno==EINTR){if(hg_now()>=deadline)break;}
                continue;
            }
        }else{
            first_empty=0;empty_reads=0;
            /* Validate every held FD and capability before any real signal in
             * this batch. A later kernel error remains an explicit partial
             * failure; earlier actual signals are never rewritten as zero. */
            bool ready=true;
            for(size_t i=0;i<scan.count;i++){
                HgProcess *p=&scan.members[i];
                if(!hg_same_held_process(p,&id)||hg_pidfd_signal(p->fd,0)!=0){ready=false;break;}
            }
            if(!ready||!hg_caller(&id)||!input_unchanged(&identity_input)||hg_now()>=deadline){
                failure="target_or_capability_changed";unknown++;hg_scan_close(&scan);break;
            }
            size_t additional=0;
            for(size_t i=0;i<scan.count;i++){
                bool seen=false;
                for(size_t j=0;j<target_count;j++)if(targets[j].pid==scan.members[i].pid
                        &&targets[j].start==scan.members[i].start)seen=true;
                if(!seen)additional++;
            }
            if(additional>HG_LIMIT-target_count){
                failure="target_limit_before_batch";unknown++;hg_scan_close(&scan);break;
            }
            int sig=hg_now()-began<HG_TERM_NS?SIGTERM:SIGKILL;
            for(size_t i=0;i<scan.count;i++){
                HgProcess *p=&scan.members[i];int at=hg_target_index(targets,&target_count,p);
                if(at<0){failure="target_limit";unknown++;break;}
                HgTarget *t=&targets[at];
                if((sig==SIGTERM&&t->term_attempted)||(sig==SIGKILL&&t->kill_attempted))continue;
                if(!hg_same_held_process(p,&id)||!hg_caller(&id)||hg_now()>=deadline){
                    failure="target_changed_before_dispatch";unknown++;break;
                }
                if(sig==SIGTERM){t->term_attempted=true;term_attempts++;}
                else{t->kill_attempted=true;kill_attempts++;}
                int result=hg_pidfd_signal(p->fd,sig),error=result==0?0:errno;
                if(sig==SIGTERM)t->term_error=error;else t->kill_error=error;
                if(error&&error!=ESRCH){failure="pidfd_signal_failed";unknown++;break;}
            }
        }
        hg_scan_close(&scan);if(unknown)break;
        struct timespec pause={.tv_sec=0,.tv_nsec=50000000};
        while(nanosleep(&pause,&pause)<0&&errno==EINTR){if(hg_now()>=deadline)break;}
    }
    uint64_t ended=hg_now();
    if(!ended||ended>deadline||!hg_caller(&id)||!input_unchanged(&identity_input)){
        clean=false;failure="deadline_or_identity_final_check";unknown++;
    }
    char *record=NULL;size_t bytes=0;FILE *f=open_memstream(&record,&bytes);
    if(!f){input_free(&identity_input);return 78;}
    fprintf(f,"{\"schema\":\"hepta.worker-generation.cleanup.v1\",\"task_id\":\"%s\","
        "\"worker_generation\":\"%s\",\"scope_token\":\"%s\",\"app_uid\":%lu,"
        "\"app_pid\":%ld,\"app_start_ticks\":%" PRIu64 ",\"leader_pid\":%ld,"
        "\"leader_start_ticks\":%" PRIu64 ",\"pgid\":%ld,\"boot_id\":\"%s\","
        "\"identity_sha256\":\"%s\",\"cleanup_nonce\":\"%s\",\"helper_pid\":%ld,"
        "\"helper_start_ticks\":%" PRIu64 ",\"helper_pgid\":%ld,\"helper_uid\":%lu,"
        "\"helper_parent_pid\":%ld,\"started_monotonic_ns\":%" PRIu64 ","
        "\"deadline_monotonic_ns\":%" PRIu64 ",\"ended_monotonic_ns\":%" PRIu64 ","
        "\"scan_complete\":%s,\"scans\":%d,\"empty_readbacks\":%d,\"remaining_owned_count\":%d,"
        "\"unknown_count\":%d,\"escaped_generation_count\":%d,\"older_unrelated_excluded\":%d,\"pidfd_supported\":%s,"
        "\"term_attempts\":%d,\"kill_attempts\":%d,\"cleanup_known\":%s,"
        "\"failure\":\"%s\",\"numeric_pid_signal_used\":false,\"group_signal_used\":false,"
        "\"sdk_called\":false,\"worker_started\":false,"
        "\"group_presence_probe_used\":%s,\"group_presence_probe_signal\":0,\"targets\":[",
        id.task,id.generation,id.token,id.uid,id.app_pid,id.app_start,id.leader_pid,id.leader_start,
        id.pgid,id.boot,identity_input.digest,nonce,(long)getpid(),helper_start,helper_pgid,
        (unsigned long)getuid(),(long)getppid(),began,deadline,ended,scan_complete?"true":"false",
        scans,empty_reads,remaining,unknown,escaped,older_unrelated,supported?"true":"false",term_attempts,kill_attempts,
        clean?"true":"false",failure,presence_count?"true":"false");
    for(size_t i=0;i<target_count;i++){
        HgTarget *t=&targets[i];if(i)fputc(',',f);
        fprintf(f,"{\"pid\":%ld,\"start_ticks\":%" PRIu64 ",\"term_attempted\":%s,\"term_errno\":%d,"
            "\"kill_attempted\":%s,\"kill_errno\":%d}",t->pid,t->start,t->term_attempted?"true":"false",
            t->term_error,t->kill_attempted?"true":"false",t->kill_error);
    }
    fputs("],\"group_presence_observations\":[",f);
    for(size_t i=0;i<presence_count;i++){
        HgPresence *p=&presence[i];if(i)fputc(',',f);
        fprintf(f,"{\"pgid\":%ld,\"monotonic_ns\":%" PRIu64 ",\"result\":%d,\"errno\":%d}",
                p->pgid,p->observed,p->result,p->error);
    }
    fputs("]}\n",f);
    bool written=fflush(f)==0&&!ferror(f);if(fclose(f)!=0)written=false;
    if(written)written=hg_publish_bytes(receipt_path,nonce,record,bytes);
    free(record);input_free(&identity_input);
    return written&&clean?0:78;
}
#endif
