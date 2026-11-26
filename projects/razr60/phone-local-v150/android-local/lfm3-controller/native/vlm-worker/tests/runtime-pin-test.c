#define _GNU_SOURCE 1
#include "../native/generation-bridge.c"
#include <assert.h>
static unsigned checks,policy_cases,io_cases;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);} }while(0)
static const char *abc="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
static uint64_t number(const char *s) {
    char *end;errno=0;unsigned long long n=strtoull(s,&end,10);
    CHECK(s[0]&&s[0]!='-'&&!errno&&!*end);return n;
}
static void policy(struct stat actual) {
    CHECK(actual.st_dev==2097218&&actual.st_ino==320747&&actual.st_mode==0100555);
    CHECK(actual.st_uid==1000&&actual.st_gid==1000&&actual.st_nlink==3&&actual.st_size==5642424);
    CHECK(actual.st_mtim.tv_sec==1795704799&&actual.st_ctim.tv_sec==1795704799);
    CHECK(pin_metadata_allowed(&actual,5642424,0));++policy_cases;
    struct stat s=actual;s.st_nlink=1;CHECK(pin_metadata_allowed(&s,5642424,0));++policy_cases;
    s=actual;s.st_nlink=0;CHECK(!pin_metadata_allowed(&s,5642424,0));++policy_cases;
    s=actual;s.st_uid=1001;CHECK(!pin_metadata_allowed(&s,5642424,0));++policy_cases;
    s=actual;s.st_gid=1001;CHECK(!pin_metadata_allowed(&s,5642424,0));++policy_cases;
    const mode_t forbidden[]={S_IWGRP,S_IWOTH,S_ISUID,S_ISGID};
    for(size_t i=0;i<sizeof(forbidden)/sizeof(*forbidden);++i){s=actual;s.st_mode|=forbidden[i];CHECK(!pin_metadata_allowed(&s,5642424,0));++policy_cases;}
    s=actual;s.st_mode=(s.st_mode&07777)|S_IFDIR;CHECK(!pin_metadata_allowed(&s,5642424,0));++policy_cases;
    s=actual;s.st_size=0;CHECK(!pin_metadata_allowed(&s,5642424,0));++policy_cases;
    CHECK(!pin_metadata_allowed(&actual,5642423,0));++policy_cases;
    CHECK(!pin_metadata_allowed(&actual,5642424,2));++policy_cases;
    s=actual;s.st_uid=getuid();s.st_mode=S_IFREG|0600;
    CHECK(!pin_metadata_allowed(&s,5642424,1));++policy_cases;
    s.st_nlink=1;CHECK(pin_metadata_allowed(&s,5642424,1));++policy_cases;
    s.st_uid=getuid()+1;CHECK(!pin_metadata_allowed(&s,5642424,1));++policy_cases;
    s.st_uid=getuid();s.st_mode=S_IFREG|0644;CHECK(!pin_metadata_allowed(&s,5642424,1));++policy_cases;
}
static void write_input(const char *path,const char *value,mode_t mode) {
    int fd=open(path,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);CHECK(fd>=0);
    CHECK(write(fd,value,3)==3);CHECK(fchmod(fd,mode)==0);CHECK(close(fd)==0);
}
static int pinned(const char *path,uint64_t bytes,const char *sha,int private_model,int (*fence)(void *),void *data) {
    HeptaInput input={.fd=-1};int result=hv_pin(&input,path,bytes,sha,private_model,fence,data);
    if(result){CHECK(input.size==bytes);CHECK(!strcmp(input.digest,sha));CHECK(hv_unchanged(&input));}
    hv_free(&input);return result;
}
static int cancelled(void *data){unsigned *calls=data;++*calls;return 0;}
typedef struct {const char *path,*extra;unsigned calls;} LinkRace;
static int add_link(void *data) {
    LinkRace *r=data;if(!r->calls++)CHECK(link(r->path,r->extra)==0);return 1;
}
typedef struct {const char *path,*old;unsigned calls;} ReplaceRace;
static int replace_path(void *data) {
    ReplaceRace *r=data;
    if(!r->calls++){CHECK(rename(r->path,r->old)==0);write_input(r->path,"abc",0555);}
    return 1;
}
static bool file_io(void) {
    char root[]="/tmp/hepta-vlm-runtime-XXXXXX";CHECK(mkdtemp(root)!=NULL);CHECK(chmod(root,0700)==0);
    char path[PATH_MAX],a[PATH_MAX],b[PATH_MAX],symbol[PATH_MAX],extra[PATH_MAX],old[PATH_MAX],dirlink[PATH_MAX],aliased[PATH_MAX];
    CHECK(snprintf(path,sizeof(path),"%s/runtime",root)>0);CHECK(snprintf(a,sizeof(a),"%s/link2",root)>0);
    CHECK(snprintf(b,sizeof(b),"%s/link3",root)>0);CHECK(snprintf(symbol,sizeof(symbol),"%s/symbol",root)>0);
    CHECK(snprintf(extra,sizeof(extra),"%s/link4",root)>0);CHECK(snprintf(old,sizeof(old),"%s/replaced",root)>0);
    CHECK(snprintf(dirlink,sizeof(dirlink),"%s/alias",root)>0);CHECK(snprintf(aliased,sizeof(aliased),"%s/alias/runtime",root)>0);
    write_input(path,"abc",0600);
    CHECK(pinned(path,3,abc,1,NULL,NULL));++io_cases;
    CHECK(!pinned(path,3,"0000000000000000000000000000000000000000000000000000000000000000",1,NULL,NULL));++io_cases;
    CHECK(link(path,a)==0&&link(path,b)==0);struct stat s;CHECK(lstat(path,&s)==0&&s.st_nlink==3);
    CHECK(!pinned(path,3,abc,1,NULL,NULL));++io_cases;
    HeptaInput private_input={.fd=-1};CHECK(!hv_read(&private_input,path,3,1));hv_free(&private_input);++io_cases;
    CHECK(chmod(path,0555)==0);bool runtime_os=getuid()==1000&&getgid()==1000;
    if(runtime_os) {
        CHECK(lstat(path,&s)==0&&s.st_uid==1000&&s.st_gid==1000&&s.st_nlink==3&&s.st_mode==(S_IFREG|0555));
        CHECK(pinned(path,3,abc,0,NULL,NULL));++io_cases;
        CHECK(!pinned(path,2,abc,0,NULL,NULL));++io_cases;
        CHECK(!pinned(path,3,"0000000000000000000000000000000000000000000000000000000000000000",0,NULL,NULL));++io_cases;
        CHECK(symlink(path,symbol)==0);CHECK(!pinned(symbol,3,abc,0,NULL,NULL));CHECK(unlink(symbol)==0);++io_cases;
        CHECK(symlink(root,dirlink)==0);CHECK(!pinned(aliased,3,abc,0,NULL,NULL));CHECK(unlink(dirlink)==0);++io_cases;
        unsigned calls=0;CHECK(!pinned(path,3,abc,0,cancelled,&calls));CHECK(calls==1);++io_cases;
        LinkRace links={path,extra,0};CHECK(!pinned(path,3,abc,0,add_link,&links));CHECK(links.calls==1);CHECK(unlink(extra)==0);++io_cases;
        ReplaceRace names={path,old,0};CHECK(!pinned(path,3,abc,0,replace_path,&names));CHECK(names.calls==1);CHECK(unlink(old)==0);++io_cases;
    }
    CHECK(unlink(a)==0&&unlink(b)==0&&unlink(path)==0&&rmdir(root)==0);return runtime_os;
}
int main(int argc,char **argv) {
    CHECK(argc==10);struct stat actual={0};actual.st_dev=number(argv[1]);actual.st_ino=number(argv[2]);
    actual.st_mode=number(argv[3]);actual.st_uid=number(argv[4]);actual.st_gid=number(argv[5]);
    actual.st_nlink=number(argv[6]);actual.st_size=number(argv[7]);actual.st_mtim.tv_sec=number(argv[8]);actual.st_ctim.tv_sec=number(argv[9]);
    policy(actual);bool runtime_os=file_io();
    printf("{\"schema\":\"hepta.vlm.runtime-pin-host.v1\",\"policy_cases\":%u,\"io_cases\":%u,\"checks\":%u,\"passed\":true,\"runtime_real_file_io_verified\":%s,\"host_uid\":%u,\"host_gid\":%u,\"phone_contacted\":false,\"model_inference_performed\":false}\n",policy_cases,io_cases,checks,runtime_os?"true":"false",(unsigned)getuid(),(unsigned)getgid());
    return 0;
}
