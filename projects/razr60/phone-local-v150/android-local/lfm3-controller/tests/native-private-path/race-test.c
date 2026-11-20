#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/fs.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(2);} }while(0)
static char ancestor[PATH_MAX],displaced[PATH_MAX],foreign[PATH_MAX];
static char trigger_abs[PATH_MAX],trigger_leaf[256];
static int replacement,armed,mutations,foreign_opened;
static struct stat foreign_file,foreign_directory;
static void mutate_path(void) {
    if(!armed)return;
    armed=0;
    CHECK(rename(ancestor,displaced)==0);
    if(replacement==1)CHECK(symlink(foreign,ancestor)==0);
    else if(replacement==2)CHECK(symlink(displaced,ancestor)==0);
    else { CHECK(replacement==3);CHECK(rename(foreign,ancestor)==0); }
    ++mutations;
}
static void observe_open(int fd,int flags) {
    struct stat st;
    if(!(flags&O_PATH)&&fd>=0&&fstat(fd,&st)==0
        &&((st.st_dev==foreign_file.st_dev&&st.st_ino==foreign_file.st_ino)
           ||(st.st_dev==foreign_directory.st_dev&&st.st_ino==foreign_directory.st_ino)))foreign_opened=1;
}
static int race_open(const char *path,int flags,...) {
    mode_t mode=0;
    if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=(mode_t)va_arg(ap,int);va_end(ap);}
    if(armed&&!strcmp(path,trigger_abs))mutate_path();
    int fd=open(path,flags,mode);observe_open(fd,flags);return fd;
}
static int race_openat(int directory,const char *path,int flags,...) {
    mode_t mode=0;
    if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=(mode_t)va_arg(ap,int);va_end(ap);}
    if(armed&&!strcmp(path,trigger_leaf))mutate_path();
    int fd=openat(directory,path,flags,mode);observe_open(fd,flags);return fd;
}
static __attribute__((unused)) int race_lstat(const char *path,struct stat *out) {
    if(armed&&!strcmp(path,trigger_abs))mutate_path();
    return lstat(path,out);
}
#define open race_open
#define openat race_openat
#define lstat race_lstat
/* The embedded bridge declares its feature set after this fixture prelude. */
#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE
#include "production-target.inc"
#undef open
#undef openat
#undef lstat

static void path(char out[PATH_MAX],const char *root,const char *leaf) {
    int n=snprintf(out,PATH_MAX,"%s/%s",root,leaf);
    CHECK(n>0&&n<PATH_MAX);
}
static void file(const char *name,const char *bytes) {
    int fd=open(name,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);
    CHECK(fd>=0);CHECK(write(fd,bytes,strlen(bytes))==(ssize_t)strlen(bytes));CHECK(close(fd)==0);
}
static void arm(const char *target,int kind) {
    const char *leaf=strrchr(target,'/');
    CHECK(leaf&&strlen(target)<sizeof(trigger_abs)&&strlen(leaf+1)<sizeof(trigger_leaf));
    strcpy(trigger_abs,target);strcpy(trigger_leaf,leaf+1);replacement=kind;armed=1;
}
static int exists(const char *p) { struct stat st;return lstat(p,&st)==0; }
static unsigned fd_count(void) {
    unsigned count=0;
    for(int fd=0;fd<1024;++fd)if(fcntl(fd,F_GETFD)>=0)++count;
    return count;
}
int main(int argc,char **argv) {
    CHECK(argc==3);
    const char *test=argv[1],*root=argv[2];
    char directory[PATH_MAX],input[PATH_MAX],output[PATH_MAX],foreign_dir[PATH_MAX],foreign_input[PATH_MAX],foreign_output[PATH_MAX];
    path(ancestor,root,"ancestor");path(displaced,root,"displaced");path(foreign,root,"foreign");
    CHECK(mkdir(ancestor,0700)==0);CHECK(mkdir(foreign,0700)==0);
    path(directory,ancestor,"private");path(foreign_dir,foreign,"private");
    CHECK(mkdir(directory,0700)==0);CHECK(mkdir(foreign_dir,0700)==0);
    path(input,directory,"input");path(foreign_input,foreign_dir,"input");
    path(output,directory,"output");path(foreign_output,foreign_dir,"output");
    file(input,"abc");file(foreign_input,"abc");
    CHECK(stat(foreign_input,&foreign_file)==0);CHECK(stat(foreign_dir,&foreign_directory)==0);
    const char *nonce="0123456789abcdef0123456789abcdef";
    const char *sha="ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    Input in={.fd=-1};
    Destination dest={.dir=-1,.fd=-1};
    int accepted=0,expected=0,expect_mutation=0;
    unsigned before=fd_count();
    if(!strcmp(test,"canonical_read")){expected=1;accepted=read_input(&in,input,3,true);if(accepted)CHECK(in.size==3&&!strcmp(in.digest,sha)&&input_unchanged(&in));}
    else if(!strcmp(test,"canonical_pin")){expected=1;accepted=guard_pin(input,sha);}
    else if(!strcmp(test,"canonical_directory")){expected=1;accepted=guard_directory(directory);}
    else if(!strcmp(test,"canonical_scope")){expected=1;accepted=hg_private_directory(directory);}
    else if(!strcmp(test,"canonical_publish")){expected=1;accepted=hg_publish_bytes(output,nonce,"abc",3);if(accepted)CHECK(exists(output));}
    else if(!strcmp(test,"unicode_read")) {
        char unicode[PATH_MAX];path(unicode,directory,"\xe5\xa4\x87\xe5\xbf\x98\xe5\xbd\x95");
        file(unicode,"abc");expected=1;accepted=read_input(&in,unicode,3,true);
    }
    else if(!strcmp(test,"traversal_only_ancestor")) {
        CHECK(chmod(ancestor,0111)==0);expected=1;accepted=read_input(&in,input,3,true);CHECK(chmod(ancestor,0700)==0);
    }
    else if(!strcmp(test,"alias_ancestor_read")) { arm(input,1);mutate_path();expect_mutation=1;accepted=read_input(&in,input,3,true); }
    else if(!strcmp(test,"alias_final_read")) {
        char alias[PATH_MAX];path(alias,directory,"alias");CHECK(symlink(input,alias)==0);accepted=read_input(&in,alias,3,true);
    }
    else if(!strcmp(test,"noncanonical_dot")) {
        char bad[PATH_MAX];path(bad,directory,"./input");accepted=read_input(&in,bad,3,true);
    }
    else if(!strcmp(test,"noncanonical_dotdot")) {
        char bad[PATH_MAX];path(bad,directory,"../private/input");accepted=read_input(&in,bad,3,true);
    }
    else if(!strcmp(test,"noncanonical_duplicate")) {
        char bad[PATH_MAX];path(bad,directory,"/input");accepted=read_input(&in,bad,3,true);
    }
    else if(!strcmp(test,"noncanonical_trailing")) {
        char bad[PATH_MAX];path(bad,directory,"");accepted=guard_directory(bad);
    }
    else if(!strcmp(test,"noncanonical_relative")) {accepted=read_input(&in,"input",3,true);}
    else if(!strcmp(test,"invalid_utf8_path")) {
        char bad[PATH_MAX];path(bad,directory,"\xc0\xaf");file(bad,"abc");accepted=read_input(&in,bad,3,true);
    }
    else if(!strcmp(test,"held_input_ancestor_alias")) {
        CHECK(read_input(&in,input,3,true));arm(input,2);mutate_path();expect_mutation=1;accepted=input_unchanged(&in);
    }
    else if(!strcmp(test,"held_input_replacement")) {
        CHECK(read_input(&in,input,3,true));
        char old[PATH_MAX];path(old,directory,"previous");CHECK(rename(input,old)==0);file(input,"abc");accepted=input_unchanged(&in);
    }
    else if(!strcmp(test,"held_publication_parent_alias")||!strcmp(test,"held_publication_parent_replacement")) {
        CHECK(reserve_destination(&dest,output,nonce));CHECK(write_all(dest.fd,"abc",3));
        arm(directory,!strcmp(test,"held_publication_parent_alias")?2:3);mutate_path();expect_mutation=1;accepted=publish(&dest);
    }
    else if(!strncmp(test,"raced_",6)) {
        int kind=strstr(test,"symlink_original")?2:strstr(test,"realreplacement")?3:1;
        expect_mutation=1;
        if(!strncmp(test,"raced_read_",11)){arm(input,kind);accepted=read_input(&in,input,3,true);}
        else if(!strncmp(test,"raced_pin_",10)){arm(input,kind);accepted=guard_pin(input,sha);}
        else if(!strncmp(test,"raced_directory_",16)){arm(directory,kind);accepted=guard_directory(directory);}
        else if(!strncmp(test,"raced_scope_",12)){arm(directory,kind);accepted=hg_private_directory(directory);}
        else if(!strncmp(test,"raced_publish_",14)){arm(directory,kind);accepted=hg_publish_bytes(output,nonce,"abc",3);}
        else CHECK(0);
    } else CHECK(0);
    input_free(&in);destination_close(&dest);guard_pin_close();
    if(armed){fprintf(stderr,"race hook was not reached\n");return 2;}
    CHECK(mutations==expect_mutation);
    CHECK(fd_count()==before);
    int redirected=exists(foreign_output);
    int passed=accepted==expected&&(!expect_mutation||!accepted)&&!redirected&&!foreign_opened;
    printf("{\"schema\":\"hepta.native-private-path.case.v1\",\"case\":\"%s\",\"accepted\":%s,\"expected\":%s,"
           "\"passed\":%s,\"checks\":%u,\"actual_rename_count\":%d,\"foreign_descriptor_opened\":%s,"
           "\"foreign_output_created\":%s,\"fd_count_before\":%u,\"fd_count_after\":%u,"
           "\"real_filesystem_executed\":true,\"phone_contacted\":false,\"model_inference_performed\":false}\n",
           test,accepted?"true":"false",expected?"true":"false",passed?"true":"false",checks,mutations,
           foreign_opened?"true":"false",redirected?"true":"false",before,fd_count());
    return passed?0:1;
}
