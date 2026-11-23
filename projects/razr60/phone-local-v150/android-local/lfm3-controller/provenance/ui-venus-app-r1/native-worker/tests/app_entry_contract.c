#define _GNU_SOURCE 1
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>
#define VENUS_APP_PACKAGE "org.trillionnium.hepta.local"
/* Functions below are extracted verbatim from the actual source by the
 * preparation script, not a separate Python implementation of the rules. */
static bool utf8(const unsigned char *p,size_t n) {
    size_t i=0;
    while(i<n) {
        uint32_t v;unsigned more;unsigned char c=p[i++];
        if(c<0x80)continue;
        if(c>=0xc2&&c<=0xdf){v=c&31u;more=1;}
        else if(c>=0xe0&&c<=0xef){v=c&15u;more=2;}
        else if(c>=0xf0&&c<=0xf4){v=c&7u;more=3;}else return false;
        if(n-i<more)return false;
        for(unsigned j=0;j<more;j++){c=p[i++];if((c&0xc0u)!=0x80u)return false;v=(v<<6)|(c&63u);}
        if((more==1&&v<0x80)||(more==2&&v<0x800)||(more==3&&v<0x10000)||v>0x10ffff||(v>=0xd800&&v<=0xdfff))return false;
    }
    return true;
}


static bool canonical(const char *path) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX||!utf8((const unsigned char*)path,strlen(path)))return false;
    char real[PATH_MAX];return realpath(path,real)&&strcmp(real,path)==0;
}


typedef struct {
    unsigned long expected_uid;
    pid_t expected_parent;
    char files[PATH_MAX],model_directory[PATH_MAX],runs_directory[PATH_MAX],run_directory[PATH_MAX];
    char binding_path[PATH_MAX];
    struct stat directories[4];
    char parent_cmdline_sha[2][65],parent_status_sha[2][65];
    size_t parent_cmdline_bytes[2];
    bool same_directory_bootstrap_verified;
} VenusAppEntry;

static bool venus_app_decimal(const char *text,unsigned long maximum,unsigned long *out){
    if(!text||!*text||text[0]=='0')return false;
    unsigned long value=0;
    for(const unsigned char *p=(const unsigned char*)text;*p;p++){
        if(*p<'0'||*p>'9'||value>(maximum-(unsigned long)(*p-'0'))/10)return false;
        value=value*10+(unsigned long)(*p-'0');
    }
    *out=value;return true;
}


static bool venus_app_take_arguments(int *argc,char **argv,VenusAppEntry *entry){
    if(!argc||!argv||!entry||*argc<5||!argv[1]||!argv[2]||!argv[3]||!argv[4]||
       strcmp(argv[1],"--expected-app-uid")||strcmp(argv[3],"--app-files-dir")||
       !venus_app_decimal(argv[2],INT_MAX,&entry->expected_uid)||entry->expected_uid<10000||
       !canonical(argv[4]))return false;
    const size_t n=strlen(argv[4]);
    if(n>=sizeof(entry->files))return false;
    memcpy(entry->files,argv[4],n+1);
    for(int i=5;i<*argc;i++)if(!argv[i]||!strcmp(argv[i],"--expected-app-uid")||
       !strcmp(argv[i],"--app-files-dir"))return false;
    memmove(argv+1,argv+5,(size_t)(*argc-4)*sizeof(*argv));
    *argc-=4;return true;
}


static bool venus_app_status_number(const char **cursor,const char *end,unsigned long *value){
    const char *at=*cursor;
    while(at<end&&(*at==' '||*at=='\t'))at++;
    if(at==end||*at<'0'||*at>'9')return false;
    unsigned long n=0;
    do{
        if(n>((unsigned long)INT_MAX-(unsigned long)(*at-'0'))/10)return false;
        n=n*10+(unsigned long)(*at-'0');at++;
    }while(at<end&&*at>='0'&&*at<='9');
    if(at<end&&*at!=' '&&*at!='\t')return false;
    *cursor=at;*value=n;return true;
}


static bool venus_app_status_tail(const char *at,const char *end){
    while(at<end&&(*at==' '||*at=='\t'))at++;
    return at==end;
}


static bool venus_app_parent_status(const unsigned char *data,size_t size,pid_t parent,unsigned long uid){
    if(!size||memchr(data,0,size)||data[size-1]!='\n')return false;
    const char *at=(const char*)data,*end=at+size;bool have_pid=false,have_uid=false;
    while(at<end){
        const char *line_end=memchr(at,'\n',(size_t)(end-at));
        if(!line_end)return false;
        size_t length=(size_t)(line_end-at);
        if(length>=4&&!memcmp(at,"Pid:",4)){
            const char *number=at+4;unsigned long value=0;
            if(have_pid||!venus_app_status_number(&number,line_end,&value)||
               !venus_app_status_tail(number,line_end)||value!=(unsigned long)parent)return false;
            have_pid=true;
        }else if(length>=4&&!memcmp(at,"Uid:",4)){
            const char *number=at+4;unsigned long value=0;
            if(have_uid)return false;
            for(unsigned i=0;i<4;i++)if(!venus_app_status_number(&number,line_end,&value)||value!=uid)return false;
            if(!venus_app_status_tail(number,line_end))return false;
            have_uid=true;
        }
        at=line_end+1;
    }
    return have_pid&&have_uid;
}


static bool venus_app_parent_cmdline(const unsigned char *data,size_t size){
    static const unsigned char package[]=VENUS_APP_PACKAGE;
    const size_t n=sizeof(package)-1;
    if(size<=n||memcmp(data,package,n))return false;
    /* Android retains argv storage as NUL padding. No additional argument,
     * shortened process name or package suffix is accepted. */
    for(size_t i=n;i<size;i++)if(data[i])return false;
    return true;
}


static unsigned assertions;
#define CHECK(x) do { assertions++; if(!(x)){fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;} } while(0)
int main(void){
    unsigned long value=0;
    CHECK(venus_app_decimal("10000",INT_MAX,&value)&&value==10000);
    CHECK(venus_app_decimal("2147483647",INT_MAX,&value)&&value==2147483647ul);
    CHECK(!venus_app_decimal("2147483648",INT_MAX,&value));
    CHECK(!venus_app_decimal("010000",INT_MAX,&value));
    CHECK(!venus_app_decimal("+10000",INT_MAX,&value));
    CHECK(!venus_app_decimal("10000\n",INT_MAX,&value));
    CHECK(!venus_app_decimal("",INT_MAX,&value));
    CHECK(!venus_app_decimal(NULL,INT_MAX,&value));
    const unsigned char valid_status[]="Name:\tapp\nPid:\t12345\nUid:\t12001\t12001\t12001\t12001\n";
    CHECK(venus_app_parent_status(valid_status,sizeof(valid_status)-1,12345,12001));
    CHECK(!venus_app_parent_status(valid_status,sizeof(valid_status)-1,12346,12001));
    CHECK(!venus_app_parent_status(valid_status,sizeof(valid_status)-1,12345,12002));
    CHECK(!venus_app_parent_status(valid_status,sizeof(valid_status)-2,12345,12001));
    const unsigned char mismatched_fsuid[]="Pid:\t12345\nUid:\t12001\t12001\t12001\t12002\n";
    CHECK(!venus_app_parent_status(mismatched_fsuid,sizeof(mismatched_fsuid)-1,12345,12001));
    const unsigned char repeated_pid[]="Pid:\t12345\nPid:\t12345\nUid:\t12001\t12001\t12001\t12001\n";
    CHECK(!venus_app_parent_status(repeated_pid,sizeof(repeated_pid)-1,12345,12001));
    const unsigned char missing_uid[]="Pid:\t12345\n";
    CHECK(!venus_app_parent_status(missing_uid,sizeof(missing_uid)-1,12345,12001));
    const unsigned char nul_status[]="Pid:\t12345\n\0Uid:\t12001\t12001\t12001\t12001\n";
    CHECK(!venus_app_parent_status(nul_status,sizeof(nul_status)-1,12345,12001));
    const unsigned char too_many_uids[]="Pid:\t12345\nUid:\t12001\t12001\t12001\t12001\t12001\n";
    CHECK(!venus_app_parent_status(too_many_uids,sizeof(too_many_uids)-1,12345,12001));
    unsigned char padded[99]={0};
    memcpy(padded,VENUS_APP_PACKAGE,strlen(VENUS_APP_PACKAGE));
    CHECK(venus_app_parent_cmdline(padded,sizeof(padded)));
    CHECK(venus_app_parent_cmdline(padded,strlen(VENUS_APP_PACKAGE)+1));
    CHECK(!venus_app_parent_cmdline(padded,strlen(VENUS_APP_PACKAGE)));
    padded[sizeof(padded)-1]='x';
    CHECK(!venus_app_parent_cmdline(padded,sizeof(padded)));
    const unsigned char suffixed[]=VENUS_APP_PACKAGE ":worker";
    CHECK(!venus_app_parent_cmdline(suffixed,sizeof(suffixed)));
    const unsigned char extra_argument[]=VENUS_APP_PACKAGE "\0--extra";
    CHECK(!venus_app_parent_cmdline(extra_argument,sizeof(extra_argument)));
    const unsigned char shell[]="sh";
    CHECK(!venus_app_parent_cmdline(shell,sizeof(shell)));
    char temporary[]="/tmp/hepta-ui-venus-entry-contract-XXXXXX";
    CHECK(mkdtemp(temporary)!=NULL);
    char directory[PATH_MAX];CHECK(realpath(temporary,directory)!=NULL);
    char *ok[]={"worker","--expected-app-uid","12001","--app-files-dir",directory,"--request-id","abc",NULL};
    int argc=7;VenusAppEntry entry={0};
    CHECK(venus_app_take_arguments(&argc,ok,&entry));
    CHECK(argc==3&&!strcmp(ok[1],"--request-id")&&!strcmp(ok[2],"abc")&&ok[3]==NULL);
    CHECK(entry.expected_uid==12001&&!strcmp(entry.files,directory));
    char *shell_uid[]={"worker","--expected-app-uid","2000","--app-files-dir",directory,NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,shell_uid,&entry));
    char *low_uid[]={"worker","--expected-app-uid","9999","--app-files-dir",directory,NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,low_uid,&entry));
    char *duplicate[]={"worker","--expected-app-uid","12001","--app-files-dir",directory,"--expected-app-uid","12001",NULL};
    argc=7;CHECK(!venus_app_take_arguments(&argc,duplicate,&entry));
    char *reordered[]={"worker","--app-files-dir",directory,"--expected-app-uid","12001",NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,reordered,&entry));
    char noncanonical[PATH_MAX];
    int n=snprintf(noncanonical,sizeof(noncanonical),"%s/../",directory);CHECK(n>0&&(size_t)n<sizeof(noncanonical));
    char *bad_path[]={"worker","--expected-app-uid","12001","--app-files-dir",noncanonical,NULL};
    argc=5;CHECK(!venus_app_take_arguments(&argc,bad_path,&entry));
    CHECK(rmdir(temporary)==0);
    printf("{\"schema\":\"hepta.ui-venus.app-entry-contract-test.v1\",\"assertions\":%u,\"passed\":true,\"sdk_initialized\":false,\"phone_contact\":false}\n",assertions);
    return 0;
}
