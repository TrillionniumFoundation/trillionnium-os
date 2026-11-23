#define _POSIX_C_SOURCE 200809L
/* Standalone read-only SHA qualification/benchmark. No model, App or network API. */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "sha256-dispatch.hpp"

static double now_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)!=0)return -1;return (double)t.tv_sec*1000.0+(double)t.tv_nsec/1000000.0;}
static void text_json(const char *text){
    fputc('"',stdout);
    for(const unsigned char *p=(const unsigned char*)text;*p;p++){
        if(*p=='"'||*p=='\\'){fputc('\\',stdout);fputc(*p,stdout);}
        else if(*p<0x20)printf("\\u%04x",*p);
        else fputc(*p,stdout);
    }
    fputc('"',stdout);
}
static bool same_file(const struct stat *a,const struct stat *b){
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&
        a->st_size==b->st_size&&a->st_nlink==b->st_nlink&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static void pattern(unsigned char *p,size_t n){for(size_t i=0;i<n;i++)p[i]=(unsigned char)(i*29u+(i>>8)+0x5au);}
static void digest_chunks(const unsigned char *p,size_t n,size_t chunk,bool portable,char out[65],uint64_t *hardware){
    Sha256 s;sha_init(&s);if(portable)s.hardware=false;
    sha_update(&s,NULL,0);
    for(size_t i=0;i<n;){size_t take=n-i;if(take>chunk)take=chunk;sha_update(&s,p+i,take);i+=take;}
    sha_finish(&s,out);*hardware+=s.hardware_blocks;
}
static int self_test(bool require_hardware){
    bool hw=hepta_sha256_runtime_sha2();
    if(require_hardware&&!hw){puts("{\"schema\":\"hepta.sha256-self-test.v1\",\"error\":\"HWCAP_SHA2 unavailable\",\"all_pass\":false}");return 77;}
    static const char *known_text[]={"","abc","abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    static const char *known_sha[]={"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"};
    static const size_t lengths[]={0,1,3,55,56,57,63,64,65,127,128,129,255,256,257,4095,4096,4097,65535,65536,65537,1048641};
    static const size_t chunks[]={1,7,63,64,65,4096,65536};
    uint64_t hardware_blocks=0;unsigned checks=0;bool good=true;char fast[65],slow[65];
    errno=EIO;bool observed_hw=hepta_sha256_runtime_sha2();bool errno_preserved=errno==EIO&&observed_hw==hw;
    printf("{\"schema\":\"hepta.sha256-self-test.v1\",\"compiled_armv8_sha2\":%s,\"runtime_hwcap_sha2\":%s,\"errno_preserved\":%s,\"known_vectors\":[",HEPTA_SHA256_ARMV8_COMPILED?"true":"false",hw?"true":"false",errno_preserved?"true":"false");
    for(unsigned i=0;i<3;i++){
        size_t n=strlen(known_text[i]);
        hash_bytes(known_text[i],n,fast);
        digest_chunks((const unsigned char*)known_text[i],n,1,true,slow,&hardware_blocks);
        bool passed=!strcmp(fast,known_sha[i])&&!strcmp(slow,known_sha[i]);good=good&&passed;checks+=2;
        if(i)fputc(',',stdout);
        printf("{\"name\":\"nist-%u\",\"bytes\":%zu,\"sha256\":\"%s\",\"passed\":%s}",i,n,fast,passed?"true":"false");
    }
    unsigned char *allocation=static_cast<unsigned char*>(malloc(1048642));if(!allocation)return 70;
    unsigned char *data=allocation+1; /* Deliberately unaligned input. */
    memset(data,'a',1000000);
    digest_chunks(data,1000000,65536,false,fast,&hardware_blocks);
    digest_chunks(data,1000000,63,true,slow,&hardware_blocks);
    bool million=!strcmp(fast,"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")&&!strcmp(fast,slow);good=good&&million;checks+=2;
    printf(",{\"name\":\"nist-million-a\",\"bytes\":1000000,\"sha256\":\"%s\",\"passed\":%s}],\"pattern_vectors\":[",fast,million?"true":"false");
    pattern(data,1048641);
    for(size_t i=0;i<sizeof(lengths)/sizeof(lengths[0]);i++){
        char reference[65];digest_chunks(data,lengths[i],65536,true,reference,&hardware_blocks);bool matched=true;
        for(size_t j=0;j<sizeof(chunks)/sizeof(chunks[0]);j++){
            digest_chunks(data,lengths[i],chunks[j],false,fast,&hardware_blocks);
            digest_chunks(data,lengths[i],chunks[j],true,slow,&hardware_blocks);
            matched=matched&&!strcmp(fast,reference)&&!strcmp(slow,reference);checks+=2;
        }
        good=good&&matched;if(i)fputc(',',stdout);
        printf("{\"bytes\":%zu,\"sha256\":\"%s\",\"chunk_sizes\":[1,7,63,64,65,4096,65536],\"all_equal\":%s}",lengths[i],reference,matched?"true":"false");
    }
    free(allocation);good=good&&errno_preserved&&(!require_hardware||hardware_blocks>0);
    printf("],\"hardware_blocks_observed\":%" PRIu64 ",\"digest_comparisons\":%u,\"all_pass\":%s}\n",hardware_blocks,checks,good?"true":"false");
    return good?0:1;
}
static int hash_file(const char *path,size_t chunk,bool portable){
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);struct stat before,after,named;
    if(fd<0||fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_size<0||(uint64_t)before.st_size>UINT64_MAX/8u){if(fd>=0)close(fd);return 66;}
    unsigned char *buffer=static_cast<unsigned char*>(malloc(chunk));if(!buffer){close(fd);return 70;}
    Sha256 hash;sha_init(&hash);if(portable)hash.hardware=false;
    double started=now_ms();if(started<0){close(fd);free(buffer);return 74;}uint64_t count=0;
    for(;;){ssize_t n=read(fd,buffer,chunk);if(n<0&&errno==EINTR)continue;if(n<0){close(fd);free(buffer);return 74;}if(!n)break;count+=(uint64_t)n;sha_update(&hash,buffer,(size_t)n);}
    char digest[65];sha_finish(&hash,digest);double finished=now_ms();
    bool unchanged=fstat(fd,&after)==0&&lstat(path,&named)==0&&same_file(&before,&after)&&same_file(&after,&named)&&count==(uint64_t)before.st_size;
    close(fd);free(buffer);
    if(finished<started||!unchanged)return 74;
    printf("{\"schema\":\"hepta.sha256-file.v1\",\"path\":");text_json(path);
    printf(",\"bytes\":%" PRIu64 ",\"sha256\":\"%s\",\"backend\":\"%s\",\"runtime_hwcap_sha2\":%s,\"hardware_blocks\":%" PRIu64 ",\"portable_blocks\":%" PRIu64 ",\"chunk_bytes\":%zu,\"elapsed_ms\":%.6f,\"held_fd_complete_read\":true,\"metadata_unchanged\":true}\n",count,digest,hepta_sha256_backend(&hash),hepta_sha256_runtime_sha2()?"true":"false",hash.hardware_blocks,hash.portable_blocks,chunk,finished-started);
    return 0;
}
static int benchmark(uint64_t count,bool portable){
    unsigned char buffer[65536];pattern(buffer,sizeof(buffer));Sha256 hash;sha_init(&hash);if(portable)hash.hardware=false;
    double started=now_ms();if(started<0)return 74;uint64_t left=count;
    while(left){size_t n=left>sizeof(buffer)?sizeof(buffer):(size_t)left;sha_update(&hash,buffer,n);left-=n;}
    char digest[65];sha_finish(&hash,digest);double finished=now_ms();if(finished<started)return 74;
    printf("{\"schema\":\"hepta.sha256-benchmark.v1\",\"bytes\":%" PRIu64 ",\"sha256\":\"%s\",\"pattern\":\"byte(i*29+(i>>8)+0x5a),period65536\",\"backend\":\"%s\",\"runtime_hwcap_sha2\":%s,\"hardware_blocks\":%" PRIu64 ",\"portable_blocks\":%" PRIu64 ",\"elapsed_ms\":%.6f,\"includes_file_io\":false}\n",count,digest,hepta_sha256_backend(&hash),hepta_sha256_runtime_sha2()?"true":"false",hash.hardware_blocks,hash.portable_blocks,finished-started);
    return 0;
}
int main(int argc,char **argv){
    const char *path=NULL;bool self=false,portable=false,require_hardware=false;uint64_t bench=0;size_t chunk=65536;
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--self-test"))self=true;
        else if(!strcmp(argv[i],"--portable"))portable=true;
        else if(!strcmp(argv[i],"--require-sha2"))require_hardware=true;
        else if(!strcmp(argv[i],"--file")&&i+1<argc)path=argv[++i];
        else if((!strcmp(argv[i],"--bench")||!strcmp(argv[i],"--chunk"))&&i+1<argc){
            bool is_bench=!strcmp(argv[i],"--bench");char *end=NULL;errno=0;const char *text=argv[++i];unsigned long long n=strtoull(text,&end,10);
            if(errno||!text[0]||text[0]=='-'||!end||*end||!n)return 64;
            if(is_bench){if(n>UINT64_C(1073741824))return 64;bench=(uint64_t)n;}
            else{if(n>1048576)return 64;chunk=(size_t)n;}
        }else return 64;
    }
    if((int)self+(path?1:0)+(bench?1:0)!=1||(portable&&require_hardware)||(self&&portable))return 64;
    if(self)return self_test(require_hardware);
    if(require_hardware&&!hepta_sha256_runtime_sha2()){puts("{\"error\":\"HWCAP_SHA2 unavailable\"}");return 77;}
    return path?hash_file(path,chunk,portable):benchmark(bench,portable);
}
