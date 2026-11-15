#define _GNU_SOURCE 1
#include "../native/generation-bridge.c"
#include "../native/admission.h"
#include <assert.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);} }while(0)
int main(void) {
    char sha[65];hv_hash("abc",3,sha);
    CHECK(!strcmp(sha,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    hv_hash("",0,sha);CHECK(!strcmp(sha,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    CHECK(hepta_vlm_admit(7920,7920,1024,256,8192));
    CHECK(!hepta_vlm_admit(7921,7919,1024,256,8192));
    CHECK(!hepta_vlm_admit(7919,7921,1024,256,8192));
    CHECK(!hepta_vlm_admit(SIZE_MAX,100,1,256,8192));
    CHECK(!hepta_vlm_admit(200,INT64_MAX,1,256,8192));
    CHECK(!hepta_vlm_admit(200,-1,1,256,8192));
    CHECK(!hepta_vlm_admit(200,200,201,256,8192));
    CHECK(!hepta_vlm_admit(1025,1025,1025,256,8192));
    CHECK(!hepta_vlm_admit(200,200,0,256,8192));
    CHECK(!hepta_vlm_admit(200,200,20,0,8192));
    CHECK(!hepta_vlm_admit(200,200,20,257,8192));
    CHECK(!hepta_vlm_admit(200,200,20,256,16384));
    CHECK(hv_id("0123456789abcdef0123456789abcdef"));CHECK(!hv_id("../../escape"));
    CHECK(!hv_id("0123456789abcdef0123456789abcdeF"));
    CHECK(!hv_utf8((const unsigned char *)"\xc0\xaf",2));
    CHECK(!hv_utf8((const unsigned char *)"\xed\xa0\x80",3));
    CHECK(hv_utf8((const unsigned char *)"\xe5\xa4\x87\xe5\xbf\x98\xe5\xbd\x95",9));
    char root[]="/tmp/hepta-vlm-guard-XXXXXX";CHECK(mkdtemp(root)!=NULL);CHECK(chmod(root,0700)==0);
    struct stat st;CHECK(hv_private_directory(root,&st));
    char path[PATH_MAX],link[PATH_MAX];snprintf(path,sizeof(path),"%s/input",root);snprintf(link,sizeof(link),"%s/link",root);
    const char *id="0123456789abcdef0123456789abcdef";
    CHECK(hv_publish(path,id,"abc",3));CHECK(!hv_publish(path,id,"changed",7));
    HeptaInput input={.fd=-1};CHECK(hv_read(&input,path,3,1));
    CHECK(input.size==3&&!strcmp(input.digest,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    CHECK(hv_unchanged(&input));
    CHECK(symlink(path,link)==0);HeptaInput aliased={.fd=-1};CHECK(!hv_read(&aliased,link,3,1));hv_free(&aliased);
    int fd=open(path,O_WRONLY|O_CLOEXEC);CHECK(fd>=0);CHECK(write(fd,"xyz",3)==3);CHECK(close(fd)==0);
    CHECK(!hv_unchanged(&input));hv_free(&input);
    HeptaInput wrong={.fd=-1};CHECK(!hv_pin(&wrong,path,3,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",1,NULL,NULL));hv_free(&wrong);
    CHECK(chmod(path,0644)==0);HeptaInput mode={.fd=-1};CHECK(!hv_read(&mode,path,100,1));hv_free(&mode);
    CHECK(!hv_scope_enter(root,id,id,getppid()));
    CHECK(!hv_arm_parent(getpid()));CHECK(!hv_parent(getppid(),getuid()));
    CHECK(unlink(link)==0);CHECK(unlink(path)==0);CHECK(rmdir(root)==0);
    printf("{\"schema\":\"hepta.vlm.host-guards.v1\",\"checks\":%u,\"passed\":true,\"phone_contacted\":false,\"model_inference_performed\":false}\n",checks);
    return 0;
}
