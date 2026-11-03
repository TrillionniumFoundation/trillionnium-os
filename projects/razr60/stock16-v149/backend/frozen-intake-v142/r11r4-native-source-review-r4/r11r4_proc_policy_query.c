/* Host-only libsepol in-memory query; never calls kernel SELinux APIs. */
#include <sepol/policydb/services.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned cases=0,denied=0;
static void query(const char* source,const char* path,const char* classname,const char* permission,int filesystem) {
 sepol_security_id_t ssid=0,tsid=0;sepol_security_class_t klass=0;sepol_access_vector_t requested=0;
 unsigned behavior=0,reason=0;struct sepol_av_decision avd={0};
 if(sepol_context_to_sid(source,strlen(source)+1,&ssid)||sepol_string_to_security_class(classname,&klass)||sepol_string_to_av_perm(klass,permission,&requested))exit(12);
 int rc=filesystem?sepol_fs_use("proc",&behavior,&tsid):sepol_genfs_sid("proc",path,klass,&tsid);
 if(rc)exit(13);
 char* context=NULL;size_t length=0;if(sepol_sid_to_context(tsid,&context,&length))exit(14);
 rc=sepol_compute_av_reason(ssid,tsid,klass,requested,&avd,&reason);
 const int allowed=rc==0 && (avd.allowed & requested)==requested;
 ++cases;if(!allowed)++denied;
 printf("{\"source\":\"%s\",\"proc_path\":\"%s\",\"actual_target\":\"%s\",\"class\":\"%s\",\"permission\":\"%s\",\"requested_bits\":%u,\"allowed_bits\":%u,\"reason\":%u,\"native_rc\":%d,\"allowed\":%s,\"filesystem_behavior\":%u}\n",source,path,context,classname,permission,requested,avd.allowed,reason,rc,allowed?"true":"false",behavior);
 free(context);
}
int main(int argc,char**argv) {
 if(argc!=2)return 2;
 FILE*f=fopen(argv[1],"rb");if(!f)return 3;fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);if(n<=0||n>32*1024*1024)return 4;void*b=malloc((size_t)n);if(!b||fread(b,1,(size_t)n,f)!=(size_t)n)return 5;fclose(f);
 if(sepol_load_policy(b,(size_t)n))return 6;free(b);
 const char* sources[]={"u:r:trillionnium_owner_open_bootstrap:s0","u:r:trillionnium_owner_open_ingress:s0"};
 const char* dirs[]={"/","/sys","/sys/kernel","/sys/kernel/random"};
 const char* perms[]={"open","read","getattr"};
 for(unsigned s=0;s<2;s++) {
  for(unsigned p=0;p<4;p++)query(sources[s],dirs[p],"dir","search",0);
  for(unsigned p=0;p<3;p++)query(sources[s],"/sys/kernel/random/boot_id","file",perms[p],0);
  query(sources[s],"/","filesystem","getattr",1);
 }
 printf("{\"summary_cases\":%u,\"denied\":%u,\"pass\":%s}\n",cases,denied,denied==0?"true":"false");
 return denied==0?0:20;
}
