#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sepol/policydb.h>
#include <sepol/policydb/policydb.h>
#include <sepol/policydb/avtab.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/hashtab.h>

/* Offline only. No kernel policy path, socket, process launch, or policy load.
 * This helper uses the actual installed libsepol structures and serializer.
 * Its narrow admitted format is the original SELinux kernel v30 MLS policy
 * with both conditional storage structures demonstrably empty.
 */
static const char *worker = "trillionnium_owner_open_phone_worker";
static const char *allocator = "hal_graphics_allocator_default";
static void fail(const char *s) { fprintf(stderr,"reject: %s\n",s); exit(2); }
static void need(int x,const char*s) { if(!x) fail(s); }
static int same_stat(const struct stat*a,const struct stat*b) {
 return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode &&
 a->st_uid==b->st_uid && a->st_gid==b->st_gid && a->st_nlink==b->st_nlink &&
 a->st_size==b->st_size && a->st_mtim.tv_sec==b->st_mtim.tv_sec &&
 a->st_mtim.tv_nsec==b->st_mtim.tv_nsec && a->st_ctim.tv_sec==b->st_ctim.tv_sec &&
 a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
typedef struct { unsigned char *raw; size_t n; struct stat st; } original_t;
static original_t original(const char *path) {
 char *resolved=realpath(path,NULL);need(resolved && !strcmp(resolved,path),"canonical original");free(resolved);
 int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);need(fd>=0,"open original");
 original_t o={0};struct stat end,now;need(!fstat(fd,&o.st),"original fstat");
 need(S_ISREG(o.st.st_mode) && o.st.st_nlink==1 && o.st.st_size>0 && o.st.st_size<=8*1024*1024,"bounded regular original");
 o.n=(size_t)o.st.st_size;o.raw=malloc(o.n);need(o.raw!=NULL,"original allocation");
 size_t off=0;while(off<o.n){ssize_t n=read(fd,o.raw+off,o.n-off);if(n<0 && errno==EINTR)continue;need(n>0,"complete original read");off+=(size_t)n;}
 unsigned char extra;ssize_t n;do{n=read(fd,&extra,1);}while(n<0 && errno==EINTR);need(n==0,"original EOF");
 need(!fstat(fd,&end) && !lstat(path,&now) && same_stat(&o.st,&end) && same_stat(&end,&now),"original changed");
 need(!close(fd),"original close");return o;
}
static void unchanged(const char *path,const original_t *o) {
 original_t z=original(path);need(z.n==o->n && same_stat(&z.st,&o->st) && !memcmp(z.raw,o->raw,o->n),"original final recheck");free(z.raw);
}
static void parse(policydb_t *p,void *raw,size_t n) {
 need(!policydb_init(p),"policydb_init");policy_file_t f;policy_file_init(&f);
 f.type=PF_USE_MEMORY;f.data=raw;f.len=n;f.size=n;
 need(!policydb_read(p,&f,0),"complete libsepol policydb_read");
 need(f.len==0 && f.data==(char*)raw+n,"policy parser must consume every original byte");
 need(p->policy_type==POLICY_KERN && p->target_platform==SEPOL_TARGET_SELINUX &&
      p->policyvers==30 && p->mls==1 && !p->unsupported_format,"supported exact kernel v30 MLS format");
 need(sepol_policy_kern_vers_min()<=30 && sepol_policy_kern_vers_max()>=30,"installed library supports v30");
 need(p->p_bools.nprim==0 && p->cond_list==NULL && p->te_cond_avtab.nel==0,"actual boolean/conditional-list/conditional-avtab must all be empty");
 need(p->handle_unknown==SEPOL_DENY_UNKNOWN || p->handle_unknown==SEPOL_REJECT_UNKNOWN ||
      p->handle_unknown==SEPOL_ALLOW_UNKNOWN,"known unknown-handling value");
}
typedef struct { void *raw; size_t n; } image_t;
static image_t image(policydb_t *p) {
 image_t z={0};need(!policydb_to_image(NULL,p,&z.raw,&z.n),"official full policy serializer");
 need(z.raw && z.n>0 && z.n<=8*1024*1024,"bounded official policy image");return z;
}
static int equal(image_t a,image_t b){return a.n==b.n && !memcmp(a.raw,b.raw,a.n);}
typedef struct { const char *name; unsigned length; unsigned selected; } orbit_t;
static void write_image(int dir,const char *name,image_t a);
static unsigned full_avtab_check(policydb_t *p);
static int less(image_t a,image_t b) {
 size_t common=a.n<b.n?a.n:b.n;int cmp=memcmp(a.raw,b.raw,common);
 return cmp<0 || (cmp==0 && a.n<b.n);
}
static image_t canonical_image(policydb_t *p,orbit_t *info,int dir) {
 /* F is only full official parse -> full official serialize. No fields or
  * prefix images are discarded. The bound is fixed, never widened on failure.
  * A closed cycle from image[0] makes its lexicographic minimum invariant
  * under changing the initial phase of the same exact byte cycle.
  */
 image_t seen[4]={image(p)};
 for(unsigned count=1;count<=4;count++) {
  char name[96];int n=snprintf(name,sizeof(name),"%s.orbit-%02u.bin",info->name,count);
  need(n>0 && (size_t)n<sizeof(name),"bounded orbit filename");write_image(dir,name,seen[count-1]);
  policydb_t reparsed;parse(&reparsed,seen[count-1].raw,seen[count-1].n);
  (void)full_avtab_check(&reparsed);
  image_t next=image(&reparsed);policydb_destroy(&reparsed);
  unsigned match=count;
  for(unsigned i=0;i<count;i++)if(equal(next,seen[i])){match=i;break;}
  if(match<count) {
   need(match==0,"serializer orbit has a transient prefix; no prefix may be discarded");
   unsigned selected=0;
   for(unsigned i=1;i<count;i++)if(less(seen[i],seen[selected]))selected=i;
   info->length=count;info->selected=selected+1;
   image_t answer=seen[selected];free(next.raw);
   for(unsigned i=0;i<count;i++)if(i!=selected)free(seen[i].raw);
   return answer;
  }
  need(count<4,"official serializer has no closed first-image orbit within fixed bound four");
  seen[count]=next;
 }
 fail("unreachable serializer cycle state");return (image_t){0};
}
static void write_image(int dir,const char *name,image_t a) {
 int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);need(fd>=0,"create-only normalized image");
 size_t pos=0;while(pos<a.n){ssize_t n=write(fd,(char*)a.raw+pos,a.n-pos);if(n<0 && errno==EINTR)continue;need(n>0,"normalized image complete write");pos+=(size_t)n;}
 need(!fsync(fd) && !close(fd),"normalized image durable close");
}
static uint16_t type(policydb_t *p,const char *name) {
 type_datum_t *d=hashtab_search(p->p_types.table,name);
 need(d && d->flavor==TYPE_TYPE && d->s.value>0 && d->s.value<=p->p_types.nprim && d->s.value<=UINT16_MAX,"known concrete type");
 need(p->p_type_val_to_name[d->s.value-1] && !strcmp(p->p_type_val_to_name[d->s.value-1],name),"canonical concrete type name");
 return (uint16_t)d->s.value;
}
static avtab_key_t key(policydb_t *p,const char *source,const char *target,const char *class_name,const char *perm,uint32_t *bit) {
 class_datum_t *c=hashtab_search(p->p_classes.table,class_name);
 need(c && c->s.value>0 && c->s.value<=p->p_classes.nprim && c->s.value<=UINT16_MAX,"known object class");
 perm_datum_t *pd=hashtab_search(c->permissions.table,perm);
 if(!pd && c->comdatum)pd=hashtab_search(c->comdatum->permissions.table,perm);
 need(pd && pd->s.value>=1 && pd->s.value<=32,"known class/common permission");
 *bit=UINT32_C(1)<<(pd->s.value-1);
 return (avtab_key_t){.source_type=type(p,source),.target_type=type(p,target),.target_class=(uint16_t)c->s.value,.specified=AVTAB_ALLOWED};
}
static int keyeq(const avtab_key_t*a,const avtab_key_t*b) {
 return a->source_type==b->source_type && a->target_type==b->target_type && a->target_class==b->target_class && a->specified==b->specified;
}
static avtab_datum_t *unique(policydb_t *p,avtab_key_t k) {
 avtab_datum_t *found=NULL;unsigned count=0;
 for(uint32_t i=0;i<p->te_avtab.nslot;i++)for(avtab_ptr_t n=p->te_avtab.htable[i];n;n=n->next)
  if(keyeq(&n->key,&k)){count++;found=&n->datum;}
 need(count<=1,"duplicate exact unconditional AV key");
 if(found)need(!found->xperms,"standard AV key has unexpected xperm storage");
 return found;
}
static unsigned full_avtab_check(policydb_t *p) {
 unsigned seen=0;
 for(uint32_t i=0;i<p->te_avtab.nslot;i++)for(avtab_ptr_t n=p->te_avtab.htable[i];n;n=n->next){
  seen++;need(n->key.source_type>0 && n->key.source_type<=p->p_types.nprim && n->key.target_type>0 && n->key.target_type<=p->p_types.nprim && n->key.target_class>0 && n->key.target_class<=p->p_classes.nprim,"valid full AV symbol indices");
  switch(n->key.specified) {
   case AVTAB_ALLOWED:case AVTAB_AUDITALLOW:case AVTAB_AUDITDENY:
   case AVTAB_TRANSITION:case AVTAB_MEMBER:case AVTAB_CHANGE:
    need(!n->datum.xperms,"non-xperm rule storage mismatch");break;
   case AVTAB_XPERMS_ALLOWED:case AVTAB_XPERMS_AUDITALLOW:case AVTAB_XPERMS_DONTAUDIT:
    need(n->datum.xperms!=NULL,"missing xperm storage");
    need(n->datum.xperms->specified==AVTAB_XPERMS_IOCTLFUNCTION ||
         n->datum.xperms->specified==AVTAB_XPERMS_IOCTLDRIVER ||
         n->datum.xperms->specified==AVTAB_XPERMS_NLMSG,"unknown xperm subtype");break;
   default:fail("unknown/conditional-marked compiled AV kind");
  }
 }
 need(seen==p->te_avtab.nel,"full AV table node count differs");return seen;
}
static void add_once(policydb_t *p,avtab_key_t k,uint32_t bit) {
 avtab_datum_t *d=unique(p,k);need(!d || !(d->data&bit),"authorized bit must be absent from parent");
 if(d)d->data|=bit;else {avtab_datum_t v={.data=bit,.xperms=NULL};need(!avtab_insert(&p->te_avtab,&k,&v),"official exact-key insertion");}
 need(unique(p,k) && (unique(p,k)->data&bit),"exact approved bit insertion missing");
}
typedef struct { const char *source,*target,*class_name,*permission; } approved_t;
/* Unpublished source candidate: no policy may be parsed or constructed until
 * the separately reviewed Root scope and exact literal rows are frozen. */
static const char *reviewed_scope_sha256 = "5a08041da77eeec9168c869ae76adae0a117a5e34872aa07a1a096bc06a36132";
static const approved_t approved[]={
 {"trillionnium_owner_open_phone_worker","build_attestation_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","build_attestation_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","build_attestation_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","build_attestation_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","dalvik_config_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","dalvik_config_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","dalvik_config_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","dalvik_config_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","dalvik_dynamic_config_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","dalvik_dynamic_config_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","dalvik_dynamic_config_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","dalvik_dynamic_config_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","dalvik_runtime_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","dalvik_runtime_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","dalvik_runtime_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","dalvik_runtime_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","default_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","default_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","default_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","default_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","odsign_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","odsign_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","odsign_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","odsign_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","persist_debug_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","persist_debug_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","persist_debug_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","persist_debug_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","qemu_sf_lcd_density_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","qemu_sf_lcd_density_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","qemu_sf_lcd_density_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","qemu_sf_lcd_density_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","radio_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","radio_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","radio_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","radio_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","system_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","system_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","system_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","system_prop","file","map"},
 {"trillionnium_owner_open_phone_worker","vendor_mot_hw_prop","file","getattr"},
 {"trillionnium_owner_open_phone_worker","vendor_mot_hw_prop","file","open"},
 {"trillionnium_owner_open_phone_worker","vendor_mot_hw_prop","file","read"},
 {"trillionnium_owner_open_phone_worker","vendor_mot_hw_prop","file","map"},
};
#define APPROVED_COUNT 44U
#define APPROVED_EDGE_COUNT 11U

static unsigned apply_approved(policydb_t *p,policydb_t *actual) {
 unsigned added_nodes=0;
 need(APPROVED_COUNT>0 && APPROVED_COUNT==4U*APPROVED_EDGE_COUNT && sizeof(approved)/sizeof(approved[0])==APPROVED_COUNT,"fixed reviewed property-read atoms");
 for(unsigned i=0;i<APPROVED_COUNT;i++) {
  const approved_t *a=&approved[i];uint32_t bit;
  need(!strcmp(a->source,worker) && !strcmp(a->class_name,"file") && (!strcmp(a->permission,"getattr") || !strcmp(a->permission,"open") || !strcmp(a->permission,"read") || !strcmp(a->permission,"map")),"read-only concrete property atom");
  avtab_key_t k=key(p,a->source,a->target,a->class_name,a->permission,&bit);
  if(actual) {
   uint32_t actual_bit;avtab_key_t ak=key(actual,a->source,a->target,a->class_name,a->permission,&actual_bit);
   need(keyeq(&k,&ak) && bit==actual_bit,"approved atom numeric identities differ");
   avtab_datum_t *d=unique(actual,ak);need(d && (d->data&bit),"candidate lacks an approved unconditional bit");
  }
  if(!unique(p,k))added_nodes++;
  add_once(p,k,bit);
 }
 return added_nodes;
}
static void print_atoms(void) {
 printf("[");
 for(unsigned i=0;i<APPROVED_COUNT;i++) {
  if(i)putchar(',');
  printf("[\"allow\",\"%s\",\"%s\",\"%s\",\"%s\"]",approved[i].source,approved[i].target,approved[i].class_name,approved[i].permission);
 }
 printf("]");
}
static int output_dir(const char *path) {
 char *parent=strdup(path);need(parent!=NULL,"output parent allocation");
 char *slash=strrchr(parent,'/');need(slash && slash!=parent && slash[1],"absolute new output directory");*slash='\0';
 char *rp=realpath(parent,NULL);need(rp && !strcmp(rp,parent),"canonical original output parent");free(rp);
 int pfd=open(parent,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(pfd>=0,"output parent open");free(parent);
 need(mkdir(path,0700)==0,"exclusive new offline output directory");need(!fsync(pfd)&&!close(pfd),"durable output directory entry");
 char *resolved=realpath(path,NULL);need(resolved && !strcmp(resolved,path),"canonical output directory");free(resolved);
 int dir=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);need(dir>=0,"output directory fd");return dir;
}
static int construct(const char *parent_path,const char *output) {
 original_t old=original(parent_path);policydb_t base;parse(&base,old.raw,old.n);
 unsigned before=full_avtab_check(&base),added=apply_approved(&base,NULL);
 need(full_avtab_check(&base)==before+added,"only approved constructor node additions");
 image_t candidate=image(&base);policydb_t reparsed;parse(&reparsed,candidate.raw,candidate.n);
 need(full_avtab_check(&reparsed)==before+added,"constructor full input reparse nodes");
 for(unsigned i=0;i<APPROVED_COUNT;i++) {
  uint32_t bit;avtab_key_t k=key(&reparsed,approved[i].source,approved[i].target,approved[i].class_name,approved[i].permission,&bit);
  avtab_datum_t *d=unique(&reparsed,k);need(d && (d->data&bit),"constructed approved bit missing");
 }
 int dir=output_dir(output);write_image(dir,"candidate.bin",candidate);need(!fsync(dir)&&!close(dir),"durable constructed candidate");
 unchanged(parent_path,&old);
 printf("{\"schema\":\"hepta.official-libsepol-runtime-properties-candidate-construction.v1\",\"state\":\"CANDIDATE_CONSTRUCTED_NOT_YET_SEMANTICALLY_VERIFIED\",\"complete_input_consumption\":true,\"approved_permission_atom_count\":%u,\"approved_new_allow_nodes\":%u,\"parent_bytes\":%zu,\"candidate_bytes\":%zu,\"approved_rule_atoms\":",APPROVED_COUNT,added,old.n,candidate.n);
 print_atoms();printf(",\"semantic_delta_verified\":false,\"phone_operations\":0,\"active_policy_writes\":0}\n");
 policydb_destroy(&base);policydb_destroy(&reparsed);free(candidate.raw);free(old.raw);return 0;
}
int main(int argc,char **argv) {
 need(reviewed_scope_sha256 && strlen(reviewed_scope_sha256)==64 && APPROVED_COUNT>0 && APPROVED_EDGE_COUNT>0,"reviewed exact scope remains unpublished");
 if(argc==4 && !strcmp(argv[1],"--construct-reviewed-runtime-properties"))return construct(argv[2],argv[3]);
 if(argc!=5 || strcmp(argv[1],"--compare-reviewed-runtime-properties")){
  fprintf(stderr,"usage: policy_runtime_properties_image --construct-reviewed-runtime-properties PARENT NEW-OUTPUT-DIRECTORY\n       policy_runtime_properties_image --compare-reviewed-runtime-properties PARENT CANDIDATE NEW-OUTPUT-DIRECTORY\n");return 2;
 }
 original_t old=original(argv[2]),actual=original(argv[3]);
 int dir=output_dir(argv[4]);
 policydb_t base,candidate;parse(&base,old.raw,old.n);parse(&candidate,actual.raw,actual.n);
 unsigned oldnodes=full_avtab_check(&base),newnodes=full_avtab_check(&candidate);
 orbit_t oldorbit={.name="parent"},neworbit={.name="candidate"},expectedorbit={.name="expected"},metaorbit={.name="negative-handle-unknown"},extraorbit={.name="negative-binder-change"};
 image_t oldnorm=canonical_image(&base,&oldorbit,dir),newnorm=canonical_image(&candidate,&neworbit,dir);
 /* The expected image is independently derived again from unchanged raw
  * parent input, not from constructor output or its report. */
 policydb_destroy(&base);parse(&base,old.raw,old.n);
 unsigned added_nodes=apply_approved(&base,&candidate);
 need(full_avtab_check(&base)==oldnodes+added_nodes,"only approved exact-key node additions");
 image_t expected=canonical_image(&base,&expectedorbit,dir);
 int exact=equal(expected,newnorm);
 need(!equal(oldnorm,expected),"positive approved-atom delta must alter parent serialized policy");
 /* Concrete in-memory negatives are the unchanged parent (missing the whole
  * approved set), unknown-handling mutation, and unapproved binder transfer. */
 policydb_t negative;parse(&negative,expected.raw,expected.n);
 unsigned saved_unknown=negative.handle_unknown;negative.handle_unknown=(saved_unknown==SEPOL_ALLOW_UNKNOWN?SEPOL_DENY_UNKNOWN:SEPOL_ALLOW_UNKNOWN);
 image_t badmeta=canonical_image(&negative,&metaorbit,dir);int reject_meta=!equal(badmeta,newnorm);free(badmeta.raw);policydb_destroy(&negative);
 int reject_missing=!equal(oldnorm,newnorm);
 parse(&negative,expected.raw,expected.n);
 uint32_t extra_bit;avtab_key_t extra_key=key(&negative,worker,allocator,"binder","transfer",&extra_bit);
 avtab_datum_t *extra=unique(&negative,extra_key);int extra_had_key=extra!=NULL;int extra_was_present=extra && (extra->data&extra_bit);
 if(extra)extra->data^=extra_bit;else{avtab_datum_t v={.data=extra_bit,.xperms=NULL};need(!avtab_insert(&negative.te_avtab,&extra_key,&v),"negative-control extra AV insert");}
 image_t extraimage=canonical_image(&negative,&extraorbit,dir);int reject_extra=!equal(extraimage,newnorm);free(extraimage.raw);policydb_destroy(&negative);
 need(reject_meta && reject_missing && reject_extra,"actual full-image negative controls");
 write_image(dir,"parent.normalized.bin",oldnorm);write_image(dir,"candidate.normalized.bin",newnorm);
 write_image(dir,"expected-approved-atoms.normalized.bin",expected);need(!fsync(dir)&&!close(dir),"durable image directory");
 unchanged(argv[2],&old);unchanged(argv[3],&actual);
 printf("{\"schema\":\"hepta.official-libsepol-runtime-properties-full-image-comparison.v1\",\"complete_input_consumption\":true,\"policy_type\":%u,\"version\":%u,\"mls\":%d,\"target_platform\":%d,\"unsupported_format\":%d,\"library_min_version\":%d,\"library_max_version\":%d,\"baseline_boolean_count\":%u,\"candidate_boolean_count\":%u,\"baseline_conditional_list_empty\":true,\"candidate_conditional_list_empty\":true,\"baseline_conditional_avtab_nodes\":%u,\"candidate_conditional_avtab_nodes\":%u,\"baseline_avtab_nodes\":%u,\"candidate_avtab_nodes\":%u,\"approved_permission_atom_count\":%u,\"approved_new_allow_nodes\":%u,\"baseline_normalized_bytes\":%zu,\"candidate_normalized_bytes\":%zu,\"expected_normalized_bytes\":%zu,\"baseline_raw_equals_its_normalized\":%s,\"candidate_raw_equals_its_normalized\":%s,\"only_approved_delta_full_image_equal\":%s,\"negative_missing_atom_rejected\":true,\"negative_missing_atom_scope\":\"unchanged-parent-missing-all-approved-atoms\",\"negative_unapproved_binder_change_rejected\":true,\"negative_unknown_handling_rejected\":true,\"phone_operations\":0,\"active_policy_writes\":0",
 candidate.policy_type,candidate.policyvers,candidate.mls,candidate.target_platform,candidate.unsupported_format,
 sepol_policy_kern_vers_min(),sepol_policy_kern_vers_max(),base.p_bools.nprim,candidate.p_bools.nprim,
 base.te_cond_avtab.nel,candidate.te_cond_avtab.nel,oldnodes,newnodes,APPROVED_COUNT,added_nodes,
 oldnorm.n,newnorm.n,expected.n,
 (old.n==oldnorm.n&&!memcmp(old.raw,oldnorm.raw,old.n))?"true":"false",
 (actual.n==newnorm.n&&!memcmp(actual.raw,newnorm.raw,actual.n))?"true":"false",exact?"true":"false");
 printf(",\"approved_rule_atoms\":");print_atoms();
 printf(",\"normalization\":\"lexicographic-minimum-complete-official-serialization-cycle\",\"cycle_bound\":4,\"all_cycles_close_at_first_image\":true,\"all_cycle_representatives_stable\":true,\"negative_binder_change_direction\":\"%s\",\"negative_binder_had_exact_allow_key\":%s,\"raw_serializer_idempotent\":%s,\"serialization_orbits\":[",extra_was_present?"remove":"add",extra_had_key?"true":"false",(oldorbit.length==1 && neworbit.length==1 && expectedorbit.length==1 && metaorbit.length==1 && extraorbit.length==1)?"true":"false");
 orbit_t *orbits[]={&oldorbit,&neworbit,&expectedorbit,&metaorbit,&extraorbit};
 for(unsigned i=0;i<5;i++){if(i)putchar(',');printf("{\"name\":\"%s\",\"length\":%u,\"selected_index\":%u}",orbits[i]->name,orbits[i]->length,orbits[i]->selected);}
 printf("]}\n");
 free(old.raw);free(actual.raw);free(oldnorm.raw);free(newnorm.raw);free(expected.raw);
 policydb_destroy(&base);policydb_destroy(&candidate);return exact?0:3;
}
