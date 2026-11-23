
/* Synthetic proc-files boundary: execute the production UID parser and the
 * production mixed-UID exclusion against one held directory descriptor.
 * No /proc filtering, process signal, SDK, Android or phone call occurs here. */
static bool mixed_fixture_replace(int directory,const char *leaf) {
    char after[48];unsigned char bytes[32769];size_t length=0;
    if(snprintf(after,sizeof(after),"after-%s",leaf)>=(int)sizeof(after))return false;
    if(hg_read_at(directory,after,bytes,32768,&length)!=0){
        if(errno!=ENOENT)return false;
        return unlinkat(directory,leaf,0)==0||errno==ENOENT;
    }
    int output=openat(directory,leaf,O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC|O_NOFOLLOW,0600);
    if(output<0)return false;
    bool ok=write_all(output,bytes,length);
    if(close(output)!=0)ok=false;
    return ok;
}
int main(int argc,char **argv) {
    if(argc!=6)return 90;
    uint64_t pid,leader,start,pgid;
    if(!hg_decimal(argv[2],INT_MAX,&pid)||!hg_decimal(argv[3],INT_MAX,&leader)
            ||!hg_decimal(argv[4],UINT64_MAX,&start)||!hg_decimal(argv[5],INT_MAX,&pgid))return 91;
    int fd=open(argv[1],O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return 92;
    HgProcess observed={.fd=fd,.pid=(long)pid};
    bool stat_ok=hg_proc_stat(&observed);
    HgUidKind kind=hg_proc_uid_kind(&observed);
    HgProcess strict=observed;
    bool strict_uid=hg_proc_uid(&strict);
    HgIdentity identity={.leader_pid=(long)leader,.leader_start=start,.pgid=(long)pgid,.uid=1001};
    if(!mixed_fixture_replace(fd,"stat")||!mixed_fixture_replace(fd,"status")){close(fd);return 93;}
    bool excluded=kind==HG_UID_MIXED&&hg_mixed_older_unrelated(&observed,&identity,stat_ok);
    printf("{\"stat_ok\":%s,\"uid_kind\":%d,\"strict_uid\":%s,\"excluded\":%s,"
           "\"same_held_fd\":%s,\"sdk_calls\":%d,\"first_uid_values\":[%lu,%lu,%lu,%lu]}\n",
        stat_ok?"true":"false",(int)kind,strict_uid?"true":"false",excluded?"true":"false",
        observed.fd==fd?"true":"false",calls_init+calls_create+calls_generate,
        observed.uids[0],observed.uids[1],observed.uids[2],observed.uids[3]);
    if(close(fd)!=0)return 94;
    return 0;
}
