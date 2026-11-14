
/* Host boundary only: actual generation entry/cleanup with a fixed fake SDK.
 * Fork modes run before any SDK init/create or READY. */
static int hepta_scope_fixture(int argc,char **argv) {
    if(argc==3&&!strcmp(argv[1],"--fixture-group-presence")){
        Input input={.fd=-1};HgIdentity id;
        if(!read_input(&input,argv[2],HG_ID_LIMIT-1,true)
            ||!hg_parse_identity(input.bytes,input.size,&id)||!hg_caller(&id)){input_free(&input);return 104;}
        HgPresence p=hg_group_presence(&id);
        printf("{\"pgid\":%ld,\"monotonic_ns\":%" PRIu64 ",\"result\":%d,\"errno\":%d}\n",
                p.pgid,p.observed,p.result,p.error);
        input_free(&input);return 0;
    }
    if(argc==12&&!strcmp(argv[1],"--hepta-owned-generation-cleanup-v1"))
        return hepta_owned_generation_cleanup(argc,argv);
    if(argc!=6||strcmp(argv[1],"--fixture-scope"))return 91;
    const char *files=argv[2],*generation=argv[3],*task=argv[4],*mode=argv[5];
    char dir[PATH_MAX],child_file[PATH_MAX];
    if(snprintf(dir,sizeof(dir),"%s/runs/%s",files,generation)>=(int)sizeof(dir)
        ||snprintf(child_file,sizeof(child_file),"%s/fixture-child.pid",dir)>=(int)sizeof(child_file))return 92;
    if(!strcmp(mode,"missing-identity"))return 0;
    if(hepta_arm_parent_death_guard(getppid())!=0
        ||!hepta_owned_generation_enter(dir,generation,task,getppid()))return 93;
    if(calls_init||calls_create||calls_generate)return 94;
    if(!strcmp(mode,"exit0"))return 0;
    if(!strcmp(mode,"exit70"))return 70;
    if(!strcmp(mode,"hold-exit")){char c;return read(STDIN_FILENO,&c,1)<0?95:0;}
    if(!strcmp(mode,"pause")){for(;;)pause();}
    int ready[2];
    if(pipe(ready)!=0)return 96;
    pid_t child=fork();
    if(child<0)return 97;
    if(child==0){
        close(ready[0]);
        if(!strcmp(mode,"fork-ignore"))signal(SIGTERM,SIG_IGN);
        if(!strcmp(mode,"fork-unreadable")||!strcmp(mode,"fork-escape-unreadable"))(void)prctl(PR_SET_DUMPABLE,0);
        if((!strcmp(mode,"fork-escape")||!strcmp(mode,"fork-escape-unreadable"))&&setpgid(0,0)!=0)_exit(98);
        if(write(ready[1],"r",1)!=1)_exit(99);
        close(ready[1]);
        if(!strcmp(mode,"fork-exec")||!strcmp(mode,"fork-wrong-token")){
            if(!strcmp(mode,"fork-wrong-token"))
                setenv("HEPTA_WORKER_SCOPE_TOKEN","ffffffffffffffffffffffffffffffff",1);
            char *args[]={(char*)"sleep",(char*)"60",NULL};
            execv("/bin/sleep",args);_exit(100);
        }
        for(;;)pause();
    }
    close(ready[1]);char ack;
    if(read(ready[0],&ack,1)!=1){close(ready[0]);return 101;}
    close(ready[0]);
    FILE *f=fopen(child_file,"wx");
    if(!f)return 102;
    if(fprintf(f,"%ld\n",(long)child)<0||fflush(f)!=0||fsync(fileno(f))!=0||fclose(f)!=0)return 103;
    if(!strcmp(mode,"fork-live-parent")){for(;;)pause();}
    return 0;
}
int main(int argc,char **argv){return hepta_scope_fixture(argc,argv);}
