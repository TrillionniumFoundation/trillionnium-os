/* Bounded ASCII IPC. Paths/configuration come from the app-owned initial argv;
 * subsequent requests can change only HEX32 request ID, token bound, deadline. */
static char hepta_warm_session_dir[PATH_MAX];
static int hepta_warm_completed_count,hepta_warm_control_fd=-1;
static int hepta_take_warm_arguments(int *argc,char **argv) {
    bool generation=false,task=false,directory=false;
    for(int i=1;i<*argc;){
        char *target=NULL;size_t bound=0;bool *seen=NULL;
        if(!strcmp(argv[i],"--warm-generation")){target=hepta_warm_generation;bound=sizeof(hepta_warm_generation);seen=&generation;}
        else if(!strcmp(argv[i],"--warm-task-id")){target=hepta_warm_task_id;bound=sizeof(hepta_warm_task_id);seen=&task;}
        else if(!strcmp(argv[i],"--warm-session-dir")){target=hepta_warm_session_dir;bound=sizeof(hepta_warm_session_dir);seen=&directory;}
        if(!target){i++;continue;}
        if(*seen||i+1>=*argc||strlen(argv[i+1])>=bound)return -1;
        strcpy(target,argv[i+1]);*seen=true;
        for(int j=i;j+2<*argc;j++)argv[j]=argv[j+2];
        *argc-=2;argv[*argc]=NULL;
    }
    if(!generation&&!task&&!directory)return 0;
    if(!generation||!task||!directory||!id_ok(hepta_warm_generation)||!id_ok(hepta_warm_task_id)
       ||!canonical(hepta_warm_session_dir))return -1;
    struct stat st;
    if(lstat(hepta_warm_session_dir,&st)<0||!S_ISDIR(st.st_mode)||st.st_uid!=getuid()||(st.st_mode&0777)!=0700)return -1;
    hepta_warm_enabled=true;return 0;
}
static bool hepta_warm_prepare_control(void) {
    if(!hepta_warm_enabled)return true;
    hepta_warm_control_fd=dup(STDOUT_FILENO);
    return hepta_warm_control_fd>=0&&fcntl(hepta_warm_control_fd,F_SETFD,FD_CLOEXEC)==0
        &&fflush(stdout)==0&&dup2(STDERR_FILENO,STDOUT_FILENO)>=0;
}
static bool hepta_warm_send(const char *format,...) {
    char frame[256];va_list args;va_start(args,format);
    int size=vsnprintf(frame,sizeof(frame),format,args);va_end(args);
    return size>0&&(size_t)size<sizeof(frame)&&write_all(hepta_warm_control_fd,frame,(size_t)size);
}
static int hepta_warm_line(char line[256]) {
    size_t used=0;
    while(!cancel_signal){
        unsigned char c;ssize_t count=read(STDIN_FILENO,&c,1);
        if(count<0&&errno==EINTR)continue;
        if(count==0)return used?-1:0;
        if(count!=1||c<32||c>126){if(count==1&&c=='\n'&&used){line[used]=0;return 1;}return -1;}
        if(used>=255)return -1;
        line[used++]=(char)c;
    }
    return -1;
}
static bool hepta_warm_terminal(const Options *o,bool close_requested,int status) {
    bool unchanged=hepta_model_verified&&hepta_model_is_unchanged(o->model);
    int32_t destroy_rc=0,deinit_rc=0;bool destroyed=hepta_warm_llm!=NULL,deinitialized=hepta_warm_initialized;
    if(hepta_warm_llm){destroy_rc=geniex_llm_destroy(hepta_warm_llm);hepta_warm_llm=NULL;}
    if(hepta_warm_initialized){deinit_rc=geniex_deinit();hepta_warm_initialized=false;}
    hepta_model_cleanup();
    char path[PATH_MAX];
    if(snprintf(path,sizeof(path),"%s/native-session-result.json",hepta_warm_session_dir)>=(int)sizeof(path))return false;
    Destination dest={.dir=-1,.fd=-1};bool ok=false;
    if(!reserve_destination(&dest,path,hepta_warm_generation))goto terminal_close;
    FILE *f=fdopen(dup(dest.fd),"w");if(!f)goto terminal_close;
    fputs("{\"schema\":\"hepta.geniex-task-session.result.v1\",\"process_exit_observed\":false,\"worker_generation\":",f);
    json_string(f,hepta_warm_generation);fputs(",\"task_id\":",f);json_string(f,hepta_warm_task_id);
    fprintf(f,",\"pid\":%ld,\"requests_received\":%d,\"requests_completed\":%d,\"model_hash_count\":%d,"
        "\"sdk_init_count\":%d,\"model_create_count\":%d,\"model_reset_count\":%d,"
        "\"model_metadata_unchanged_before_close\":%s,\"close_requested\":%s,\"signal_observed\":%d,"
        "\"last_request_status\":%d,\"sdk_destroy_attempted\":%s,\"sdk_destroy_rc\":%" PRId32 ","
        "\"sdk_deinit_attempted\":%s,\"sdk_deinit_rc\":%" PRId32 "}\n",
        (long)getpid(),hepta_warm_sequence,hepta_warm_completed_count,hepta_warm_hash_count,
        hepta_warm_init_count,hepta_warm_create_count,hepta_warm_reset_count,unchanged?"true":"false",
        close_requested?"true":"false",(int)cancel_signal,status,destroyed?"true":"false",destroy_rc,
        deinitialized?"true":"false",deinit_rc);
    ok=fflush(f)==0&&!ferror(f);if(fclose(f)!=0)ok=false;
    if(ok)ok=publish(&dest);
    ok=ok&&destroy_rc==0&&deinit_rc==0;
terminal_close:
    destination_close(&dest);return ok;
}
static int hepta_warm_loop(int argc,char **argv) {
    Options initial;if(!parse(argc,argv,&initial)||strcmp(initial.mode,"llm")||strcmp(initial.runtime,"llama_cpp")
        ||!initial.system||!initial.grammar||initial.image||initial.mmproj||initial.tokenizer||initial.vit)return 64;
    char root[PATH_MAX];if(strlen(initial.prompt)>=sizeof(root))return 64;strcpy(root,initial.prompt);
    char *slash=strrchr(root,'/');if(!slash||strcmp(slash,"/prompt.txt"))return 64;*slash=0;
    slash=strrchr(root,'/');if(!slash||!id_ok(slash+1))return 64;*slash=0;
    if(!canonical(root)||!install_signals())return 64;
    char session_parent[PATH_MAX];strcpy(session_parent,hepta_warm_session_dir);
    slash=strrchr(session_parent,'/');if(!slash||strcmp(slash+1,hepta_warm_generation))return 64;*slash=0;
    if(strcmp(session_parent,root))return 64;
    if(!hepta_warm_send("HEPTA_WARM_READY %s %s %ld\n",hepta_warm_generation,hepta_warm_task_id,(long)getpid()))return 74;
    char seen[64][33];int status=0;bool close_requested=false;
    for(;;){
        char line[256];int got=hepta_warm_line(line);if(got!=1){status=cancel_signal?128+(int)cancel_signal:70;break;}
        char *parts[8],*save=NULL;int count=0;
        for(char *part=strtok_r(line," ",&save);part;part=strtok_r(NULL," ",&save)){
            if(count==8){count=9;break;}parts[count++]=part;
        }
        if(count==3&&!strcmp(parts[0],"CLOSE")&&!strcmp(parts[1],hepta_warm_generation)&&!strcmp(parts[2],hepta_warm_task_id)){
            close_requested=true;break;
        }
        int seq,tokens,timeout;
        if(count!=7||strcmp(parts[0],"RUN")||strcmp(parts[1],hepta_warm_generation)||strcmp(parts[2],hepta_warm_task_id)
            ||!id_ok(parts[3])||!strcmp(parts[3],hepta_warm_generation)||!number(parts[4],1,64,&seq)
            ||seq!=hepta_warm_sequence+1||!number(parts[5],1,1024,&tokens)||!number(parts[6],1000,300000,&timeout)){
            status=64;break;
        }
        bool duplicate=false;for(int i=0;i<hepta_warm_sequence;i++)if(!strcmp(seen[i],parts[3]))duplicate=true;
        if(duplicate){status=64;break;}strcpy(seen[seq-1],parts[3]);hepta_warm_sequence=seq;
        char prompt[PATH_MAX],system[PATH_MAX],grammar[PATH_MAX],result[PATH_MAX],text[PATH_MAX];
        const char *names[]={"prompt.txt","system.txt","grammar.gbnf","native-result.json","raw-text.txt"};
        char *paths[]={prompt,system,grammar,result,text};bool fits=true;
        for(unsigned i=0;i<5;i++)if(snprintf(paths[i],PATH_MAX,"%s/%s/%s",root,parts[3],names[i])>=PATH_MAX)fits=false;
        if(!fits){status=64;break;}
        char *request_argv[64];if(argc>=64){status=64;break;}
        for(int i=0;i<=argc;i++)request_argv[i]=argv[i];
        for(int i=1;i+1<argc;i+=2){
            if(!strcmp(argv[i],"--request-id"))request_argv[i+1]=parts[3];
            else if(!strcmp(argv[i],"--prompt-file"))request_argv[i+1]=prompt;
            else if(!strcmp(argv[i],"--system-file"))request_argv[i+1]=system;
            else if(!strcmp(argv[i],"--grammar-file"))request_argv[i+1]=grammar;
            else if(!strcmp(argv[i],"--result-file"))request_argv[i+1]=result;
            else if(!strcmp(argv[i],"--text-file"))request_argv[i+1]=text;
            else if(!strcmp(argv[i],"--max-tokens"))request_argv[i+1]=parts[5];
            else if(!strcmp(argv[i],"--timeout-ms"))request_argv[i+1]=parts[6];
        }
        deadline_hit=false;callback_limit=false;callback_count=callback_bytes=callback_retained=0;
        hepta_warm_reset_rc=-1;hepta_model_unchanged=false;
        hepta_prompt_budget=(HeptaPromptBudget){.exact=hepta_model_profile->exact_tokens,.model_sha256=hepta_model_profile->sha256};
        hepta_prompt_evidence_complete=false;
        memset(hepta_phase_timings,0,sizeof(hepta_phase_timings));
        status=upstream_worker_main(argc,request_argv);
        if(status==0)hepta_warm_completed_count++;
        if(!hepta_warm_send("HEPTA_WARM_DONE %s %s %s %d %d\n",hepta_warm_generation,hepta_warm_task_id,parts[3],seq,status)){
            status=74;break;
        }
        if(status!=0||cancel_signal)break;
    }
    if(!hepta_warm_terminal(&initial,close_requested,status))status=74;
    close(hepta_warm_control_fd);return status;
}
