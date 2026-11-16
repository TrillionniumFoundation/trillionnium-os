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
static bool same_stat(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&
        a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&
        a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static bool canonical(const char *path) {
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX||!utf8((const unsigned char*)path,strlen(path)))return false;
    char real[PATH_MAX];return realpath(path,real)&&strcmp(real,path)==0;
}
typedef HeptaInput Input;
static bool read_input(Input *in,const char *path,size_t limit,bool text) {
    in->fd=-1;in->path=path;
    if(!path)return true;
    if(!canonical(path))return false;
    in->fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(in->fd<0||fstat(in->fd,&in->before)<0||!S_ISREG(in->before.st_mode)||in->before.st_nlink!=1||
       in->before.st_uid!=getuid()||(in->before.st_mode&0777)!=0600||in->before.st_size<=0||
       (uint64_t)in->before.st_size>limit)return false;
    in->size=(size_t)in->before.st_size;in->bytes=malloc(in->size+1);if(!in->bytes)return false;
    size_t done=0;
    while(done<in->size){ssize_t n=read(in->fd,in->bytes+done,in->size-done);if(n<0&&errno==EINTR)continue;if(n<=0)return false;done+=(size_t)n;}
    unsigned char extra;ssize_t n;do{n=read(in->fd,&extra,1);}while(n<0&&errno==EINTR);if(n!=0)return false;
    in->bytes[in->size]=0;struct stat after,named;
    if(fstat(in->fd,&after)<0||lstat(path,&named)<0||!same_stat(&in->before,&after)||!same_stat(&after,&named))return false;
    if(text&&(memchr(in->bytes,0,in->size)||!utf8(in->bytes,in->size)))return false;
    hash_bytes(in->bytes,in->size,in->digest);return true;
}
static bool input_unchanged(const Input *in) {
    if(!in->path)return true;
    struct stat a,b;
    return fstat(in->fd,&a)==0&&lstat(in->path,&b)==0&&same_stat(&in->before,&a)&&same_stat(&a,&b);
}
static void input_free(Input *in) { if(in->fd>=0)close(in->fd);free(in->bytes); }

typedef struct {int dir,fd;char name[201],pending[240];bool published;} Destination;
static bool reserve_destination(Destination *d,const char *path,const char *id) {
    d->dir=d->fd=-1;
    if(!path||path[0]!='/'||strlen(path)>=PATH_MAX)return false;
    const char *slash=strrchr(path,'/');size_t len=(size_t)(slash-path);
    if(len==0||strlen(slash+1)==0||strlen(slash+1)>200)return false;
    char parent[PATH_MAX];memcpy(parent,path,len);parent[len]=0;
    if(!canonical(parent)||!utf8((const unsigned char*)(slash+1),strlen(slash+1)))return false;
    strcpy(d->name,slash+1);if(!strcmp(d->name,".")||!strcmp(d->name,".."))return false;
    d->dir=open(parent,O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_NOFOLLOW);struct stat st;
    if(d->dir<0||fstat(d->dir,&st)<0||st.st_uid!=getuid()||(st.st_mode&0777)!=0700)return false;
    if(fstatat(d->dir,d->name,&st,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return false;
    (void)snprintf(d->pending,sizeof(d->pending),"%s.%s.pending",d->name,id);
    d->fd=openat(d->dir,d->pending,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    return d->fd>=0;
}
static bool publish(Destination *d) {
    if(fsync(d->fd)<0){
        int saved=errno;
        fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=file_fsync file=%s errno=%d error=%s\n",d->name,saved,strerror(saved));
        return false;
    }
    /* Android app domains can forbid hard links. renameat2 NOREPLACE keeps
     * the original no-overwrite guarantee; no ordinary rename fallback. */
    if(syscall(SYS_renameat2,d->dir,d->pending,d->dir,d->name,RENAME_NOREPLACE)<0){
        int saved=errno;
        fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=renameat2_noreplace file=%s errno=%d error=%s\n",d->name,saved,strerror(saved));
        return false;
    }
    if(fsync(d->dir)<0){
        int saved=errno;
        fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=directory_fsync file=%s errno=%d error=%s\n",d->name,saved,strerror(saved));
        return false;
    }
    fprintf(stderr,"HEPTA_APPUID_PUBLISH method=renameat2_noreplace file=%s published=true\n",d->name);
    d->published=true;return true;
}

static void destination_close(Destination *d) {
    if(d->fd>=0)close(d->fd);
    if(d->dir>=0)close(d->dir);
    /* Failed/incomplete pending files deliberately remain as incomplete data. */
}
static bool write_all(int fd,const void *data,size_t size) {
    const unsigned char *p=data;
    while(size){ssize_t n=write(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)return false;p+=n;size-=(size_t)n;}return true;
}

static bool id_ok(const char *s) {
    if(!s||strlen(s)!=32)return false;
    for(size_t i=0;i<32;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
    return true;
}
