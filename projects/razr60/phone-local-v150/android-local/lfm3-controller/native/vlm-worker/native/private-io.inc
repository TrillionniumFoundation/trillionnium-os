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
/* Resolve each component relative to an already held directory.  realpath
 * followed by an absolute open only rejects aliases at the time of the check;
 * O_NOFOLLOW on that open does not protect ancestors replaced afterwards.
 * O_PATH requires traversal, not read permission, on Android /data ancestors. */
static bool canonical_text(const char *path) {
    if(!path||path[0]!='/')return false;
    size_t size=strnlen(path,PATH_MAX);
    if(!size||size>=PATH_MAX||!utf8((const unsigned char*)path,size))return false;
    if(size==1)return true;
    const char *part=path+1;
    for(const char *p=part;;++p) {
        if(*p!='/'&&*p)continue;
        size_t n=(size_t)(p-part);
        if(!n||(n==1&&part[0]=='.')||(n==2&&part[0]=='.'&&part[1]=='.'))return false;
        if(!*p)return true;
        part=p+1;
    }
}
static int open_canonical(const char *path,int flags) {
    if(!canonical_text(path)){errno=EINVAL;return -1;}
    if(path[1]==0)return open("/",flags|O_CLOEXEC|O_NOFOLLOW);
    int dir=open("/",O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(dir<0)return -1;
    char copy[PATH_MAX];strcpy(copy,path);
    char *part=copy+1;
    for(;;) {
        char *slash=strchr(part,'/');if(slash)*slash=0;
        int next=openat(dir,part,(slash?O_PATH|O_DIRECTORY:flags)|O_CLOEXEC|O_NOFOLLOW);
        int saved=errno;
        if(close(dir)!=0){if(next>=0)close(next);return -1;}
        if(next<0){errno=saved;return -1;}
        if(!slash) {
            /* O_PATH|O_NOFOLLOW may open a symlink itself, never accept it. */
            struct stat st;
            if(fstat(next,&st)!=0){saved=errno;close(next);errno=saved;return -1;}
            if(S_ISLNK(st.st_mode)){close(next);errno=ELOOP;return -1;}
            return next;
        }
        dir=next;part=slash+1;
    }
}
static int stat_canonical(const char *path,struct stat *out) {
    int fd=open_canonical(path,O_PATH);
    if(fd<0)return -1;
    int result=fstat(fd,out),saved=errno;
    if(close(fd)!=0)return -1;
    errno=saved;return result;
}
static bool private_directory_stat(const char *path,struct stat *out) {
    int fd=open_canonical(path,O_RDONLY|O_DIRECTORY);
    struct stat held,named;
    bool ok=fd>=0&&fstat(fd,&held)==0&&stat_canonical(path,&named)==0
        &&same_stat(&held,&named)&&S_ISDIR(held.st_mode)&&held.st_uid==getuid()
        &&(held.st_mode&0777)==0700;
    if(fd>=0&&close(fd)!=0)ok=false;
    if(ok&&out)*out=held;
    return ok;
}
typedef HeptaInput Input;
static bool read_input(Input *in,const char *path,size_t limit,bool text) {
    in->fd=-1;in->path=path;
    if(!path)return true;
    in->fd=open_canonical(path,O_RDONLY);
    if(in->fd<0||fstat(in->fd,&in->before)<0||!S_ISREG(in->before.st_mode)||in->before.st_nlink!=1||
       in->before.st_uid!=getuid()||(in->before.st_mode&0777)!=0600||in->before.st_size<=0||
       (uint64_t)in->before.st_size>limit)return false;
    in->size=(size_t)in->before.st_size;in->bytes=malloc(in->size+1);if(!in->bytes)return false;
    size_t done=0;
    while(done<in->size){ssize_t n=read(in->fd,in->bytes+done,in->size-done);if(n<0&&errno==EINTR)continue;if(n<=0)return false;done+=(size_t)n;}
    unsigned char extra;ssize_t n;do{n=read(in->fd,&extra,1);}while(n<0&&errno==EINTR);if(n!=0)return false;
    in->bytes[in->size]=0;struct stat after,named;
    if(fstat(in->fd,&after)<0||stat_canonical(path,&named)<0||!same_stat(&in->before,&after)||!same_stat(&after,&named))return false;
    if(text&&(memchr(in->bytes,0,in->size)||!utf8(in->bytes,in->size)))return false;
    hash_bytes(in->bytes,in->size,in->digest);return true;
}
static bool input_unchanged(const Input *in) {
    if(!in->path)return true;
    struct stat a,b;
    return fstat(in->fd,&a)==0&&stat_canonical(in->path,&b)==0&&same_stat(&in->before,&a)&&same_stat(&a,&b);
}
static void input_free(Input *in) { if(in->fd>=0)close(in->fd);free(in->bytes); }

typedef struct {int dir,fd;char name[201],pending[240],parent[PATH_MAX];struct stat before;bool published;} Destination;
static bool destination_unchanged(const Destination *d) {
    struct stat held,named;
    return d->dir>=0&&fstat(d->dir,&held)==0&&stat_canonical(d->parent,&named)==0
        &&same_stat(&held,&named)&&S_ISDIR(held.st_mode)
        &&held.st_dev==d->before.st_dev&&held.st_ino==d->before.st_ino
        &&held.st_uid==d->before.st_uid&&held.st_gid==d->before.st_gid
        &&held.st_mode==d->before.st_mode&&held.st_uid==getuid()&&(held.st_mode&0777)==0700;
}
static bool reserve_destination(Destination *d,const char *path,const char *id) {
    d->dir=d->fd=-1;
    if(!canonical_text(path))return false;
    const char *slash=strrchr(path,'/');size_t len=(size_t)(slash-path);
    if(len==0||strlen(slash+1)==0||strlen(slash+1)>200)return false;
    memcpy(d->parent,path,len);d->parent[len]=0;
    strcpy(d->name,slash+1);
    d->dir=open_canonical(d->parent,O_RDONLY|O_DIRECTORY);struct stat st;
    if(d->dir<0||fstat(d->dir,&d->before)<0||!destination_unchanged(d))return false;
    if(fstatat(d->dir,d->name,&st,AT_SYMLINK_NOFOLLOW)==0||errno!=ENOENT)return false;
    (void)snprintf(d->pending,sizeof(d->pending),"%s.%s.pending",d->name,id);
    d->fd=openat(d->dir,d->pending,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    return d->fd>=0&&destination_unchanged(d);
}
static bool publish(Destination *d) {
    if(!destination_unchanged(d))return false;
    if(fsync(d->fd)<0){
        int saved=errno;
        fprintf(stderr,"HEPTA_APPUID_PUBLISH stage=file_fsync file=%s errno=%d error=%s\n",d->name,saved,strerror(saved));
        return false;
    }
    /* Android app domains can forbid hard links. renameat2 NOREPLACE keeps
     * the original no-overwrite guarantee; no ordinary rename fallback. */
    if(!destination_unchanged(d))return false;
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
    if(!destination_unchanged(d))return false;
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
