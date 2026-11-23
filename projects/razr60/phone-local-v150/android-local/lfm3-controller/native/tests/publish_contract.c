#define _GNU_SOURCE 1
/* Use the production IO definitions. Keep this test calling the separate
 * generated-text publication include, with its original assertions intact. */
#define publish vlm_fixture_publish
#include "../vlm-worker/native/generation-bridge.c"
#undef publish
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include "../publish-appuid.inc"
static const char *fixture_directory;
static void bind_directory(Destination *d){
    assert(strlen(fixture_directory)<sizeof(d->parent));strcpy(d->parent,fixture_directory);
    assert(fstat(d->dir,&d->before)==0);assert(destination_unchanged(d));
}
static Destination pending(int dir,const char *name,const char *tmp,const char *bytes){
    Destination d={.dir=dir,.fd=openat(dir,tmp,O_CREAT|O_EXCL|O_WRONLY,0600)};
    bind_directory(&d);
    assert(d.fd>=0);strcpy(d.name,name);strcpy(d.pending,tmp);assert(write(d.fd,bytes,strlen(bytes))==(ssize_t)strlen(bytes));return d;
}
static void expect(int dir,const char *name,const char *bytes){
    char value[64]={0};int fd=openat(dir,name,O_RDONLY);assert(fd>=0);ssize_t n=read(fd,value,sizeof(value)-1);assert(n==(ssize_t)strlen(bytes));assert(!memcmp(value,bytes,(size_t)n));close(fd);
}
int main(void){
    char path[]="/tmp/hepta-publish-contract-XXXXXX";assert(mkdtemp(path));int dir=open(path,O_RDONLY|O_DIRECTORY);assert(dir>=0);
    fixture_directory=path;
    Destination a=pending(dir,"result","one.pending","original");assert(publish(&a)&&a.published);assert(faccessat(dir,"one.pending",F_OK,0)<0&&errno==ENOENT);expect(dir,"result","original");close(a.fd);
    Destination b=pending(dir,"result","two.pending","replacement");assert(!publish(&b)&&!b.published);expect(dir,"result","original");expect(dir,"two.pending","replacement");close(b.fd);
    assert(symlinkat("result",dir,"link-result")==0);Destination c=pending(dir,"link-result","three.pending","other");assert(!publish(&c));struct stat st;assert(fstatat(dir,"link-result",&st,AT_SYMLINK_NOFOLLOW)==0&&S_ISLNK(st.st_mode));expect(dir,"result","original");close(c.fd);
    Destination empty=pending(dir,"empty-result","empty.pending","");assert(publish(&empty));expect(dir,"empty-result","");close(empty.fd);
    Destination invalid={.dir=dir,.fd=-1};bind_directory(&invalid);strcpy(invalid.name,"invalid-result");strcpy(invalid.pending,"missing.pending");assert(!publish(&invalid));assert(errno==EBADF);assert(faccessat(dir,"invalid-result",F_OK,0)<0);
    const char *files[]={"result","two.pending","link-result","three.pending","empty-result"};for(unsigned i=0;i<sizeof(files)/sizeof(files[0]);i++)assert(unlinkat(dir,files[i],0)==0);close(dir);assert(rmdir(path)==0);
    puts("PASS: fresh publication, no-clobber collision, symlink collision, empty output, fsync failure");return 0;
}
