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
