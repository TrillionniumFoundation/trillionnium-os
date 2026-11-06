def read(desc):
 need(type(desc)is dict and set(desc)=={'path','bytes','sha256'},'exact source descriptor')
 need(type(desc['path'])is str and type(desc['bytes'])is int and 0<desc['bytes']<=1048576
  and type(desc['sha256'])is str and re.fullmatch('[0-9a-f]{64}',desc['sha256']),'bounded typed source descriptor')
 p=Path(desc['path']);need(p.is_absolute()and p.parent.resolve(strict=True)==p.parent,'canonical source parent')
 fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
 try:
  a=os.fstat(fd);need(stat.S_ISREG(a.st_mode)and a.st_nlink==1 and a.st_size==desc['bytes'],'exact single-link source')
  chunks=[];n=0
  while n<=a.st_size:
   b=os.read(fd,min(65536,a.st_size+1-n))
   if not b:break
   n+=len(b);chunks.append(b)
  raw=b''.join(chunks)
  need(pin(raw)=={k:desc[k]for k in ('bytes','sha256')}and meta(a)==meta(os.fstat(fd))==meta(p.lstat()),'full source bytes/hash/metadata')
 finally:os.close(fd)
 row=dict(desc,metadata=meta(a));need(str(p)not in BOOK or BOOK[str(p)]==row,'stable source original')
 BOOK[str(p)]=row;return raw
