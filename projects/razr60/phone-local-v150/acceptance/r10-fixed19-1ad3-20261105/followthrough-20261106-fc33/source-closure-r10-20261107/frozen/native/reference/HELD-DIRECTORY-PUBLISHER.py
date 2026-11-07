def publish_material(out,files):
 """Create a complete host artifact through held directory FDs; terminal JSON is last."""
 need(isinstance(out,Path)and out.is_absolute(),'absolute fresh material output')
 need(type(files)is dict and 'DERIVATION.json'in files,'complete material map with terminal record')
 need(0<len(files)<=256 and sum(map(len,files.values()))<=33554432,'complete bounded runtime file set')
 parents={str(parent)for name in files for parent in Path(name).parents if str(parent)!='.'}
 need(len(parents)<=128,'bounded runtime directory set')
 directories=('',)+tuple(sorted(parents,key=lambda p:(len(Path(p).parts),p)))
 for name,raw in files.items():
  need(type(name)is str and name and not any(c in name for c in '\0\r\n\t'),'plain material member')
  p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
  need(not p.is_absolute()and str(p)==name and p.name and '..'not in p.parts
   and parent in directories and name not in directories and type(raw)is bytes,'closed relative material file')
 out.mkdir(mode=0o700);created=out.lstat();handles={};identities={};members={n:set()for n in directories};observed={}
 def close_all():
  primary=sys.exc_info()[1];errors=[]
  for fd in reversed(list(handles.values())):
   try:os.close(fd)
   except BaseException as error:errors.append(error)
  if errors:
   if primary is not None:raise primary from errors[0]
   raise errors[0]
 def verify_directory(name):
  info=os.fstat(handles[name])
  if name=='':path_info=out.lstat()
  else:
   p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
   path_info=os.stat(p.name,dir_fd=handles[parent],follow_symlinks=False)
  need(stat.S_ISDIR(path_info.st_mode)and stat.S_IMODE(path_info.st_mode)==0o700
   and meta(info)[:5]==meta(path_info)[:5]==identities[name],'same owned material directory identity')
  need(set(os.listdir(handles[name]))==members[name],'exact known material directory membership')
 def verify_directories():
  for name in handles:verify_directory(name)
 def owner(name):
  p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent)
  return parent,p.name
 def readback(name,expected,first=False):
  parent,base=owner(name);verify_directories()
  fd=os.open(base,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=handles[parent])
  try:
   before=os.fstat(fd)
   need(stat.S_ISREG(before.st_mode)and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1,'private single-link material output')
   with os.fdopen(fd,'rb',closefd=False)as f:raw=f.read(len(expected)+1)
   need(raw==expected and meta(before)==meta(os.fstat(fd))
    ==meta(os.stat(base,dir_fd=handles[parent],follow_symlinks=False)),'complete created material full9/byte readback')
   if first:observed[name]=meta(before)
   else:need(observed[name]==meta(before),'created material changed before terminal publication')
  finally:os.close(fd)
  verify_directories()
 def put(name,raw):
  parent,base=owner(name);verify_directories()
  fd=os.open(base,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=handles[parent])
  with os.fdopen(fd,'wb')as f:f.write(raw);f.flush();os.fsync(f.fileno())
  members[parent].add(base);verify_directories();readback(name,raw,True)
 try:
  handles['']=os.open(out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
  identities['']=meta(created)[:5];verify_directory('')
  for name in directories[1:]:
   p=Path(name);parent=''if str(p.parent)=='.'else str(p.parent);verify_directories()
   os.mkdir(p.name,mode=0o700,dir_fd=handles[parent]);members[parent].add(p.name)
   first=os.stat(p.name,dir_fd=handles[parent],follow_symlinks=False)
   handles[name]=os.open(p.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=handles[parent])
   identities[name]=meta(first)[:5];verify_directories()
  for name,raw in sorted(files.items()):
   if name!='DERIVATION.json':put(name,raw)
  for name in sorted(observed):readback(name,files[name])
  for name in reversed(directories):os.fsync(handles[name])
  verify_directories()
  put('DERIVATION.json',files['DERIVATION.json'])
  os.fsync(handles['']);verify_directories()
 finally:close_all()
