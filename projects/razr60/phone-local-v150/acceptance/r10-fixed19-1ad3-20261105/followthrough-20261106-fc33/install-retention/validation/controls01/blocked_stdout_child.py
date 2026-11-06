import importlib.util,json,os,sys,time
p=sys.argv[1];s=importlib.util.spec_from_file_location('retention',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r,w=os.pipe();os.set_blocking(w,False)
try:
 while True:os.write(w,b'x'*65536)
except BlockingIOError:pass
os.set_blocking(w,True);saved=os.dup(1);os.dup2(w,1);start=time.monotonic();before=[os.getpid(),os.getpgrp(),os.getsid(0)]
try:
 try:m.write_response(b'z',time.monotonic()+0.15)
 except ValueError as e:error=str(e)
 else:raise AssertionError('full pipe accepted')
 blocking=os.get_blocking(1)
finally:os.dup2(saved,1);os.close(saved);os.close(w);os.close(r)
print(json.dumps(dict(error=error,elapsed=time.monotonic()-start,same_process=before==[os.getpid(),os.getpgrp(),os.getsid(0)],blocking_restored=blocking)))
