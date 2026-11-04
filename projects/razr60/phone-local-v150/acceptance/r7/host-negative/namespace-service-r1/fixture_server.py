#!/usr/bin/env python3
"""One synthetic held HTTP request in a private network namespace; no model."""
import argparse,hashlib,http.server,json,os,re,select,signal,socket,threading,time
from pathlib import Path
def write(path,value):
 raw=(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
 fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 os.umask(0o077);a.out.mkdir(mode=0o700)
 stop=threading.Event();request_ended=threading.Event();lock=threading.Lock();state={'post_count':0,'active':False,'get_count':0,'request_terminal':None}
 started=time.monotonic()
 def on_signal(n,f):stop.set()
 for n in (signal.SIGTERM,signal.SIGINT):signal.signal(n,on_signal)
 class Handler(http.server.BaseHTTPRequestHandler):
  protocol_version='HTTP/1.1'
  def log_message(self,*a):pass
  def answer(self,code,value):
   raw=json.dumps(value,separators=(',',':')).encode()
   self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers()
   try:self.wfile.write(raw);self.wfile.flush()
   except (BrokenPipeError,ConnectionResetError):pass
  def do_GET(self):
   if self.path!='/slots':return self.answer(404,{'error':'fixture route absent'})
   with lock:initially_active=state['active']
   # One bounded slot response may await the real request-handler EOF observation.
   # This never changes active or forces a client/socket terminal.
   wait_started=time.monotonic()
   if initially_active:request_ended.wait(.1)
   with lock:
    state['get_count']+=1;n=state['get_count'];active=state['active']
   write(a.out/('slot-%03d.json'%n),{'synthetic':True,'observed_monotonic':time.monotonic(),'initially_active':initially_active,'bounded_wait_seconds':time.monotonic()-wait_started,'active':active})
   self.answer(200,[{'id':0,'id_task':1,'is_processing':active}])
  def do_POST(self):
   if self.path!='/v1/chat/completions':return self.answer(404,{'error':'fixture route absent'})
   size=int(self.headers.get('Content-Length','0'))
   if not 0<size<=2*1024*1024:return self.answer(413,{'error':'fixture request bound'})
   raw=self.rfile.read(size);rid=self.headers.get('X-HEPTA-Request-ID','')
   with lock:
    state['post_count']+=1;n=state['post_count']
    if n==1:state['active']=True
   if n!=1:return self.answer(409,{'error':'fixture permits exactly one original request'})
   value=json.loads(raw)
   write(a.out/'REQUEST.json',{'synthetic':True,'request_id':rid,'request_bytes':len(raw),'request_sha256':hashlib.sha256(raw).hexdigest(),'body':value,'started_monotonic':time.monotonic(),'real_model':False})
   outcome='unknown';deadline=time.monotonic()+5
   try:
    while time.monotonic()<deadline and not stop.is_set():
     ready=select.select([self.connection],[],[],.01)[0]
     if ready and self.connection.recv(1,socket.MSG_PEEK)==b'':
      outcome='original_client_connection_closed_without_response';break
    else:outcome='fixture_deadline_or_stop'
   except (OSError,ConnectionError) as e:outcome='original_client_connection_error:'+type(e).__name__
   finally:
    with lock:state['active']=False;state['request_terminal']=outcome
    write(a.out/'REQUEST-TERMINAL.json',{'synthetic':True,'request_id':rid,'terminal':outcome,'ended_monotonic':time.monotonic(),'response_sent':False,'real_model':False})
    request_ended.set()
 class Server(http.server.ThreadingHTTPServer):
  daemon_threads=False
  block_on_close=True
 server=Server(('127.0.0.1',18099),Handler);server.timeout=.1
 write(a.out/'READY.json',{'pid':os.getpid(),'pgid':os.getpgrp(),'sid':os.getsid(0),'endpoint':'http://127.0.0.1:18099/v1/chat/completions','netns':os.readlink('/proc/self/ns/net'),'mode':'synthetic-one-hold-no-model','monotonic':time.monotonic()})
 try:
  while not stop.is_set() and time.monotonic()-started<35:server.handle_request()
 finally:
  stop.set();server.server_close()
  with lock:final=dict(state)
  final.update(synthetic=True,ended_monotonic=time.monotonic(),real_model_requests=0)
  write(a.out/'EXIT.json',final)
 return 0
if __name__=='__main__':raise SystemExit(main())
