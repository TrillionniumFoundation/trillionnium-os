#!/usr/bin/env python3
"""Deterministic host-only HTTP peer for frozen provider; not a language model."""
import argparse,hashlib,http.server,json,os,select,signal,socket,threading,time
from pathlib import Path
def write(p,value):
 raw=(json.dumps(value,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--mode',choices=('hold','open'),required=True);a=p.parse_args()
 os.umask(0o077);a.out.mkdir(mode=0o700)
 stop=threading.Event();ended=threading.Event();lock=threading.Lock()
 state={'post_count':0,'get_count':0,'active':False,'request_terminal':None}
 started=time.monotonic()
 def stopping(n,f):stop.set()
 for n in (signal.SIGTERM,signal.SIGINT):signal.signal(n,stopping)
 class Handler(http.server.BaseHTTPRequestHandler):
  protocol_version='HTTP/1.1'
  def log_message(self,*args):pass
  def answer(self,status,value):
   raw=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
   self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.send_header('Connection','close');self.end_headers()
   self.wfile.write(raw);self.wfile.flush()
   return raw
  def do_GET(self):
   if self.path!='/slots':
    return self.answer(404,{'fixture_error':'unavailable route'})
   with lock:was_active=state['active']
   wait_start=time.monotonic()
   if was_active:ended.wait(.1)
   with lock:
    state['get_count']+=1;n=state['get_count'];active=state['active']
   write(a.out/('slot-%03d.json'%n),{'synthetic':True,'active':active,'observed_monotonic':time.monotonic(),'initially_active':was_active,'bounded_wait_seconds':time.monotonic()-wait_start})
   self.answer(200,[{'id':0,'id_task':1,'is_processing':active}])
  def do_POST(self):
   if self.path!='/v1/chat/completions':return self.answer(404,{'fixture_error':'unavailable route'})
   size=int(self.headers.get('Content-Length','0'))
   if not 0<size<=2*1024*1024:return self.answer(413,{'fixture_error':'request bound'})
   raw=self.rfile.read(size);rid=self.headers.get('X-HEPTA-Request-ID','')
   with lock:
    state['post_count']+=1;n=state['post_count']
    if n==1:state['active']=True
   write(a.out/('POST-%03d.json'%n),{'synthetic':True,'request_id':rid,'request_bytes':len(raw),'request_sha256':hashlib.sha256(raw).hexdigest(),'body':json.loads(raw),'started_monotonic':time.monotonic(),'actual_model_inference':False})
   if n!=1:return self.answer(409,{'fixture_error':'one original request only; replay refused'})
   outcome='unknown';sent=False;response_sha=None
   try:
    body=json.loads(raw)
    if a.mode=='hold':
     deadline=time.monotonic()+12
     while time.monotonic()<deadline and not stop.is_set():
      if select.select([self.connection],[],[],.01)[0] and self.connection.recv(1,socket.MSG_PEEK)==b'':
       outcome='original_client_eof_without_response';break
     else:outcome='fixture_bound_or_stop'
    else:
     schema=body['response_format']['json_schema']['schema']
     branch=next(x for x in schema['oneOf'] if x['properties']['tool']=={'const':'phone.open_app'})
     props=branch['properties'];aliases=props['argv']['items']['enum']
     alias='设置' if '设置' in aliases else aliases[0]
     decision={'kind':'tool.call','call_id':props['call_id']['const'],'tool':'phone.open_app','command':'','argv':[alias],
               'summary':'Synthetic host fixture requests one disposable executor counter; no phone operation is executed.','task_status':'in_progress'}
     response={'model':body['model'],'choices':[{'message':{'role':'assistant','content':json.dumps(decision,ensure_ascii=False,separators=(',',':'))},'finish_reason':'stop'}],
               'usage':None,'timings':None}
     output=self.answer(200,response);sent=True;response_sha=hashlib.sha256(output).hexdigest()
     write(a.out/'RESPONSE.json',{'synthetic':True,'body':response,'raw_sha256':response_sha,'raw_bytes':len(output),'actual_model_inference':False})
     outcome='fixture_response_written'
   except (OSError,ValueError,KeyError,StopIteration) as ex:outcome='fixture_handler_error:'+type(ex).__name__+':'+str(ex)
   finally:
    with lock:state['active']=False;state['request_terminal']=outcome
    write(a.out/'POST-TERMINAL.json',{'synthetic':True,'request_id':rid,'outcome':outcome,'response_sent':sent,'response_sha256':response_sha,'ended_monotonic':time.monotonic(),'actual_model_inference':False})
    ended.set()
 class Server(http.server.ThreadingHTTPServer):
  daemon_threads=False
  block_on_close=True
 srv=Server(('127.0.0.1',18099),Handler);srv.timeout=.1
 write(a.out/'READY.json',{'pid':os.getpid(),'pgid':os.getpgrp(),'sid':os.getsid(0),'netns':os.readlink('/proc/self/ns/net'),'mode':a.mode,'synthetic':True,'actual_model_inference':False,'endpoint':'http://127.0.0.1:18099/v1/chat/completions'})
 try:
  while not stop.is_set() and time.monotonic()-started<60:srv.handle_request()
 finally:
  stop.set();srv.server_close()
  with lock:result=dict(state)
  write(a.out/'EXIT.json',dict(result,synthetic=True,actual_model_inference=False,elapsed_seconds=time.monotonic()-started))
 return 0
if __name__=='__main__':raise SystemExit(main())
