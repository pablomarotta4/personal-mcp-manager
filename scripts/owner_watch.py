"""Private macOS owner leases. No backend commands, credentials or PID signaling."""
import ctypes
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import select
import socket
import stat
import subprocess
import threading
import time

REVIEWED_CODEX = '/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex'
# Claude Code CLI: one Anthropic-signed binary per installed version; several versions can be live at once.
CLAUDE_ROOT = os.path.join(pwd.getpwuid(os.getuid()).pw_dir, '.local/share/claude/versions')
CLAUDE_VERSION = re.compile(r'[0-9]+\.[0-9]+\.[0-9]+\Z')
CLAUDE_REQUIREMENT = 'anchor apple generic and certificate leaf[subject.OU] = "Q6L2SF6YDW" and identifier "com.anthropic.claude-code"'
BACKEND = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')
HEX32 = re.compile(r'[0-9a-f]{32}\Z')
HEX64 = re.compile(r'[0-9a-f]{64}\Z')

class OwnerError(Exception):
    def __init__(self):super().__init__('OWNER_WATCH_FAILED')


def private(path, directory=False):
    path=Path(path)
    if not path.is_absolute() or path.resolve()!=path:raise OwnerError()
    info=path.lstat()
    if info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=(0o700 if directory else 0o600) or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISSOCK(info.st_mode)):
        raise OwnerError()
    return path


def strict_json(value):
    def pairs(items):
        result={}
        for key,item in items:
            if key in result:raise OwnerError()
            result[key]=item
        return result
    return json.loads(value,object_pairs_hook=pairs)


def read_artifact(path, maximum):
    path=Path(path)
    if path.resolve()!=path:raise OwnerError()
    for parent in path.parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise OwnerError()
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        info=os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022 or info.st_size>maximum:raise OwnerError()
        value=os.read(descriptor,maximum+1)
        if len(value)>maximum:raise OwnerError()
        return value
    finally:os.close(descriptor)

@dataclass(frozen=True)
class Identity:
    pid:int
    ppid:int
    uid:int
    seconds:int
    microseconds:int
    path:str
    status:int=field(compare=False)

@dataclass(frozen=True)
class CwdBinding:
    path:str
    device:int
    inode:int


def checked_cwd(value):
    if not isinstance(value,CwdBinding) or not isinstance(value.path,str) or not os.path.isabs(value.path) or '\0' in value.path or type(value.device)!=int or type(value.inode)!=int or not 0<=value.device<2**64 or not 0<value.inode<2**64:raise OwnerError()
    value.path.encode('utf-8',errors='strict')
    if os.path.realpath(value.path)!=value.path:raise OwnerError()
    info=os.stat(value.path)
    if not stat.S_ISDIR(info.st_mode) or info.st_dev!=value.device or info.st_ino!=value.inode:raise OwnerError()
    return value

class NativeIdentity:
    def __init__(self):
        root=Path(__file__).resolve().parents[1]
        manifest=strict_json(read_artifact(root/'dist/owner-identity.json',16384))
        flags=['-std=c11','-O2','-Wall','-Wextra','-Werror','-fstack-protector-strong','-dynamiclib','-lproc']
        if type(manifest.get('version'))!=int or set(manifest)!={'version','binary','binarySha256','sourceSha256','compiler','flags'} or manifest['version']!=1 or manifest['binary']!='personal-mcp-owner-identity.dylib' or manifest['flags']!=flags or set(manifest['compiler'])!={'path','version','target'} or manifest['compiler']['path']!='/usr/bin/clang' or any(not isinstance(manifest['compiler'][key],str) or not 0<len(manifest['compiler'][key])<=1024 for key in ['version','target']):raise OwnerError()
        binary=root/'dist'/manifest['binary']
        for file,key,limit in [(binary,'binarySha256',16777216),(root/'native/owner-identity.c','sourceSha256',1048576)]:
            if not HEX64.fullmatch(manifest[key]) or hashlib.sha256(read_artifact(file,limit)).hexdigest()!=manifest[key]:raise OwnerError()
        self.library=ctypes.CDLL(str(binary))
        self.library.pm_peer.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint64)]
        self.library.pm_identity.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint64),ctypes.c_char_p,ctypes.c_uint32]
        self.library.pm_cwd.argtypes=[ctypes.c_int,ctypes.POINTER(ctypes.c_uint64),ctypes.c_char_p,ctypes.c_uint32]
        self.zombie=self.library.pm_zombie_status()
    def peer(self,fd):
        values=(ctypes.c_uint64*2)()
        if self.library.pm_peer(fd,values)!=0:raise OwnerError()
        return tuple(values)
    def process(self,pid):
        values=(ctypes.c_uint64*6)();capacity=self.library.pm_path_capacity();path=ctypes.create_string_buffer(capacity)
        if self.library.pm_identity(pid,values,path,capacity)!=0 or values[5]==self.zombie:raise OwnerError()
        return Identity(values[0],values[1],values[2],values[3],values[4],os.path.realpath(os.fsdecode(path.value)),values[5])
    def cwd(self,pid):
        values=(ctypes.c_uint64*2)();capacity=self.library.pm_cwd_capacity();path=ctypes.create_string_buffer(capacity)
        if self.library.pm_cwd(pid,values,path,capacity)!=0:raise OwnerError()
        try:physical=os.path.realpath(path.value.decode('utf-8',errors='strict'))
        except UnicodeError:raise OwnerError()
        return checked_cwd(CwdBinding(physical,values[0],values[1]))
    def boot(self):
        value=subprocess.check_output(['/usr/sbin/sysctl','-n','kern.bootsessionuuid'],text=True,stderr=subprocess.DEVNULL,timeout=5).strip()
        if not re.fullmatch(r'[A-Fa-f0-9-]{36}',value):raise OwnerError()
        return value

class KernelEvents:
    def __init__(self,native):
        self.queue=select.kqueue();self.receipt=native.library.pm_ev_receipt();self.lock=threading.Lock()
    def arm(self,pid,generation):
        event=select.kevent(pid,filter=select.KQ_FILTER_PROC,flags=select.KQ_EV_ADD|select.KQ_EV_ENABLE|select.KQ_EV_ONESHOT|self.receipt,fflags=select.KQ_NOTE_EXIT,udata=generation)
        with self.lock:result=self.queue.control([event],1,0)
        if len(result)!=1 or not result[0].flags&select.KQ_EV_ERROR or result[0].data!=0:raise OwnerError()
    def disarm(self,pid,generation):
        with self.lock:
            try:self.queue.control([select.kevent(pid,filter=select.KQ_FILTER_PROC,flags=select.KQ_EV_DELETE)],0,0)
            except OSError:pass
    def poll(self,timeout=0):
        with self.lock:events=self.queue.control(None,128,timeout)
        if any(event.flags&select.KQ_EV_ERROR or event.filter!=select.KQ_FILTER_PROC or not event.fflags&select.KQ_NOTE_EXIT for event in events):raise OwnerError()
        return [(event.ident,event.udata) for event in events]
    def close(self):
        with self.lock:self.queue.close()


def signed(path, *, approved_paths=None):
    allowed = (REVIEWED_CODEX,) if approved_paths is None else approved_paths
    if path not in allowed or str(Path(path).resolve())!=path:raise OwnerError()
    requirement='anchor apple generic and certificate leaf[subject.OU] = "2DC432GLL2" and identifier "codex"'
    result=subprocess.run(['/usr/bin/codesign','--verify','--strict','-R','='+requirement,path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5)
    if result.returncode:raise OwnerError()
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
    return digest.hexdigest()

def claude_path(path, root=CLAUDE_ROOT):
    parent,name=os.path.split(path)
    return parent==root and bool(CLAUDE_VERSION.fullmatch(name)) and os.path.realpath(path)==path


def signed_claude(path, root=CLAUDE_ROOT):
    if not claude_path(path,root):raise OwnerError()
    for parent in Path(path).parents:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0,os.getuid()) or info.st_mode&0o022:raise OwnerError()
    info=os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o022:raise OwnerError()
    result=subprocess.run(['/usr/bin/codesign','--verify','--strict','-R','='+CLAUDE_REQUIREMENT,path],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
    if result.returncode:raise OwnerError()
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):digest.update(block)
    return digest.hexdigest()


def file_key(path):
    info=os.stat(path)
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns)

@dataclass
class Acknowledgment:
    deadline:float
    event:threading.Event=field(default_factory=threading.Event)
    seen:bool=False
    cancelled:bool=False

@dataclass
class Owner:
    identity:Identity
    generation:int
    profiles:dict=field(default_factory=dict)
    live:bool=True

class OwnerWatch:
    def __init__(self,runtime,channel,*,backends,cwd_backends=frozenset(),identity=None,signature=None,events=None,reviewed_path=REVIEWED_CODEX,deadline=5,max_owners=128,max_caps=1024,on_failure=None,loki_environment_guard=None,mysql_environment_guard=None,claude_match=None,claude_signature=None,claude_key=None,claude_root=CLAUDE_ROOT,owner_paths=None,portable_environment_guard=None):
        if not backends or any(not isinstance(v,str) or not BACKEND.fullmatch(v) for v in backends) or not 0<deadline<=5 or not 1<=max_owners<=128 or not 1<=max_caps<=1024:raise OwnerError()
        self.runtime=Path(runtime);self.channel=channel;self.backends=frozenset(backends);self.cwd_backends=frozenset(cwd_backends)
        if not self.cwd_backends<=self.backends:raise OwnerError()
        self.portable_environment_guard=portable_environment_guard
        if portable_environment_guard is None:
            if loki_environment_guard is not None or self.backends&frozenset({'loki-stg','loki-prd','loki-tools'}):
                from loki_owner_environment import LokiOwnerEnvironmentGuard, RESERVED
                if type(loki_environment_guard)!=LokiOwnerEnvironmentGuard or loki_environment_guard.backends!=self.backends&RESERVED:raise OwnerError()
            self.loki_environment_guard=loki_environment_guard
            mysql_backends=frozenset(backend for backend in self.backends if backend.startswith('mysql-'))
            if mysql_environment_guard is not None or mysql_backends:
                from mysql_environment import MysqlOwnerEnvironmentGuard
                if type(mysql_environment_guard)!=MysqlOwnerEnvironmentGuard or mysql_environment_guard.backends!=mysql_backends:raise OwnerError()
            self.mysql_environment_guard=mysql_environment_guard
            self.mysql_guards={backend:mysql_environment_guard for backend in mysql_backends} if mysql_environment_guard is not None else {}
        else:
            from portable_owner_environment import PortableEnvironmentGuard
            if type(portable_environment_guard) is not PortableEnvironmentGuard or portable_environment_guard.backends!=self.backends:
                raise OwnerError()
            self.loki_environment_guard=None
            self.mysql_environment_guard=None
            self.mysql_guards={backend:portable_environment_guard for backend in portable_environment_guard.context_backends}
        self.mysql_context_key=secrets.token_bytes(32)
        self.identity=identity or NativeIdentity();self.events=events or KernelEvents(self.identity)
        paths = (reviewed_path,) if owner_paths is None else owner_paths
        if (not isinstance(paths, tuple) or len(paths) > 8 or len(set(paths)) != len(paths)
                or any(not isinstance(path, str) or not os.path.isabs(path) or '\0' in path for path in paths)):
            raise OwnerError()
        self.signature=signature or (lambda path: signed(path, approved_paths=paths))
        self.owner_paths=frozenset(paths)
        self.codex_pins={path:self.signature(path) for path in paths}
        self.reviewed_path=reviewed_path
        self.executable=self.codex_pins.get(reviewed_path)
        self.boot=self.identity.boot()
        self.deadline=deadline;self.max_owners=max_owners;self.max_caps=max_caps;self.on_failure=on_failure
        # Claude owners: verified per path (signature + digest pinned at first sight), cached by file identity.
        self.claude_root=claude_root;self.claude_match=claude_match or (lambda path:claude_path(path,claude_root))
        self.claude_signature=claude_signature or (lambda path:signed_claude(path,claude_root));self.claude_key=claude_key or file_key
        self.claude_pins={};self.claude_lock=threading.Lock()
        self.lock=threading.RLock();self.write_lock=threading.Lock();self.stop=threading.Event();self.ready=threading.Event()
        self.slots=threading.BoundedSemaphore(8);self.owners={};self.generations={};self.acks={};self.failed=False
        self.listener=None;self.socket_identity=None;self.threads=[];self.closed=False;self.next_generation=secrets.randbits(62) or 1;self.next_issuance=1
        self.channel.settimeout(deadline)
    def fail(self):
        with self.lock:
            if self.failed or self.stop.is_set():return
            self.failed=True;self.stop.set();self.ready.set()
            for acknowledgment in self.acks.values():acknowledgment.event.set()
            for owner in self.owners.values():owner.live=False
            try:self.channel.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            if self.listener:self.listener.close()
        if self.on_failure:
            try:self.on_failure()
            except Exception:pass
    def send(self,value):
        line=json.dumps(value,separators=(',',':')).encode()+b'\n'
        mysql_frame=(value.get('type')=='register' and value.get('backend') in self.mysql_guards and 'mysqlContext' in value)
        if len(line)>(131072 if mysql_frame else 4096) or self.failed or self.stop.is_set():raise OwnerError()
        try:
            with self.write_lock:self.channel.sendall(line)
        except Exception:self.fail();raise OwnerError()
    def read_channel(self):
        buffer=b'';partial_deadline=None
        try:
            while not self.stop.is_set():
                remaining=self.deadline if partial_deadline is None else partial_deadline-time.monotonic()
                if remaining<=0:raise OwnerError()
                # Keep the socket's send timeout unchanged for the writer thread.
                readable,_,_=select.select([self.channel],[],[],remaining)
                if not readable:
                    if partial_deadline is not None:raise OwnerError()
                    continue
                try:chunk=self.channel.recv(4096)
                except socket.timeout:
                    if partial_deadline is not None and time.monotonic()>=partial_deadline:raise OwnerError()
                    continue
                if partial_deadline is not None and time.monotonic()>=partial_deadline:raise OwnerError()
                if not chunk:raise OwnerError()
                if not buffer:partial_deadline=time.monotonic()+self.deadline
                buffer+=chunk
                while b'\n' in buffer:
                    line,buffer=buffer.split(b'\n',1)
                    partial_deadline=time.monotonic()+self.deadline if buffer else None
                    if len(line)+1>4096:raise OwnerError()
                    value=strict_json(line.decode('utf-8'))
                    with self.lock:
                        if type(value)!=dict or type(value.get('v'))!=int or value['v']!=1:raise OwnerError()
                        if value.get('type')=='ready' and set(value)=={'v','type'} and not self.ready.is_set():self.ready.set()
                        elif value.get('type')=='ack' and set(value)=={'v','type','requestId'} and isinstance(value['requestId'],str) and HEX32.fullmatch(value['requestId']) and value['requestId'] in self.acks and not self.acks[value['requestId']].seen:
                            acknowledgment=self.acks[value['requestId']]
                            acknowledgment.seen=True;acknowledgment.event.set()
                            if acknowledgment.cancelled:self.acks.pop(value['requestId'],None)
                        else:raise OwnerError()
                if not buffer:partial_deadline=None
                if len(buffer)>=4096:raise OwnerError()
        except Exception:self.fail()
    def start(self):
        try:
            private(self.runtime,True);path=self.runtime/'owner.sock'
            if path.exists() or path.is_symlink():raise OwnerError()
            self.listener=socket.socket(socket.AF_UNIX);self.listener.bind(str(path));os.chmod(path,0o600)
            self.socket_identity=path.lstat().st_ino;self.listener.listen(8);self.listener.settimeout(.1)
            self.spawn(self.read_channel)
            if not self.ready.wait(self.deadline) or self.failed:raise OwnerError()
            self.spawn(self.accept);self.spawn(self.watch_events);self.spawn(self.warm_claude)
        except Exception:
            self.fail();self.close();raise OwnerError()
    def spawn(self,function,*args):
        thread=threading.Thread(target=function,args=args,daemon=True)
        with self.lock:self.threads=[value for value in self.threads if value.is_alive()];self.threads.append(thread)
        thread.start()
    def claude_verified(self,path):
        # Expensive codesign+digest runs at most once per file identity, never inside self.lock when warm.
        if not self.claude_match(path):raise OwnerError()
        with self.claude_lock:
            key=self.claude_key(path);pin=self.claude_pins.get(path)
            if pin and pin[0]==key:return pin[1]
            digest=self.claude_signature(path)
            if pin and pin[1]!=digest:raise OwnerError()
            self.claude_pins[path]=(key,digest);return digest
    def warm_claude(self):
        try:names=sorted(os.listdir(self.claude_root)) if self.claude_root else []
        except OSError:return
        for name in names:
            if self.stop.is_set():return
            try:self.claude_verified(os.path.join(self.claude_root,name))
            except Exception:pass
    def client_path(self,path):
        return path in self.owner_paths or self.claude_match(path)
    def prewarm_peer(self,peer):
        # Best effort and lock-free: resolve the client chain early so a cold Claude version is verified before register().
        pid=peer[0]
        for _ in range(8):
            value=self.identity.process(pid)
            if value.path in self.owner_paths:return
            if self.claude_match(value.path):self.claude_verified(value.path);return
            pid=value.ppid
    def owner_for(self,peer):
        if peer[1]!=os.getuid() or self.identity.boot()!=self.boot:raise OwnerError()
        chain=[];pid=peer[0]
        for _ in range(8):
            value=self.identity.process(pid)
            if value.pid!=pid or value.uid!=os.getuid() or value.pid<2 or not 0<=value.microseconds<1000000:raise OwnerError()
            chain.append(value)
            if self.client_path(value.path):break
            pid=value.ppid
        else:raise OwnerError()
        for value in chain:
            if self.identity.process(value.pid)!=value:raise OwnerError()
        final=chain[-1]
        key=(self.boot,final.uid,final.pid,final.seconds,final.microseconds,final.path)
        owner=self.owners.get(key)
        if owner:
            if owner.identity!=final:raise OwnerError()
            return owner
        if any(value.identity.pid==final.pid for value in self.owners.values()):raise OwnerError()
        if final.path in self.owner_paths:
            if self.signature(final.path)!=self.codex_pins[final.path]:raise OwnerError()
        else:self.claude_verified(final.path)
        if len(self.owners)>=self.max_owners:raise OwnerError()
        generation=self.next_generation;self.next_generation+=1
        if generation>=2**63:raise OwnerError()
        owner=Owner(chain[-1],generation);self.owners[key]=owner;self.generations[generation]=(key,owner)
        try:
            self.events.arm(owner.identity.pid,generation)
            for value in chain:
                if self.identity.process(value.pid)!=value:raise OwnerError()
            self.handle_events(self.events.poll(0))
            if not owner.live:raise OwnerError()
        except Exception:
            self.owners.pop(key,None);self.generations.pop(generation,None)
            if hasattr(self.events,'disarm'):self.events.disarm(owner.identity.pid,generation)
            raise OwnerError()
        return owner
    def register(self,peer,backend,deadline):
        with self.lock:
            if self.failed or self.stop.is_set():raise OwnerError()
            mysql_guard=self.mysql_guards.get(backend)
            needs_cwd=backend in self.cwd_backends or mysql_guard is not None
            peer_identity=self.identity.process(peer[0]) if needs_cwd else None
            binding=checked_cwd(self.identity.cwd(peer[0])) if peer_identity is not None else None
            owner=self.owner_for(peer)
            if self.portable_environment_guard is not None and backend not in self.mysql_guards:
                self.portable_environment_guard(backend,owner.identity,binding)
            if self.loki_environment_guard is not None and backend in self.loki_environment_guard.backends:self.loki_environment_guard(backend,owner.identity)
            mysql_context=None
            if mysql_guard is not None:
                mysql_context=mysql_guard(backend,owner.identity,binding)
                self.checked_mysql_context(backend,mysql_context)
            if binding is not None and (self.identity.process(peer[0])!=peer_identity or checked_cwd(self.identity.cwd(peer[0]))!=binding):raise OwnerError()
            profile=(backend,binding) if backend in self.cwd_backends else backend
            if mysql_context is not None:
                encoded=json.dumps(mysql_context,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
                profile=(backend,binding,hmac.digest(self.mysql_context_key,encoded,'sha256'))
            if profile not in owner.profiles:
                if sum(len(o.profiles) for o in self.owners.values())>=self.max_caps or len(self.acks)>=self.max_caps:raise OwnerError()
                if self.next_issuance>=2**64:self.fail();raise OwnerError()
                # Allocation and send share this lock, preserving channel order.
                token=f'{self.next_issuance:016x}'+secrets.token_hex(24);self.next_issuance+=1
                request=secrets.token_hex(16);event=Acknowledgment(deadline)
                message={'v':1,'type':'register','requestId':request,'owner':token,'backend':backend}
                if backend in self.cwd_backends:message['cwd']={'pathB64':base64.b64encode(binding.path.encode('utf-8')).decode('ascii'),'device':str(binding.device),'inode':str(binding.inode)}
                if mysql_context is not None:message['mysqlContext']=mysql_context
                maximum=131072 if mysql_context is not None else 4096
                if len(json.dumps(message,separators=(',',':')).encode()+b'\n')>maximum:raise OwnerError()
                owner.profiles[profile]=(token,request,event);self.acks[request]=event
                self.send(message)
            token,request,event=owner.profiles[profile]
        if not event.event.wait(max(0,deadline-time.monotonic())):self.fail();raise OwnerError()
        with self.lock:
            if self.failed or not owner.live or event.cancelled or not event.seen:raise OwnerError()
            self.acks.pop(request,None)
            if self.portable_environment_guard is not None and backend not in self.mysql_guards:
                self.portable_environment_guard(backend,owner.identity,binding)
            if binding is not None and (self.identity.process(peer[0])!=peer_identity or checked_cwd(self.identity.cwd(peer[0]))!=binding):raise OwnerError()
            if self.loki_environment_guard is not None and backend in self.loki_environment_guard.backends:self.loki_environment_guard(backend,owner.identity)
            if mysql_guard is not None:
                current_context=mysql_guard(backend,owner.identity,binding)
                self.checked_mysql_context(backend,current_context)
                if current_context!=mysql_context:raise OwnerError()
            return token
    def checked_mysql_context(self,backend,context):
        if context is None:return
        from mysql_environment import INHERITED, PROHIBITED
        if type(context)!=dict or set(context)!={'environment'}:raise OwnerError()
        environment=context['environment']
        if type(environment)!=dict or len(environment)>64:raise OwnerError()
        for key,value in environment.items():
            allowed=key in INHERITED and key not in PROHIBITED
            if (not allowed or type(value)!=str or '\0' in value or
                    len(value.encode('utf-8'))>16384):raise OwnerError()
        if len(json.dumps(context,separators=(',',':')).encode())>130048:raise OwnerError()
    def handle_events(self,events):
        with self.lock:
            for pid,generation in events:
                entry=self.generations.get(generation)
                if not entry or entry[1].identity.pid!=pid:continue
                key,owner=entry;owner.live=False
                for token,request,event in owner.profiles.values():
                    self.send({'v':1,'type':'exit','owner':token});event.cancelled=True;event.event.set()
                    if event.seen:self.acks.pop(request,None)
                self.owners.pop(key,None);self.generations.pop(generation,None)
    def watch_events(self):
        try:
            while not self.stop.is_set():
                self.handle_events(self.events.poll(.05))
                with self.lock:
                    for request,acknowledgment in list(self.acks.items()):
                        if acknowledgment.cancelled and time.monotonic()>=acknowledgment.deadline:self.acks.pop(request,None)
                self.stop.wait(.02)
        except Exception:self.fail()
    def accept(self):
        try:
            while not self.stop.is_set():
                try:connection,_=self.listener.accept()
                except socket.timeout:continue
                if not self.slots.acquire(False):connection.close();continue
                self.spawn(self.serve,connection)
        except Exception:
            if not self.stop.is_set():self.fail()
    def serve(self,connection):
        try:
            with connection:
                deadline=time.monotonic()+self.deadline
                connection.settimeout(self.deadline);peer=self.identity.peer(connection.fileno());buffer=b''
                while b'\n' not in buffer:
                    connection.settimeout(max(.001,deadline-time.monotonic()))
                    if time.monotonic()>=deadline:raise OwnerError()
                    chunk=connection.recv(130-len(buffer))
                    if not chunk:raise OwnerError()
                    buffer+=chunk
                    if len(buffer)>129:raise OwnerError()
                if not buffer.endswith(b'\n') or buffer.count(b'\n')!=1:raise OwnerError()
                backend=buffer[:-1].decode('ascii')
                if not BACKEND.fullmatch(backend) or backend not in self.backends:raise OwnerError()
                try:self.prewarm_peer(peer)
                except Exception:pass
                token=self.register(peer,backend,deadline);connection.settimeout(max(.001,deadline-time.monotonic()));connection.sendall(token.encode()+b'\n')
        except Exception:pass
        finally:self.slots.release()
    def close(self):
        if self.closed:return
        self.closed=True;self.stop.set()
        with self.lock:
            for acknowledgment in self.acks.values():acknowledgment.event.set()
            for owner in self.owners.values():owner.live=False
        if self.listener:self.listener.close()
        try:self.channel.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        deadline=time.monotonic()+self.deadline+.2
        for thread in self.threads:
            if thread is not threading.current_thread():thread.join(max(0,deadline-time.monotonic()))
        self.events.close();self.channel.close()
        path=self.runtime/'owner.sock'
        if self.socket_identity is not None:
            try:
                if path.lstat().st_ino==self.socket_identity:path.unlink()
            except FileNotFoundError:pass


def request_owner(runtime,backend,timeout=5):
    if not isinstance(backend,str) or not BACKEND.fullmatch(backend) or not 0<timeout<=5:raise OwnerError()
    path=private(private(runtime,True)/'owner.sock')
    try:
        with socket.socket(socket.AF_UNIX) as client:
            deadline=time.monotonic()+timeout
            client.settimeout(timeout);client.connect(str(path));client.sendall(backend.encode('ascii')+b'\n');value=b''
            while b'\n' not in value:
                client.settimeout(max(.001,deadline-time.monotonic()))
                if time.monotonic()>=deadline:raise OwnerError()
                chunk=client.recv(66-len(value))
                if not chunk:raise OwnerError()
                value+=chunk
                if len(value)>65:raise OwnerError()
        if len(value)!=65 or not value.endswith(b'\n') or not HEX64.fullmatch(value[:-1].decode('ascii')):raise OwnerError()
        return value[:-1].decode('ascii')
    except Exception:raise OwnerError()
