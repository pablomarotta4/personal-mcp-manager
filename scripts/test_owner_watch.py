import os
from pathlib import Path
import socket
import tempfile
import threading
import unittest
import owner_watch as ow

class Events:
    def __init__(self):self.events=[];self.armed=[]
    def arm(self,pid,generation):self.armed.append((pid,generation))
    def poll(self,timeout=0):
        result=self.events[:];self.events.clear();return result
    def close(self):pass

class Identity:
    def __init__(self):self.native=ow.NativeIdentity();self.birth=1;self.race=False
    def peer(self,fd):return self.native.peer(fd)
    def boot(self):return 'synthetic-boot'
    def process(self,pid):
        if pid==os.getpid():return ow.Identity(pid,777,os.getuid(),1,0,'/synthetic/helper',1)
        result=ow.Identity(777,1,os.getuid(),self.birth,0,'/synthetic/codex',1)
        if self.race:self.birth+=1
        return result

class ClaudeIdentity(Identity):
    def __init__(self,path='/synthetic/claude/2.1.300'):super().__init__();self.path=path
    def process(self,pid):
        if pid==os.getpid():return ow.Identity(pid,778,os.getuid(),1,0,'/synthetic/helper',1)
        return ow.Identity(778,1,os.getuid(),self.birth,0,self.path,1)

class OwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.runtime=Path(self.temp.name).resolve();os.chmod(self.runtime,0o700)
        self.parent,self.node=socket.socketpair();self.identity=Identity();self.events=Events();self.messages=[]
        self.watch=None
    def tearDown(self):
        if self.watch:self.watch.close()
        self.parent.close();self.node.close();self.temp.cleanup()
    def start(self,ack=True,ready_parts=None,**options):
        def node():
            for part in ([b'{"v":1,"type":"ready"}\n'] if ready_parts is None else ready_parts):
                self.node.sendall(part);__import__('time').sleep(.005)
            buffer=b''
            try:
                while True:
                    chunk=self.node.recv(4096)
                    if not chunk:return
                    buffer+=chunk
                    while b'\n' in buffer:
                        line,buffer=buffer.split(b'\n',1);value=__import__('json').loads(line);self.messages.append(value)
                        if ack and value['type']=='register':
                            self.node.sendall(__import__('json').dumps({'v':1,'type':'ack','requestId':value['requestId']}).encode()+b'\n')
            except OSError:return
        threading.Thread(target=node,daemon=True).start()
        self.watch=ow.OwnerWatch(self.runtime,self.parent,backends={'fixture','other'},identity=self.identity,events=self.events,signature=lambda path:None,reviewed_path='/synthetic/codex',deadline=.3,**options)
        self.watch.start()
    def test_private_peer_and_ack_bound_capability_retained(self):
        self.start();first=ow.request_owner(self.runtime,'fixture',timeout=1);second=ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(first,second);self.assertEqual(len(first),64);self.assertEqual(len(self.events.armed),1)
        self.assertEqual((self.runtime/'owner.sock').stat().st_mode&0o777,0o600)
        other=ow.request_owner(self.runtime,'other',timeout=1);self.assertNotEqual(first,other)
        self.assertTrue(all(set(v)=={'v','type','requestId','owner','backend'} for v in self.messages))
    def test_birth_race_fails_before_helper_completion(self):
        self.identity.race=True;self.start()
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
    def test_ack_timeout_fails_closed(self):
        self.start(ack=False)
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertTrue(self.watch.failed)
    def test_existing_socket_refused_without_unlink(self):
        path=self.runtime/'owner.sock';path.write_text('synthetic')
        with self.assertRaises(ow.OwnerError):
            ow.OwnerWatch(self.runtime,self.parent,backends={'fixture'},identity=self.identity,events=self.events,signature=lambda path:None,reviewed_path='/synthetic/codex').start()
        self.assertEqual(path.read_text(),'synthetic')
    def test_exit_and_stale_generation(self):
        self.start();first=ow.request_owner(self.runtime,'fixture',timeout=1);pid,generation=self.events.armed[0]
        self.watch.handle_events([(pid,generation+1)]);self.assertEqual(ow.request_owner(self.runtime,'fixture',timeout=1),first)
        self.watch.handle_events([(pid,generation)]);self.identity.birth+=1
        second=ow.request_owner(self.runtime,'fixture',timeout=1);self.assertNotEqual(first,second)
        self.assertEqual(len(self.events.armed),2)
    def test_cap_limit_and_unknown_backend(self):
        self.start(max_caps=1);ow.request_owner(self.runtime,'fixture',timeout=1)
        for backend in ['other','unknown','bad/id']:
            with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,backend,timeout=1)

    def wait_failed(self):
        import time
        end=time.monotonic()+1
        while not self.watch.failed and time.monotonic()<end:time.sleep(.01)
        self.assertTrue(self.watch.failed)
    def test_channel_malformed_duplicate_and_oversize_fail_closed(self):
        self.start();self.node.sendall(b'{"v":1,"v":1,"type":"ready"}\n');self.wait_failed()
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
    def test_unknown_ack_fails_closed(self):
        self.start();self.node.sendall(b'{"v":1,"type":"ack","requestId":"00000000000000000000000000000000"}\n');self.wait_failed()
    def test_partial_channel_deadline(self):
        self.start();self.node.sendall(b'{');self.wait_failed()
    def test_partial_channel_trickle_cannot_extend_frame_deadline(self):
        import time
        self.start();began=time.monotonic();self.node.sendall(b'{')
        time.sleep(.24);self.node.sendall(b' ')
        end=began+.44
        while not self.watch.failed and time.monotonic()<end:time.sleep(.005)
        self.assertTrue(self.watch.failed, 'trickle must not restart the 0.3-second assembly budget')
    def test_coalesced_next_partial_frame_gets_its_own_deadline(self):
        import time,json
        self.start()
        ids=['a'*32,'b'*32]
        with self.watch.lock:
            for request in ids:self.watch.acks[request]=ow.Acknowledgment(time.monotonic()+2)
        frames=[json.dumps({'v':1,'type':'ack','requestId':request}).encode()+b'\n' for request in ids]
        self.node.sendall(frames[0][:1]);time.sleep(.24)
        self.node.sendall(frames[0][1:]+frames[1][:1]);time.sleep(.12)
        self.node.sendall(frames[1][1:])
        self.assertTrue(self.watch.acks[ids[1]].event.wait(.2))
        self.assertFalse(self.watch.failed, 'the second frame must not inherit the first frame deadline')
        self.assertTrue(all(self.watch.acks[request].seen for request in ids))
    def test_owner_limit_retains_live_watch(self):
        self.start(max_owners=1);first=ow.request_owner(self.runtime,'fixture',timeout=1);self.identity.birth+=1
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(len(self.events.armed),1)
        self.identity.birth-=1;self.assertEqual(ow.request_owner(self.runtime,'fixture',timeout=1),first)
    def test_exit_during_arm_rejects_without_capability(self):
        original=self.events.arm
        def arm(pid,generation):original(pid,generation);self.events.events.append((pid,generation))
        self.events.arm=arm;self.start()
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.messages,[])
    def test_private_runtime_symlink_and_mode_refused(self):
        self.start();os.chmod(self.runtime,0o755)
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        os.chmod(self.runtime,0o700)
    def test_kernel_identity_receipt_and_exit_on_owned_child(self):
        import subprocess,sys,time
        child=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(.3)'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        native=ow.NativeIdentity();events=ow.KernelEvents(native)
        try:
            before=native.process(child.pid);self.assertEqual(before.uid,os.getuid());self.assertGreater(before.seconds,0)
            events.arm(child.pid,17);self.assertEqual(native.process(child.pid),before)
            found=[];end=time.monotonic()+2
            while not found and time.monotonic()<end:found=events.poll(.1)
            self.assertEqual(found,[(child.pid,17)]);child.wait(timeout=2)
        finally:events.close();child.wait(timeout=2)

    def test_oversize_frame_fails_closed(self):
        self.start();self.node.sendall(b'x'*4096);self.wait_failed()
    def test_invalid_utf8_frame_fails_closed(self):
        self.start();self.node.sendall(b'\xff\n');self.wait_failed()
    def test_split_ready_frame_is_accepted(self):
        frame=b'{"v":1,"type":"ready"}\n';self.start(ready_parts=[frame[:4],frame[4:11],frame[11:]])
        self.assertEqual(len(ow.request_owner(self.runtime,'fixture',timeout=1)),64)
    def test_readiness_timeout_cleans_owned_socket(self):
        with self.assertRaises(ow.OwnerError):self.start(ready_parts=[])
        self.assertTrue(self.watch.failed);self.assertFalse((self.runtime/'owner.sock').exists())
    def test_helper_waits_for_matching_ack(self):
        import time,json
        self.start(ack=False);result=[]
        thread=threading.Thread(target=lambda:result.append(ow.request_owner(self.runtime,'fixture',timeout=1)));thread.start()
        end=time.monotonic()+.2
        while not self.messages and time.monotonic()<end:time.sleep(.005)
        self.assertTrue(self.messages);self.assertEqual(result,[])
        message=self.messages[0];self.node.sendall(json.dumps({'v':1,'type':'ack','requestId':message['requestId']}).encode()+b'\n')
        thread.join(1);self.assertEqual(result,[message['owner']])
    def test_reparenting_during_arm_rejects(self):
        process=self.identity.process
        def arm(pid,generation):
            self.events.armed.append((pid,generation))
            def changed(candidate):
                value=process(candidate)
                return ow.Identity(value.pid,778 if candidate==os.getpid() else value.ppid,value.uid,value.seconds,value.microseconds,value.path,value.status)
            self.identity.process=changed
        self.events.arm=arm;self.start()
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.messages,[])

    def test_coalesced_acks_for_two_profiles(self):
        import time,json
        self.start(ack=False);results=[]
        threads=[threading.Thread(target=lambda backend=backend:results.append(ow.request_owner(self.runtime,backend,timeout=1))) for backend in ['fixture','other']]
        for thread in threads:thread.start()
        end=time.monotonic()+.2
        while len(self.messages)<2 and time.monotonic()<end:time.sleep(.005)
        self.assertEqual(len(self.messages),2)
        self.node.sendall(b''.join(json.dumps({'v':1,'type':'ack','requestId':value['requestId']}).encode()+b'\n' for value in self.messages))
        for thread in threads:thread.join(1)
        self.assertEqual(len(set(results)),2);self.assertEqual(len(self.events.armed),1)
    def test_birth_reuse_requires_old_exit_even_below_limit(self):
        self.start();ow.request_owner(self.runtime,'fixture',timeout=1);self.identity.birth+=1
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(len(self.events.armed),1)
    def test_foreign_peer_uid_rejected_locally(self):
        self.identity.peer=lambda fd:(os.getpid(),os.getuid()+1);self.start()
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.messages,[]);self.assertFalse(self.watch.failed)
    def test_channel_eof_invokes_fatal_callback(self):
        called=[];delivered=threading.Event()
        def failed():called.append(True);delivered.set()
        self.start(on_failure=failed);self.node.close();self.wait_failed()
        self.assertTrue(delivered.wait(1));self.assertEqual(called,[True])

    def test_independent_owners_exit_retires_only_matching_generation(self):
        peers=iter([111,112,112]);self.identity.peer=lambda fd:(next(peers),os.getuid())
        def process(pid):
            if pid in [111,112]:return ow.Identity(pid,777 if pid==111 else 778,os.getuid(),1,0,'/synthetic/helper',1)
            return ow.Identity(pid,1,os.getuid(),1,0,'/synthetic/codex',1)
        self.identity.process=process;self.start()
        first=ow.request_owner(self.runtime,'fixture',timeout=1);second=ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertNotEqual(first,second);self.assertEqual(len(self.events.armed),2)
        self.watch.handle_events([self.events.armed[0]])
        self.assertEqual(ow.request_owner(self.runtime,'fixture',timeout=1),second)
    def test_watch_backend_failure_is_fatal(self):
        self.start()
        def broken(timeout=0):raise OSError('synthetic')
        self.events.poll=broken;self.wait_failed()

    def test_late_ack_after_exit_does_not_fail_other_owner(self):
        import time,json
        peers=iter([111,112]);self.identity.peer=lambda fd:(next(peers),os.getuid())
        self.identity.process=lambda pid:ow.Identity(pid,777 if pid==111 else 778 if pid==112 else 1,os.getuid(),1,0,'/synthetic/helper' if pid in [111,112] else '/synthetic/codex',1)
        self.start(ack=False);results=[]
        def request():
            try:results.append(ow.request_owner(self.runtime,'fixture',timeout=1))
            except ow.OwnerError:results.append(None)
        thread=threading.Thread(target=request);thread.start();end=time.monotonic()+.2
        while not self.messages and time.monotonic()<end:time.sleep(.005)
        first=self.messages[0];self.watch.handle_events([self.events.armed[0]]);thread.join(1);self.assertEqual(results,[None])
        self.node.sendall(json.dumps({'v':1,'type':'ack','requestId':first['requestId']}).encode()+b'\n');time.sleep(.03)
        self.assertFalse(self.watch.failed)
        second=threading.Thread(target=request);second.start();end=time.monotonic()+.2
        while len([v for v in self.messages if v['type']=='register'])<2 and time.monotonic()<end:time.sleep(.005)
        message=[v for v in self.messages if v['type']=='register'][-1]
        self.node.sendall(json.dumps({'v':1,'type':'ack','requestId':message['requestId']}).encode()+b'\n');second.join(1)
        self.assertEqual(len(results[-1]),64);self.assertFalse(self.watch.failed)

    def test_cancelled_ack_tombstones_are_bounded_and_expire(self):
        import time
        self.start(ack=False,max_caps=1);result=[]
        def request():
            try:ow.request_owner(self.runtime,'fixture',timeout=1)
            except ow.OwnerError:result.append(False)
        thread=threading.Thread(target=request);thread.start();end=time.monotonic()+.2
        while not self.messages and time.monotonic()<end:time.sleep(.005)
        self.watch.handle_events([self.events.armed[0]]);thread.join(1)
        self.assertEqual(len(self.watch.acks),1);self.identity.birth+=1
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertFalse(self.watch.failed);time.sleep(.4);self.assertEqual(len(self.watch.acks),0)
    def test_signature_requires_openai_team_and_identifier(self):
        from unittest.mock import patch
        with patch('owner_watch.subprocess.run') as command:
            command.return_value.returncode=1
            with self.assertRaises(ow.OwnerError):ow.signed(ow.REVIEWED_CODEX)
            arguments=command.call_args.args[0]
            self.assertIn('-R',arguments);self.assertTrue(arguments[arguments.index('-R')+1].startswith('='))
            self.assertIn('2DC432GLL2',arguments[arguments.index('-R')+1]);self.assertIn('identifier "codex"',arguments[arguments.index('-R')+1])
    def test_bridge_build_refuses_unsafe_source_before_compilation(self):
        import shutil,subprocess
        root=self.runtime/'build-fixture';(root/'native').mkdir(parents=True);(root/'scripts').mkdir()
        source=root/'native/owner-identity.c';source.write_text('synthetic');os.chmod(source,0o666)
        shutil.copyfile(Path(ow.__file__).parent/'build-owner-identity.mjs',root/'scripts/build-owner-identity.mjs')
        node=shutil.which('node');self.assertIsNotNone(node)
        result=subprocess.run([node,str(root/'scripts/build-owner-identity.mjs')],capture_output=True,timeout=5)
        self.assertNotEqual(result.returncode,0);self.assertIn(b'unsafe_owner_source',result.stderr)
        self.assertFalse((root/'dist').exists())

    def test_capabilities_issue_monotonically_in_wire_order(self):
        self.start();results=[]
        threads=[threading.Thread(target=lambda backend=backend:results.append(ow.request_owner(self.runtime,backend,timeout=1))) for backend in ['fixture','other']]
        for thread in threads:thread.start()
        for thread in threads:thread.join(1)
        issued=[int(value['owner'][:16],16) for value in self.messages if value['type']=='register']
        self.assertEqual(issued,[1,2]);self.assertEqual(len(results),2)
        before=len(self.messages);ow.request_owner(self.runtime,'fixture',timeout=1);self.assertEqual(len(self.messages),before)
    def test_counter_overflow_fails_closed_without_wrap(self):
        self.start();self.watch.next_issuance=2**64
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.messages,[]);self.assertTrue(self.watch.failed)
    def test_new_incarnation_issues_next_counter_after_exit(self):
        self.start();first=ow.request_owner(self.runtime,'fixture',timeout=1);self.watch.handle_events([self.events.armed[0]]);self.identity.birth+=1
        second=ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(int(second[:16],16),int(first[:16],16)+1)

    def test_more_than_lifetime_cap_limit_owner_churn(self):
        import time
        self.start()
        for index in range(1100):
            token=self.watch.register((os.getpid(),os.getuid()),'fixture',time.monotonic()+1)
            self.assertEqual(int(token[:16],16),index+1)
            self.watch.handle_events([self.events.armed[-1]]);self.identity.birth+=1
            self.assertEqual(len(self.watch.owners),0);self.assertEqual(len(self.watch.acks),0)
        self.assertFalse(self.watch.failed)

    def test_client_cwd_capabilities_b_c_b_and_fixed_wire(self):
        b=self.runtime/'B unicode é';c=self.runtime/'C';b.mkdir();c.mkdir();current=[b]
        def cwd(pid):
            value=current[0].stat();return ow.CwdBinding(str(current[0]),value.st_dev,value.st_ino)
        self.identity.cwd=cwd;self.start(cwd_backends=frozenset({'fixture'}))
        first=ow.request_owner(self.runtime,'fixture',timeout=1);current[0]=c
        second=ow.request_owner(self.runtime,'fixture',timeout=1);current[0]=b
        self.assertNotEqual(first,second);self.assertEqual(ow.request_owner(self.runtime,'fixture',timeout=1),first)
        ow.request_owner(self.runtime,'other',timeout=1)
        dynamic=[value for value in self.messages if value['backend']=='fixture'];self.assertEqual(len(dynamic),2)
        import base64
        self.assertEqual(base64.b64decode(dynamic[0]['cwd']['pathB64']).decode(),str(b))
        self.assertEqual(set(dynamic[0]['cwd']),{'pathB64','device','inode'})
        self.assertNotIn('cwd',[value for value in self.messages if value['backend']=='other'][0])
    def test_cwd_change_during_owner_arm_rejects_before_wire(self):
        b=self.runtime/'B';c=self.runtime/'C';b.mkdir();c.mkdir();current=[b]
        self.identity.cwd=lambda pid:ow.CwdBinding(str(current[0]),current[0].stat().st_dev,current[0].stat().st_ino)
        self.events.arm=lambda pid,generation:current.__setitem__(0,c)
        self.start(cwd_backends=frozenset({'fixture'}))
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.messages,[])

    def test_kernel_owned_helper_cwd_unicode_and_physical_path(self):
        import subprocess,sys
        b=self.runtime/'B unicode é space';c=self.runtime/'C';b.mkdir();c.mkdir();alias=self.runtime/'alias';alias.symlink_to(b,target_is_directory=True)
        native=ow.NativeIdentity()
        for directory in [b,c,alias]:
            child=subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(.4)'],cwd=directory,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                before=native.process(child.pid);binding=native.cwd(child.pid);after=native.process(child.pid)
                self.assertEqual(before,after);self.assertEqual(Path(binding.path).stat().st_dev,directory.stat().st_dev)
                self.assertEqual(binding.device,directory.stat().st_dev);self.assertEqual(binding.inode,directory.stat().st_ino)
                self.assertEqual(os.path.realpath(binding.path),binding.path);self.assertNotIn('/alias',binding.path)
                self.assertEqual(directory.stat().st_mode&0o777,0o755)
            finally:child.wait(timeout=2)
    def test_cwd_change_while_ack_pending_rejects_helper(self):
        import time,json
        b=self.runtime/'B';c=self.runtime/'C';b.mkdir();c.mkdir();current=[b]
        self.identity.cwd=lambda pid:ow.CwdBinding(str(current[0]),current[0].stat().st_dev,current[0].stat().st_ino)
        self.start(ack=False,cwd_backends=frozenset({'fixture'}));result=[]
        def request():
            try:ow.request_owner(self.runtime,'fixture',timeout=1);result.append(True)
            except ow.OwnerError:result.append(False)
        thread=threading.Thread(target=request);thread.start();end=time.monotonic()+.2
        while not self.messages and time.monotonic()<end:time.sleep(.005)
        self.assertTrue(self.messages);current[0]=c;message=self.messages[0]
        self.node.sendall(json.dumps({'v':1,'type':'ack','requestId':message['requestId']}).encode()+b'\n');thread.join(1)
        self.assertEqual(result,[False]);self.assertFalse(self.watch.failed)
    def test_wrong_cwd_inode_and_nul_fail_before_wire(self):
        b=self.runtime/'B';b.mkdir();info=b.stat()
        self.identity.cwd=lambda pid:ow.CwdBinding(str(b),info.st_dev,info.st_ino+1)
        self.start(cwd_backends=frozenset({'fixture'}))
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.messages,[])
        self.identity.cwd=lambda pid:ow.CwdBinding(str(b)+'\0',info.st_dev,info.st_ino)
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.messages,[])
    def test_peer_birth_change_while_ack_pending_rejects_helper(self):
        import time,json
        b=self.runtime/'B';b.mkdir();info=b.stat();self.identity.cwd=lambda pid:ow.CwdBinding(str(b),info.st_dev,info.st_ino)
        process=self.identity.process;generation=[1]
        def changed(pid):
            value=process(pid)
            return ow.Identity(value.pid,value.ppid,value.uid,generation[0] if pid==os.getpid() else value.seconds,value.microseconds,value.path,value.status)
        self.identity.process=changed;self.start(ack=False,cwd_backends=frozenset({'fixture'}));result=[]
        def request():
            try:ow.request_owner(self.runtime,'fixture',timeout=1);result.append(True)
            except ow.OwnerError:result.append(False)
        thread=threading.Thread(target=request);thread.start();end=time.monotonic()+.2
        while not self.messages and time.monotonic()<end:time.sleep(.005)
        self.assertTrue(self.messages);generation[0]+=1;message=self.messages[0]
        self.node.sendall(json.dumps({'v':1,'type':'ack','requestId':message['requestId']}).encode()+b'\n');thread.join(1)
        self.assertEqual(result,[False])

    def test_actual_unix_peer_cwd_b_c_b_reuses_context(self):
        import subprocess,sys,json,base64
        b=self.runtime/'B unicode é';c=self.runtime/'C';b.mkdir();c.mkdir()
        native=self.identity.native
        def process(pid):
            if pid==777:return ow.Identity(pid,1,os.getuid(),1,0,'/synthetic/codex',1)
            value=native.process(pid)
            return ow.Identity(value.pid,777,value.uid,value.seconds,value.microseconds,'/synthetic/helper',value.status)
        self.identity.process=process;self.identity.cwd=native.cwd;self.start(cwd_backends=frozenset({'fixture'}))
        results=[];script=str(Path(ow.__file__).parent)
        code='import sys;sys.path.insert(0,'+repr(script)+');from owner_watch import request_owner;print(request_owner('+repr(str(self.runtime))+',"fixture"),flush=True)'
        for directory in [b,c,b]:
            child=subprocess.Popen([sys.executable,'-I','-c',code],cwd=directory,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            output,errors=child.communicate(timeout=3);self.assertEqual(child.returncode,0);self.assertEqual(errors,'');results.append(output.strip())
        self.assertEqual(results[0],results[2]);self.assertNotEqual(results[0],results[1]);self.assertEqual(len(self.events.armed),1)
        self.assertEqual(len(self.messages),2)
        for message,directory in zip(self.messages,[b,c]):
            binding=message['cwd'];path=base64.b64decode(binding['pathB64'],validate=True).decode('utf-8')
            self.assertEqual(Path(path).stat().st_ino,directory.stat().st_ino)
            self.assertEqual(binding['device'],str(directory.stat().st_dev));self.assertEqual(binding['inode'],str(directory.stat().st_ino))
    def test_bridge_small_cwd_buffer_rejected_without_copy(self):
        import ctypes
        native=ow.NativeIdentity();values=(ctypes.c_uint64*2)();path=ctypes.create_string_buffer(b'Z',2)
        self.assertEqual(native.library.pm_cwd(os.getpid(),values,path,2),-1);self.assertEqual(path.raw,b'Z\0')


class LokiGuardRegistrationTests(unittest.TestCase):
    """Pure registration fixtures: no native bridge, child, socket or thread."""
    def setUp(self):
        from types import SimpleNamespace
        import loki_profile as loki
        from loki_owner_environment import LokiOwnerEnvironmentGuard
        self.owner=ow.Identity(777,1,os.getuid(),1,0,ow.REVIEWED_CODEX,1)
        self.env={'HOME':'/synthetic/home'}
        identity=SimpleNamespace(boot=lambda:'fixture',process=lambda pid:self.owner,cwd=lambda pid:ow.CwdBinding('/',1,2))
        sources={name:{'command':'npx','args':['-y','simple-loki-mcp'],'env':{'LOKI_ADDR':'synthetic','LOKI_DATASOURCE_ID':'synthetic','LOKI_BEARER_TOKEN':'synthetic'}} for name in loki.PROFILES}
        expected={name:dict(self.env,**source['env']) for name,source in sources.items()}
        self.reads=0
        def read(pid):self.reads+=1;return self.owner,SimpleNamespace(environment=dict(self.env))
        self.guard=LokiOwnerEnvironmentGuard(sources,expected,identity=identity,reader=SimpleNamespace(read=read))
        self.identity=identity;self.channel=SimpleNamespace(settimeout=lambda value:None)
    def watch(self,guard=True,backends=None):
        watch=ow.OwnerWatch('/synthetic',self.channel,backends=backends or {'loki-stg','loki-prd','loki-tools','other'},identity=self.identity,events=Events(),signature=lambda path:'fixture',loki_environment_guard=self.guard if guard else None)
        owner=ow.Owner(self.owner,1);watch.owner_for=lambda peer:owner
        self.sent=[]
        def send(message):
            self.sent.append(message);ack=watch.acks[message['requestId']];ack.seen=True;ack.event.set()
        watch.send=send
        return watch
    def test_cached_registration_fresh_guard_before_token_return(self):
        import time
        watch=self.watch();first=watch.register((777,os.getuid()),'loki-stg',time.monotonic()+1)
        self.assertEqual(self.reads,2)
        self.assertEqual(watch.register((777,os.getuid()),'loki-stg',time.monotonic()+1),first)
        self.assertEqual(self.reads,4);self.assertEqual(len(self.sent),1)
        self.env['HOME']='/changed'
        with self.assertRaises(ow.OwnerError):watch.register((777,os.getuid()),'loki-stg',time.monotonic()+1)
        self.assertEqual(len(self.sent),1)
    def test_post_ack_drift_rejected(self):
        import time
        watch=self.watch();send=watch.send
        def changed(message):send(message);self.env['HOME']='/changed'
        watch.send=changed
        with self.assertRaises(ow.OwnerError):watch.register((777,os.getuid()),'loki-stg',time.monotonic()+1)
        self.assertEqual(self.reads,2)
    def test_guard_cannot_silently_skip_configured_backend(self):
        with self.assertRaises(ow.OwnerError):self.watch(backends={'loki-stg','other'})
    def test_missing_guard_with_reserved_loki_backend_rejected(self):
        for backend in ('loki-stg','loki-prd','loki-tools'):
            with self.subTest(backend=backend), self.assertRaises(ow.OwnerError):
                self.watch(guard=False,backends={backend,'other'})

    def test_default_and_unrelated_backend_do_not_read_environment(self):
        import time
        self.watch().register((777,os.getuid()),'other',time.monotonic()+1)
        self.watch(guard=False,backends={'other'}).register((777,os.getuid()),'other',time.monotonic()+1)
        self.assertEqual(self.reads,0)


class ClaudeOwnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.runtime=Path(self.temp.name).resolve();os.chmod(self.runtime,0o700)
        self.parent,self.node=socket.socketpair();self.events=Events();self.watch=None;self.calls=[];self.key=1;self.digest='a'*64
    def tearDown(self):
        if self.watch:self.watch.close()
        self.parent.close();self.node.close();self.temp.cleanup()
    def signature(self,path):
        self.calls.append(path)
        if self.digest is None:raise ow.OwnerError()
        return self.digest
    def start(self,identity):
        def node():
            import json
            self.node.sendall(b'{"v":1,"type":"ready"}\n');buffer=b''
            try:
                while True:
                    chunk=self.node.recv(4096)
                    if not chunk:return
                    buffer+=chunk
                    while b'\n' in buffer:
                        line,buffer=buffer.split(b'\n',1);value=json.loads(line)
                        if value['type']=='register':self.node.sendall(json.dumps({'v':1,'type':'ack','requestId':value['requestId']}).encode()+b'\n')
            except OSError:return
        threading.Thread(target=node,daemon=True).start()
        self.watch=ow.OwnerWatch(self.runtime,self.parent,backends={'fixture'},identity=identity,events=self.events,signature=lambda path:None,reviewed_path='/synthetic/codex',deadline=.5,
            claude_match=lambda path:path.startswith('/synthetic/claude/'),claude_signature=self.signature,claude_key=lambda path:self.key,claude_root=None)
        self.watch.start()
    def test_signed_claude_owner_admitted_and_verified_once(self):
        self.start(ClaudeIdentity());first=ow.request_owner(self.runtime,'fixture',timeout=1);second=ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(first,second);self.assertEqual(len(first),64);self.assertEqual(self.events.armed[0][0],778)
        self.assertEqual(self.calls,['/synthetic/claude/2.1.300'])
    def test_unsigned_claude_owner_refused(self):
        self.digest=None;self.start(ClaudeIdentity())
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.events.armed,[])
    def test_unmatched_client_path_refused(self):
        self.start(ClaudeIdentity('/synthetic/other/2.1.300'))
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
        self.assertEqual(self.calls,[])
    def test_replaced_binary_with_new_digest_refused_for_new_owner(self):
        identity=ClaudeIdentity();self.start(identity);ow.request_owner(self.runtime,'fixture',timeout=1)
        pid,generation=self.events.armed[0];self.watch.handle_events([(pid,generation)]);identity.birth+=1
        self.key=2;self.digest='b'*64
        with self.assertRaises(ow.OwnerError):ow.request_owner(self.runtime,'fixture',timeout=1)
    def test_updated_file_with_same_digest_still_admitted(self):
        identity=ClaudeIdentity();self.start(identity);ow.request_owner(self.runtime,'fixture',timeout=1)
        pid,generation=self.events.armed[0];self.watch.handle_events([(pid,generation)]);identity.birth+=1
        self.key=2;ow.request_owner(self.runtime,'fixture',timeout=1);self.assertEqual(len(self.calls),2)

class ClaudeSignatureTests(unittest.TestCase):
    def test_claude_path_requires_versions_parent_semver_and_no_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root=os.path.realpath(temp);real=os.path.join(root,'2.1.300');open(real,'w').close()
            self.assertTrue(ow.claude_path(real,root))
            for bad in [os.path.join(root,'latest'),os.path.join(root,'2.1'),os.path.join(root,'x','2.1.300'),'/synthetic/claude/2.1.300']:
                self.assertFalse(ow.claude_path(bad,root))
            link=os.path.join(root,'2.1.301');os.symlink(real,link);self.assertFalse(ow.claude_path(link,root))
    def test_signed_claude_refuses_codex_and_unsigned_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root=os.path.realpath(temp);fake=os.path.join(root,'2.1.300');Path(fake).write_text('x');os.chmod(fake,0o755)
            with self.assertRaises(ow.OwnerError):ow.signed_claude(fake,root)
        if os.path.exists(ow.REVIEWED_CODEX):
            with self.assertRaises(ow.OwnerError):ow.signed_claude(ow.REVIEWED_CODEX)
    @unittest.skipUnless(os.path.isdir(ow.CLAUDE_ROOT) and os.listdir(ow.CLAUDE_ROOT),'no installed Claude Code')
    def test_installed_claude_binary_verifies(self):
        name=max(n for n in os.listdir(ow.CLAUDE_ROOT) if ow.CLAUDE_VERSION.fullmatch(n))
        self.assertRegex(ow.signed_claude(os.path.join(ow.CLAUDE_ROOT,name)),r'[0-9a-f]{64}\Z')

if __name__=='__main__':unittest.main()