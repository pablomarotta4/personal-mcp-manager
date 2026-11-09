import os
import unittest
from types import SimpleNamespace
import owner_watch as ow
import loki_profile as loki

class LokiOwnerEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.owner=ow.Identity(777,1,os.getuid(),2,3,ow.REVIEWED_CODEX,1)
        self.cwd=ow.CwdBinding('/',1,2)
        self.native={'HOME':'/synthetic/home','NODE_EXTRA_CA_CERTS':'/synthetic/ca','SSL_CERT_FILE':'/synthetic/ssl'}
        self.sources={name:{'command':'npx','args':['-y','simple-loki-mcp'],'env':{'LOKI_ADDR':'synthetic','LOKI_DATASOURCE_ID':'synthetic','LOKI_BEARER_TOKEN':'synthetic'}} for name in loki.PROFILES}
        self.expected={name:dict(self.native,**source['env']) for name,source in self.sources.items()}
        self.identity=SimpleNamespace(process=lambda pid:self.owner,cwd=lambda pid:self.cwd)
        self.reader=SimpleNamespace(read=lambda pid:(self.owner,SimpleNamespace(environment=dict(self.native))))
    def guard(self):
        import loki_owner_environment as guard
        return guard.LokiOwnerEnvironmentGuard(self.sources,self.expected,identity=self.identity,reader=self.reader)
    def test_fresh_read_detects_home_and_ca_drift(self):
        guard=self.guard();guard('loki-stg',self.owner)
        for key in self.native:
            old=self.native[key];self.native[key]=old+'-changed'
            with self.assertRaises(ow.OwnerError):guard('loki-stg',self.owner)
            self.native[key]=old
    def test_claude_owner_admitted_only_with_matching_environment(self):
        guard=self.guard();self.owner=ow.Identity(777,1,os.getuid(),2,3,os.path.join(ow.CLAUDE_ROOT,'2.1.300'),1)
        if os.path.realpath(self.owner.path)!=self.owner.path:self.skipTest('installed path is a symlink')
        guard('loki-stg',self.owner)
        self.native['HOME']='/synthetic/other-home'
        with self.assertRaises(ow.OwnerError):guard('loki-stg',self.owner)
    def test_unreviewed_client_path_refused(self):
        guard=self.guard()
        for path in ['/synthetic/other',os.path.join(ow.CLAUDE_ROOT,'latest'),os.path.join(ow.CLAUDE_ROOT,'x','2.1.300')]:
            self.owner=ow.Identity(777,1,os.getuid(),2,3,path,1)
            with self.assertRaises(ow.OwnerError):guard('loki-stg',self.owner)
    def test_ignored_proxy_and_caller_mutation_isolation(self):
        guard=self.guard();self.native['HTTPS_PROXY']='ignored'
        self.sources['loki-stg']['env']['LOKI_ADDR']='mutated';self.expected['loki-stg']['HOME']='mutated'
        guard('loki-stg',self.owner)
    def test_wrong_identity_uid_reader_error_and_cwd_drift_fail_closed(self):
        guard=self.guard()
        wrong=ow.Identity(777,1,os.getuid()+1,2,3,ow.REVIEWED_CODEX,1)
        with self.assertRaises(ow.OwnerError):guard('loki-stg',wrong)
        self.reader.read=lambda pid:(wrong,SimpleNamespace(environment=self.native))
        with self.assertRaises(ow.OwnerError):guard('loki-stg',self.owner)
        def broken(pid):raise RuntimeError('sensitive fixture')
        self.reader.read=broken
        with self.assertRaisesRegex(ow.OwnerError,'^OWNER_WATCH_FAILED$'):guard('loki-stg',self.owner)
        def changed(pid):self.cwd=ow.CwdBinding('/changed',1,3);return self.owner,SimpleNamespace(environment=self.native)
        self.reader.read=changed
        with self.assertRaises(ow.OwnerError):guard('loki-stg',self.owner)
    def test_empty_unknown_and_mismatched_configuration_rejected(self):
        for sources,expected in [({},{}),(self.sources,{}),({'other':self.sources['loki-stg']},{'other':self.expected['loki-stg']})]:
            import loki_owner_environment as guard
            with self.assertRaises(ow.OwnerError):guard.LokiOwnerEnvironmentGuard(sources,expected,identity=self.identity,reader=self.reader)
    def test_birth_drift_before_and_during_read_rejected(self):
        guard=self.guard();changed=ow.Identity(777,1,os.getuid(),9,3,ow.REVIEWED_CODEX,1)
        self.identity.process=lambda pid:changed
        with self.assertRaises(ow.OwnerError):guard('loki-stg',self.owner)
        self.identity.process=lambda pid:self.owner
        def race(pid):
            self.identity.process=lambda pid:changed
            return self.owner,SimpleNamespace(environment=self.native)
        self.reader.read=race
        with self.assertRaises(ow.OwnerError):guard('loki-stg',self.owner)

    def test_claude_read_injection_and_birth_race_refused(self):
        guard=self.guard()
        self.owner=ow.Identity(777,1,os.getuid(),2,3,os.path.join(ow.CLAUDE_ROOT,'2.1.300'),1)
        for name in ('NODE_OPTIONS','NODE_PATH','DYLD_INSERT_LIBRARIES','LOKI_UNREVIEWED'):
            with self.subTest(name=name):
                self.native[name]='synthetic'
                with self.assertRaisesRegex(ow.OwnerError,'^OWNER_WATCH_FAILED$'):guard('loki-stg',self.owner)
                del self.native[name]
        changed=ow.Identity(777,1,os.getuid(),99,3,self.owner.path,1)
        def raced(pid):
            self.identity.process=lambda pid:changed
            return self.owner,SimpleNamespace(environment=dict(self.native))
        self.reader.read=raced
        with self.assertRaisesRegex(ow.OwnerError,'^OWNER_WATCH_FAILED$'):guard('loki-stg',self.owner)

    def test_guard_frozen(self):
        guard=self.guard()
        with self.assertRaises(AttributeError):guard.backends=frozenset()

if __name__=='__main__':unittest.main()
