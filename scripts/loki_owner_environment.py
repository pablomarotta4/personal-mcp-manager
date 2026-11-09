"""Fresh signed-owner Loki launch-environment checks, entirely in memory.

Owners are the reviewed Codex binary or a Claude CLI version path; OwnerWatch has already
verified the signature before this guard runs, and the effective env must still match.

Construction requires already reviewed sources and expected effective launch envs.
This is an optional staging seam; it performs no source admission or launch.
"""
from dataclasses import dataclass, field
import hmac
import json
import os
import secrets
from types import MappingProxyType
import loki_profile as loki
from owner_watch import Identity, CwdBinding, OwnerError, REVIEWED_CODEX, claude_path

RESERVED=frozenset({'loki-stg','loki-prd','loki-tools'})


def _encode(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

@dataclass(frozen=True,repr=False,init=False)
class LokiOwnerEnvironmentGuard:
    backends:frozenset
    _sources:object=field(repr=False)
    _expected:object=field(repr=False)
    _key:bytes=field(repr=False)
    _identity:object=field(repr=False)
    _reader:object=field(repr=False)

    def __init__(self,sources,expected_envs,*,identity,reader):
        try:
            if type(sources)!=dict or type(expected_envs)!=dict or not sources or set(sources)!=set(expected_envs) or not set(sources)<=RESERVED:raise OwnerError()
            key=secrets.token_bytes(32);encoded={};expected={}
            for backend,source in sources.items():
                loki.validate_source(source,backend)
                env=expected_envs[backend]
                if type(env)!=dict or loki.source_policy(source,loki.native_owner_environment(env,'/'))['env']!=env:raise OwnerError()
                encoded[backend]=_encode(source)
                expected[backend]=hmac.digest(key,_encode(env),'sha256')
            for name,value in [('backends',frozenset(sources)),('_sources',MappingProxyType(encoded)),('_expected',MappingProxyType(expected)),('_key',key),('_identity',identity),('_reader',reader)]:object.__setattr__(self,name,value)
        except Exception:raise OwnerError() from None

    def __call__(self,backend,owner):
        try:
            if backend not in self.backends or type(owner)!=Identity or owner.uid!=os.getuid() or not (owner.path==REVIEWED_CODEX or claude_path(owner.path)):raise OwnerError()
            before=self._identity.process(owner.pid);cwd=self._identity.cwd(owner.pid)
            if before!=owner or type(cwd)!=CwdBinding:raise OwnerError()
            observed,environment=self._reader.read(owner.pid)
            if observed!=owner or self._identity.process(owner.pid)!=owner or self._identity.cwd(owner.pid)!=cwd:raise OwnerError()
            inherited=loki.native_owner_environment(environment.environment,cwd.path)
            effective=loki.source_policy(json.loads(self._sources[backend]),inherited)['env']
            if not hmac.compare_digest(self._expected[backend],hmac.digest(self._key,_encode(effective),'sha256')):raise OwnerError()
        except Exception:raise OwnerError() from None
