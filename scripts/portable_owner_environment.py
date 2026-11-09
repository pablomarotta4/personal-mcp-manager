"""Per-lease native environment reconstruction for reviewed portable routes."""
from copy import deepcopy
import hmac
import json
import os

from owner_watch import CwdBinding, Identity, OwnerError


class PortableEnvironmentGuard:
    """The owner watcher has verified vendor signature before calling this guard."""

    def __init__(self, routes: dict, *, identity, reader, client_kind, source_verifier=None):
        if not routes or len(routes) > 64:
            raise OwnerError()
        self._routes = deepcopy(routes)
        self.backends = frozenset(routes)
        self.families = {name: route["family"] for name, route in routes.items()}
        if any(family not in {"mysql", "loki", "langfuse"} for family in self.families.values()):
            raise OwnerError()
        self.context_backends = frozenset(name for name, family in self.families.items() if family == "mysql")
        self._identity = identity
        self._reader = reader
        self._client_kind = client_kind
        self._source_verifier = source_verifier

    def __repr__(self):
        return "<PortableEnvironmentGuard values withheld>"

    def __call__(self, backend, owner, client_cwd=None):
        try:
            route = self._routes[backend]
            if (type(owner) is not Identity or owner.uid != os.getuid()
                    or self._client_kind(owner.path) not in route["clients"]):
                raise OwnerError()
            before = self._identity.process(owner.pid)
            cwd = self._identity.cwd(owner.pid)
            if before != owner or type(cwd) is not CwdBinding:
                raise OwnerError()
            if self._source_verifier is not None:
                self._source_verifier(backend)
            family = route["family"]
            if family == "langfuse":
                return None
            if family == "mysql":
                return self._mysql(backend, owner, cwd, client_cwd)
            observed, snapshot = self._reader.read(owner.pid)
            self._unchanged(owner, cwd, observed)
            import loki_profile
            source = route["source"]
            inherited = loki_profile.native_owner_environment(snapshot.environment, cwd.path)
            actual = loki_profile.source_policy(source, inherited)["env"]
            encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            if not hmac.compare_digest(encode(actual), encode(route["expected_env"])):
                raise OwnerError()
            return None
        except Exception:
            raise OwnerError() from None

    def _unchanged(self, owner, cwd, observed):
        if observed != owner or self._identity.process(owner.pid) != owner or self._identity.cwd(owner.pid) != cwd:
            raise OwnerError()

    def _mysql(self, backend, owner, cwd, client_cwd):
        from mysql_environment import INHERITED, effective_environment
        if type(client_cwd) is not CwdBinding:
            raise OwnerError()
        observed, snapshot = self._reader.read(owner.pid, INHERITED)
        self._unchanged(owner, cwd, observed)
        source = self._routes[backend]["source"]
        environment, _ = effective_environment(source, snapshot.environment,
                                                source.get("cwd", client_cwd.path))
        return {"environment": environment}

