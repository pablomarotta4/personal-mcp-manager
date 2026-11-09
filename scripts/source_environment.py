"""Bounded same-UID macOS environment observation; no CLI or serialization.

Kernel buffers/argv/selected values remain in the caller's memory. Signed-owner
authentication and original-source provenance are separate admission gates.
"""
import ctypes
from dataclasses import dataclass
import os
import re
import struct
import sys
from loki_profile import INHERITED

MAXIMUM=1048576
MAX_PROJECTION_KEYS=64
MAX_ENVIRONMENT_NAME=128
DARWIN_AUXILIARY={b'ptr_munge',b'main_stack',b'executable_file',b'dyld_file',b'executable_cdhash',b'executable_boothash',b'th_port',b'security_config'}

class EnvironmentObservationError(Exception):
    def __init__(self,code='layout'):
        super().__init__('SOURCE_ENVIRONMENT_OBSERVATION_FAILED')
        allowed={'layout','arguments','environment','auxiliary','prohibited',
                 'pid','identity_before','capacity','kernel_read','identity_after','executable'}
        self.code=code if code in allowed else 'layout'

class _EnvironmentParseFailure(Exception):
    def __init__(self,code='layout'):
        self.code=code

@dataclass(frozen=True,repr=False)
class ExecEnvironment:
    executable:str
    argv:tuple
    environment:dict

@dataclass(frozen=True,repr=False)
class ExecArguments:
    executable:str
    argv:tuple

def _checked_projection(environment_keys):
    if type(environment_keys) not in (set,frozenset) or len(environment_keys)>MAX_PROJECTION_KEYS:
        raise ValueError()
    try:
        selected=frozenset(environment_keys)
    except (TypeError,RuntimeError):
        raise ValueError() from None
    if len(selected)>MAX_PROJECTION_KEYS:
        raise ValueError()
    for name in selected:
        if (not isinstance(name,str) or len(name)>MAX_ENVIRONMENT_NAME
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',name)):
            raise ValueError()
    return selected

def _checked_prefixes(environment_prefixes):
    if type(environment_prefixes) not in (set,frozenset) or not environment_prefixes<=frozenset({'AWS_','PYTHON'}):
        raise ValueError()
    return frozenset(environment_prefixes)

def _parse_argument_prefix(data):
    try:
        if not isinstance(data,bytes) or not 5<=len(data)<=MAXIMUM or data[-1:]!=b'\0':
            raise ValueError()
        argc=struct.unpack_from('=i',data)[0]
        if not 1<=argc<=1024:raise ValueError()
        position=4
        def string(limit):
            nonlocal position
            end=data.find(b'\0',position)
            if end<position or end-position>limit:raise ValueError()
            value=data[position:end];position=end+1
            return value.decode('utf-8',errors='strict')
        executable=string(4096)
        if not os.path.isabs(executable):raise ValueError()
        while position<len(data) and data[position]==0:position+=1
        argv=tuple(string(16384) for _ in range(argc))
        if not argv[0]:raise ValueError()
        return ExecArguments(executable,argv),position
    except (ValueError,TypeError,UnicodeError,struct.error):
        raise _EnvironmentParseFailure('arguments') from None

def parse_procargs2_arguments(data):
    """Return only bounded executable/argv fields; never parse or return environ."""
    try:
        arguments,_position=_parse_argument_prefix(data)
        return arguments
    except _EnvironmentParseFailure as error:
        raise EnvironmentObservationError(error.code) from None

def parse_procargs2(data,environment_keys=None,*,environment_prefixes=frozenset()):
    try:
        selected_keys=INHERITED if environment_keys is None else _checked_projection(environment_keys)
        selected_prefixes=_checked_prefixes(environment_prefixes)
        arguments,position=_parse_argument_prefix(data)
        executable=arguments.executable
        argv=arguments.argv
        remaining=data[position:].rstrip(b'\0')
        fields=remaining.split(b'\0') if remaining else []
        if len(fields)>2048:raise _EnvironmentParseFailure('layout')
        # Keep a NUL-separated platform trailer behind the exact allowlist. A
        # leading empty field is ambiguous, so treat it as padding only when a
        # complete, structurally valid environment segment follows and a second
        # empty record terminates that segment. Hidden HOME/loader inputs remain
        # ambiguous and fail closed.
        if b'' in fields:
            boundary=fields.index(b'')
            if boundary == 0:
                try:
                    later_boundary=fields.index(b'',1)
                except ValueError:
                    later_boundary=None
                leading_environment=fields[1:later_boundary] if later_boundary is not None else []
                if (leading_environment and all(
                        field.partition(b'=')[1]
                        and re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_]*',field.partition(b'=')[0])
                        for field in leading_environment)):
                    fields=fields[1:]
                    boundary=later_boundary-1
            auxiliary=fields[boundary+1:];fields=fields[:boundary];auxiliary_seen=set()
            for field in auxiliary:
                if not field:continue
                key,separator,value=field.partition(b'=')
                if not separator or key not in DARWIN_AUXILIARY or key in auxiliary_seen or len(value)>4096:
                    raise _EnvironmentParseFailure('auxiliary')
                auxiliary_seen.add(key)
        seen=set();selected={}
        for field in fields:
            key,separator,value=field.partition(b'=')
            if not separator or not re.fullmatch(rb'[A-Za-z_][A-Za-z0-9_]*',key) or key in seen:
                raise _EnvironmentParseFailure('environment')
            seen.add(key);name=key.decode('ascii')
            if name in {'NODE_OPTIONS','NODE_PATH'} or name.startswith('DYLD_') or (name.startswith('LOKI_') and name not in INHERITED):
                raise _EnvironmentParseFailure('prohibited')
            if name in selected_keys or any(name.startswith(prefix) for prefix in selected_prefixes):
                if len(name)>MAX_ENVIRONMENT_NAME or len(selected)>=MAX_PROJECTION_KEYS:raise _EnvironmentParseFailure('environment')
                if len(value)>16384:raise _EnvironmentParseFailure('environment')
                selected[name]=value.decode('utf-8',errors='strict')
        return ExecEnvironment(executable,argv,selected)
    except EnvironmentObservationError:
        raise
    except _EnvironmentParseFailure as error:
        raise EnvironmentObservationError(error.code) from None
    except (ValueError,TypeError,UnicodeError,struct.error):
        raise EnvironmentObservationError('layout') from None

class KernelEnvironmentReader:
    def __init__(self,identity=None):
        if sys.platform!='darwin':raise EnvironmentObservationError()
        from owner_watch import NativeIdentity
        self.identity=identity or NativeIdentity()
        self.sysctl=ctypes.CDLL('/usr/lib/libSystem.B.dylib',use_errno=True).sysctl
        self.sysctl.argtypes=[ctypes.POINTER(ctypes.c_int),ctypes.c_uint,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p,ctypes.c_size_t]
        self.sysctl.restype=ctypes.c_int
    def _read_parsed(self,pid,parser):
        phase='pid'
        try:
            if type(pid)!=int or not 1<pid<=2147483647:raise ValueError()
            phase='identity_before'
            before=self.identity.process(pid)
            if before.pid!=pid or before.uid!=os.getuid() or before.status==self.identity.zombie:raise ValueError()
            phase='capacity'
            maximum=ctypes.c_int();size=ctypes.c_size_t(ctypes.sizeof(maximum));query=(ctypes.c_int*2)(1,8)
            if self.sysctl(query,2,ctypes.byref(maximum),ctypes.byref(size),None,0)!=0 or size.value!=ctypes.sizeof(maximum) or not 4096<=maximum.value<=MAXIMUM:raise ValueError()
            phase='kernel_read';buffer=ctypes.create_string_buffer(maximum.value);size=ctypes.c_size_t(maximum.value);query=(ctypes.c_int*3)(1,49,pid)
            if self.sysctl(query,3,buffer,ctypes.byref(size),None,0)!=0 or not 5<=size.value<=maximum.value:raise ValueError()
            phase='layout'
            try:
                observed=parser(buffer.raw[:size.value])
            except EnvironmentObservationError as error:
                if error.code in {'arguments','layout','environment','auxiliary','prohibited'}:
                    phase=error.code
                raise
            phase='identity_after';after=self.identity.process(pid)
            if before!=after:raise ValueError()
            phase='executable'
            if os.path.realpath(observed.executable)!=os.path.realpath(before.path):raise ValueError()
            return before,observed
        except Exception:raise EnvironmentObservationError(phase) from None

    def read(self,pid,environment_keys=None,*,environment_prefixes=frozenset()):
        return self._read_parsed(pid,lambda data:parse_procargs2(data,environment_keys,environment_prefixes=environment_prefixes))

    def read_arguments(self,pid):
        return self._read_parsed(pid,parse_procargs2_arguments)
