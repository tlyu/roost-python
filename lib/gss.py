import ctypes
import functools

import gss_ctypes

def _display_status(status_value, status_type):
    ret = []
    status_string = gss_ctypes.gss_buffer_desc()
    message_context = gss_ctypes.OM_uint32()
    for _ in xrange(8):
        gss_display_status(status_value, status_type,
                           None, message_context, status_string)
        try:
            ret.append(status_string.as_str())
        finally:
            gss_release_buffer(status_string)
        if message_context.value == 0:
            break
    return ret

class Error(Exception):
    def __init__(self, major, minor):
        self.major = major
        self.minor = minor
        self.messages = []
        if major != gss_ctypes.GSS_S_FAILURE:
            self.messages += _display_status(major, gss_ctypes.GSS_C_GSS_CODE)
        if minor:
            self.messages += _display_status(minor, gss_ctypes.GSS_C_MECH_CODE)

    def __str__(self):
        return '; '.join(self.messages)

def check_error(fn):
    @functools.wraps(fn)
    def wrapped(*args):
        minor = gss_ctypes.OM_uint32()
        ret = fn(minor, *args)
        if gss_ctypes.GSS_ERROR(ret):
            raise Error(ret, minor.value)
        return ret
    return wrapped

gss_acquire_cred = check_error(gss_ctypes.gss_acquire_cred)
gss_release_cred = check_error(gss_ctypes.gss_release_cred)
gss_init_sec_context = check_error(gss_ctypes.gss_init_sec_context)
gss_delete_sec_context = check_error(gss_ctypes.gss_delete_sec_context)
gss_display_status = check_error(gss_ctypes.gss_display_status)
gss_display_name = check_error(gss_ctypes.gss_display_name)
gss_import_name = check_error(gss_ctypes.gss_import_name)
gss_release_name = check_error(gss_ctypes.gss_release_name)
gss_release_oid_set = check_error(gss_ctypes.gss_release_oid_set)
gss_release_buffer = check_error(gss_ctypes.gss_release_buffer)
gss_canonicalize_name = check_error(gss_ctypes.gss_canonicalize_name)

def to_str(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    raise TypeError('Expected string')

__all__ = ['KRB5_MECHANISM',
           'C_NT_HOSTBASED_SERVICE',
           'C_NT_EXPORT_NAME',
           'import_name']

class OID(object):
    def __init__(self, handle, copy=False):
        if copy:
            self._data = ctypes.string_at(handle.elements,
                                          handle.length)
            self._handle = gss_ctypes.gss_OID_desc()
            self._handle.elements = ctypes.c_char_p(self._data)
            self._handle.length = len(self._data)
        else:
            self._handle = handle

C_NT_HOSTBASED_SERVICE = OID(gss_ctypes.GSS_C_NT_HOSTBASED_SERVICE.contents)
C_NT_EXPORT_NAME = OID(gss_ctypes.GSS_C_NT_EXPORT_NAME.contents)

KRB5_MECHANISM = OID(gss_ctypes.gss_mech_krb5.contents)
KRB5_NT_PRINCIPAL_NAME = OID(gss_ctypes.GSS_KRB5_NT_PRINCIPAL_NAME.contents)

def import_name(inp, oid):
    inp = to_str(inp)
    name = Name()
    inp_buf = gss_ctypes.gss_buffer_desc()
    inp_buf.length = len(inp)
    inp_buf.value = ctypes.c_char_p(inp)
    gss_import_name(inp_buf, oid._handle, name._handle)
    return name

class Name(object):
    def __init__(self):
        self._handle = gss_ctypes.gss_name_t()

    def __del__(self):
        if bool(self._handle):
            gss_release_name(self._handle)

    def display(self):
        buf = gss_ctypes.gss_buffer_desc()
        oid = gss_ctypes.gss_OID()
        gss_display_name(self._handle, buf, oid)
        try:
            return (buf.as_str(), OID(oid.contents))
        finally:
            gss_release_buffer(buf)

    def canonicalize(self, oid):
        name = Name()
        gss_canonicalize_name(self._handle, oid._handle, name._handle)
        return name

    def __str__(self):
        return self.display()[0]

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, str(self))
