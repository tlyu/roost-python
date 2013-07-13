import ctypes
import functools

import krb5_ctypes

__all__ = ['Context']

class Error(Exception):
    def __init__(self, ctx_raw, code):
        self.code = code
        msg_c = krb5_ctypes.krb5_get_error_message(ctx_raw, code)
        self.message = msg_c.value
        krb5_ctypes.krb5_free_error_message(ctx_raw, msg_c)

    def __str__(self):
        return self.message

def check_error(fn):
    if fn.restype is not krb5_ctypes.krb5_error_code:
        return fn
    @functools.wraps(fn)
    def wrapped(ctx, *args):
        ret = fn(ctx, *args)
        if ret:
            raise Error(ctx, ret)
        return ret
    return wrapped

krb5_init_context = check_error(krb5_ctypes.krb5_init_context)
krb5_free_context = check_error(krb5_ctypes.krb5_free_context)
krb5_cc_default = check_error(krb5_ctypes.krb5_cc_default)
krb5_cc_close = check_error(krb5_ctypes.krb5_cc_close)
krb5_cc_get_principal = check_error(krb5_ctypes.krb5_cc_get_principal)
krb5_free_principal = check_error(krb5_ctypes.krb5_free_principal)
krb5_unparse_name = check_error(krb5_ctypes.krb5_unparse_name)
krb5_free_unparsed_name = check_error(krb5_ctypes.krb5_free_unparsed_name)
krb5_build_principal = check_error(krb5_ctypes.krb5_build_principal)
krb5_get_credentials = check_error(krb5_ctypes.krb5_get_credentials)
krb5_free_creds = check_error(krb5_ctypes.krb5_free_creds)

def to_str(obj):
    if isinstance(obj, str):
        return obj
    if isinstance(obj, unicode):
        return obj.encode('utf-8')
    raise TypeError('Expected string')

class Context(object):
    def __init__(self):
        self._handle = krb5_ctypes.krb5_context()
        krb5_init_context(self._handle)

    def __del__(self):
        if bool(self._handle):
            krb5_free_context(self._handle)

    def cc_default(self):
        ccache = CCache(self)
        krb5_cc_default(self._handle, ccache._handle)
        return ccache

    def build_principal(self, realm, name):
        realm = to_str(realm)
        name = [to_str(comp) for comp in name]
        principal = Principal(self)
        name_args = [ctypes.c_char_p(comp) for comp in name]
        name_args.append(ctypes.c_char_p())
        krb5_build_principal(self._handle,
                             principal._handle,
                             len(realm),
                             ctypes.c_char_p(realm),
                             *name_args)
        return principal

class CCache(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_ccache()

    def __del__(self):
        if bool(self._handle):
            krb5_cc_close(self._ctx._handle, self._handle)

    def get_principal(self):
        principal = Principal(self._ctx)
        krb5_cc_get_principal(self._ctx._handle,
                              self._handle,
                              principal._handle)
        return principal

    def get_credentials(self, client, server,
                        cache_only=False,
                        user_to_user=False):
        flags = 0
        if cache_only:
            flags |= krb5_ctypes.KRB5_GC_CACHED
        if user_to_user:
            flags |= krb5_ctypes.KRB5_GC_USER_USER

        in_creds = krb5_ctypes.krb5_creds()
        in_creds.client = client._handle
        in_creds.server = server._handle
        # TODO(davidben): If we care, pass in parameters for the other
        # options too.
        creds = Credentials(self._ctx)
        krb5_get_credentials(self._ctx._handle, flags, self._handle, in_creds,
                             creds._handle)
        return creds

class Principal(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_principal()

    def __del__(self):
        if bool(self._handle):
            krb5_free_principal(self._ctx._handle, self._handle)

    def unparse_name(self):
        name_c = ctypes.c_char_p()
        krb5_unparse_name(self._ctx._handle, self._handle, name_c)
        name = name_c.value
        krb5_free_unparsed_name(self._ctx._handle, name_c)
        return name

    def __str__(self):
        return self.unparse_name()

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self.unparse_name())

class Credentials(object):
    def __init__(self, ctx):
        self._ctx = ctx
        self._handle = krb5_ctypes.krb5_creds_ptr()

    def __del__(self):
        if bool(self._handle):
            krb5_free_creds(self._ctx._handle, self._handle)
