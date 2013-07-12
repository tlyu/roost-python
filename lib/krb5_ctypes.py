import ctypes

# Library
libkrb5 = ctypes.cdll.LoadLibrary("libkrb5.so.3")

# Types
krb5_int32 = ctypes.c_int32
krb5_error_code = krb5_int32
krb5_magic = krb5_error_code

class _krb5_context(ctypes.Structure): pass
krb5_context = ctypes.POINTER(_krb5_context)
class _krb5_ccache(ctypes.Structure): pass
krb5_ccache = ctypes.POINTER(_krb5_ccache)

class krb5_data(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('length', ctypes.c_uint),
                ('data', ctypes.POINTER(ctypes.c_char))]

class krb5_principal_data(ctypes.Structure):
    _fields_ = [('magic', krb5_magic),
                ('realm', krb5_data),
                ('data', ctypes.POINTER(krb5_data)),
                ('length', krb5_int32),
                ('type', krb5_int32)]
krb5_principal = ctypes.POINTER(krb5_principal_data)
krb5_const_principal = ctypes.POINTER(krb5_principal_data)

# Don't do the conversion on return.
class _c_char_p_noconv(ctypes.c_char_p): pass

# Functions
krb5_init_context = libkrb5.krb5_init_context
krb5_init_context.restype = krb5_error_code
krb5_init_context.argtypes = (ctypes.POINTER(krb5_context),)

krb5_free_context = libkrb5.krb5_free_context
krb5_free_context.restype = None
krb5_free_context.argtypes = (krb5_context,)

krb5_cc_default = libkrb5.krb5_cc_default
krb5_cc_default.restype = krb5_error_code
krb5_cc_default.argtypes = (krb5_context, ctypes.POINTER(krb5_ccache))

krb5_cc_close = libkrb5.krb5_cc_close
krb5_cc_close.restype = krb5_error_code
krb5_cc_close.argtypes = (krb5_context, krb5_ccache)

krb5_cc_get_principal = libkrb5.krb5_cc_get_principal
krb5_cc_get_principal.restype = krb5_error_code
krb5_cc_get_principal.argtypes = (krb5_context,
                                  krb5_ccache,
                                  ctypes.POINTER(krb5_principal))

krb5_free_principal = libkrb5.krb5_free_principal
krb5_free_principal.restype = None
krb5_free_principal.argtypes = (krb5_context, krb5_principal)

krb5_unparse_name = libkrb5.krb5_unparse_name
krb5_unparse_name.restype = krb5_error_code
krb5_unparse_name.argtypes = (krb5_context,
                              krb5_const_principal,
                              ctypes.POINTER(ctypes.c_char_p))

krb5_free_unparsed_name = libkrb5.krb5_free_unparsed_name
krb5_free_unparsed_name.restype = None
krb5_free_unparsed_name.argtypes = (krb5_context, ctypes.c_char_p)

krb5_get_error_message = libkrb5.krb5_get_error_message
krb5_get_error_message.restype = _c_char_p_noconv
krb5_get_error_message.argtypes = (krb5_context, krb5_error_code)

krb5_free_error_message = libkrb5.krb5_free_error_message
krb5_free_error_message.restype = None
krb5_free_error_message.argtypes = (krb5_context, ctypes.c_char_p)
