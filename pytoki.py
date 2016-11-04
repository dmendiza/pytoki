from cffi import FFI


# NULL_PTR = 0x00 - Needed???
#CK_VOID_PTR
CKR_OK = 0x00

ffi = FFI()

#TODO(dmend): Figure out why these don't work in CFFI
#    #define CK_PTR *
#    #define CK_DECLARE_FUNCTION(returnType, name) \
#        returnType name
#    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
#        returnType (* name)
#    #define CK_CALLBACK_FUNCTION(returnType, name) \
#        returnType (* name)


ffi.cdef("""
    #define NULL_PTR 0

    typedef unsigned char CK_BYTE;
    typedef CK_BYTE CK_CHAR;
    typedef CK_BYTE CK_UTF8CHAR;
    typedef CK_BYTE CK_BBOOL;
    typedef unsigned long int CK_ULONG;
    typedef long int CK_LONG;
    typedef CK_ULONG CK_FLAGS;
    typedef CK_ULONG CK_RV;

    typedef void * CK_VOID_PTR;

    typedef struct CK_VERSION {
        CK_BYTE major;
        CK_BYTE minor;
    } CK_VERSION;

    typedef struct CK_INFO {
        CK_VERSION cryptokiVersion;
        CK_UTF8CHAR manufacturerID[32];
        CK_FLAGS flags;
        CK_UTF8CHAR libraryDescription[32];
        CK_VERSION libraryVersion;
    } CK_INFO;

    typedef CK_INFO * CK_INFO_PTR;
""")

ffi.cdef("""
    CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
    CK_RV C_Finalize(CK_VOID_PTR pReserved);
    CK_RV C_GetInfo(CK_INFO_PTR pInfo);
""")

def error_check(value):
    if rv == CKR_OK:
        print('All good in the hood')
    else:
        print('Uh oh {}'.format(rv))

cryptoki = ffi.dlopen('/usr/local/lib/libykcs11.dylib')
rv = cryptoki.C_Initialize(ffi.NULL)
error_check(rv)

info = ffi.new('CK_INFO_PTR')
rv = cryptoki.C_GetInfo(info)
error_check(rv)
print('{}.{}'.format(info.cryptokiVersion.major, info.cryptokiVersion.minor))
print('{}.{}'.format(info.libraryVersion.major, info.libraryVersion.minor))
print(ffi.string(info.manufacturerID))
print(ffi.string(info.libraryDescription))

rv = cryptoki.C_Finalize(ffi.NULL)
error_check(rv)
