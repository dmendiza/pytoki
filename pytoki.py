from cffi import FFI
import click



CK_TRUE = 0x01
CK_FALSE = 0x00

# NULL_PTR = 0x00 - Needed???
#CK_VOID_PTR
CKR_OK = 0x00

CKU_USER = 0x01

CKO_SECRET_KEY = 0x04

CKA_KEY_TYPE = 0x0100

CKK_RSA = 0x0000

CKF_RW_SESSION = 0x02
CKF_SERIAL_SESSION = 0x04

_ffi = FFI()
_SESSION_STATES = {
    2: "CKS_RW_PUBLIC_SESSION",
    3: "CKS_RW_USER_FUNCTIONS"
}

_ERRORS = {
    0x00000160: 'CKR_SAVED_STATE_INVALID',
    0x000000A0: 'CKR_PIN_INCORRECT'
}

_MECHANISMS = {
    0x00000000: 'CKM_RSA_PKCS_KEY_PAIR_GEN',
    0x00000001: 'CKM_RSA_PKCS',
    0x00000002: 'CKM_RSA_9796',
    0x00000003: 'CKM_RSA_X_509',

    0x00000004: 'CKM_MD2_RSA_PKCS',
    0x00000005: 'CKM_MD5_RSA_PKCS',
    0x00000006: 'CKM_SHA1_RSA_PKCS',

    0x00000007: 'CKM_RIPEMD128_RSA_PKCS',
    0x00000008: 'CKM_RIPEMD160_RSA_PKCS',
    0x00000009: 'CKM_RSA_PKCS_OAEP',

    0x0000000A: 'CKM_RSA_X9_31_KEY_PAIR_GEN',
    0x0000000B: 'CKM_RSA_X9_31',
    0x0000000C: 'CKM_SHA1_RSA_X9_31',
    0x0000000D: 'CKM_RSA_PKCS_PSS',
    0x0000000E: 'CKM_SHA1_RSA_PKCS_PSS',

    0x00000010: 'CKM_DSA_KEY_PAIR_GEN',
    0x00000011: 'CKM_DSA',
    0x00000012: 'CKM_DSA_SHA1',
    0x00000013: 'CKM_DSA_SHA224',
    0x00000014: 'CKM_DSA_SHA256',
    0x00000015: 'CKM_DSA_SHA384',
    0x00000016: 'CKM_DSA_SHA512',

    0x00000020: 'CKM_DH_PKCS_KEY_PAIR_GEN',
    0x00000021: 'CKM_DH_PKCS_DERIVE',

    0x00000030: 'CKM_X9_42_DH_KEY_PAIR_GEN',
    0x00000031: 'CKM_X9_42_DH_DERIVE',
    0x00000032: 'CKM_X9_42_DH_HYBRID_DERIVE',
    0x00000033: 'CKM_X9_42_MQV_DERIVE',

    0x00000040: 'CKM_SHA256_RSA_PKCS',
    0x00000041: 'CKM_SHA384_RSA_PKCS',
    0x00000042: 'CKM_SHA512_RSA_PKCS',
    0x00000043: 'CKM_SHA256_RSA_PKCS_PSS',
    0x00000044: 'CKM_SHA384_RSA_PKCS_PSS',
    0x00000045: 'CKM_SHA512_RSA_PKCS_PSS',

    0x00000046: 'CKM_SHA224_RSA_PKCS',
    0x00000047: 'CKM_SHA224_RSA_PKCS_PSS',

    0x00000048: 'CKM_SHA512_224',
    0x00000049: 'CKM_SHA512_224_HMAC',
    0x0000004A: 'CKM_SHA512_224_HMAC_GENERAL',
    0x0000004B: 'CKM_SHA512_224_KEY_DERIVATION',
    0x0000004C: 'CKM_SHA512_256',
    0x0000004D: 'CKM_SHA512_256_HMAC',
    0x0000004E: 'CKM_SHA512_256_HMAC_GENERAL',
    0x0000004F: 'CKM_SHA512_256_KEY_DERIVATION',

    0x00000050: 'CKM_SHA512_T',
    0x00000051: 'CKM_SHA512_T_HMAC',
    0x00000052: 'CKM_SHA512_T_HMAC_GENERAL',
    0x00000053: 'CKM_SHA512_T_KEY_DERIVATION',

    0x00000100: 'CKM_RC2_KEY_GEN',
    0x00000101: 'CKM_RC2_ECB',
    0x00000102: 'CKM_RC2_CBC',
    0x00000103: 'CKM_RC2_MAC',

    0x00000104: 'CKM_RC2_MAC_GENERAL',
    0x00000105: 'CKM_RC2_CBC_PAD',

    0x00000110: 'CKM_RC4_KEY_GEN',
    0x00000111: 'CKM_RC4',
    0x00000120: 'CKM_DES_KEY_GEN',
    0x00000121: 'CKM_DES_ECB',
    0x00000122: 'CKM_DES_CBC',
    0x00000123: 'CKM_DES_MAC',

    0x00000124: 'CKM_DES_MAC_GENERAL',
    0x00000125: 'CKM_DES_CBC_PAD',

    0x00000130: 'CKM_DES2_KEY_GEN',
    0x00000131: 'CKM_DES3_KEY_GEN',
    0x00000132: 'CKM_DES3_ECB',
    0x00000133: 'CKM_DES3_CBC',
    0x00000134: 'CKM_DES3_MAC',

    0x00000135: 'CKM_DES3_MAC_GENERAL',
    0x00000136: 'CKM_DES3_CBC_PAD',
    0x00000137: 'CKM_DES3_CMAC_GENERAL',
    0x00000138: 'CKM_DES3_CMAC',
    0x00000140: 'CKM_CDMF_KEY_GEN',
    0x00000141: 'CKM_CDMF_ECB',
    0x00000142: 'CKM_CDMF_CBC',
    0x00000143: 'CKM_CDMF_MAC',
    0x00000144: 'CKM_CDMF_MAC_GENERAL',
    0x00000145: 'CKM_CDMF_CBC_PAD',

    0x00000201: 'CKM_MD2_HMAC',
    0x00000202: 'CKM_MD2_HMAC_GENERAL',

    0x00000210: 'CKM_MD5',

    0x00000211: 'CKM_MD5_HMAC',
    0x00000212: 'CKM_MD5_HMAC_GENERAL',

    0x00000220: 'CKM_SHA_1',

    0x00000221: 'CKM_SHA_1_HMAC',
    0x00000222: 'CKM_SHA_1_HMAC_GENERAL',

    0x00000250: 'CKM_SHA256',
    0x00000251: 'CKM_SHA256_HMAC',
    0x00000252: 'CKM_SHA256_HMAC_GENERAL',
    0x00000255: 'CKM_SHA224',
    0x00000256: 'CKM_SHA224_HMAC',
    0x00000257: 'CKM_SHA224_HMAC_GENERAL',
    0x00000260: 'CKM_SHA384',
    0x00000261: 'CKM_SHA384_HMAC',
    0x00000262: 'CKM_SHA384_HMAC_GENERAL',
    0x00000270: 'CKM_SHA512',
    0x00000271: 'CKM_SHA512_HMAC',
    0x00000272: 'CKM_SHA512_HMAC_GENERAL',
    0x00000280: 'CKM_SECURID_KEY_GEN',
    0x00000282: 'CKM_SECURID',
    0x00000290: 'CKM_HOTP_KEY_GEN',
    0x00000291: 'CKM_HOTP',
    0x000002A0: 'CKM_ACTI',
    0x000002A1: 'CKM_ACTI_KEY_GEN',

    0x00001040: 'CKM_EC_KEY_PAIR_GEN',

    0x00001041: 'CKM_ECDSA',
    0x00001042: 'CKM_ECDSA_SHA1',
    0x00001043: 'CKM_ECDSA_SHA224',
    0x00001044: 'CKM_ECDSA_SHA256',
    0x00001045: 'CKM_ECDSA_SHA384',
    0x00001046: 'CKM_ECDSA_SHA512',
}

#TODO(dmend): Figure out why these don't work in CFFI
#    #define CK_PTR *
#    #define CK_DECLARE_FUNCTION(returnType, name) \
#        returnType name
#    #define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
#        returnType (* name)
#    #define CK_CALLBACK_FUNCTION(returnType, name) \
#        returnType (* name)


_ffi.cdef("""
    #define NULL_PTR 0

    typedef unsigned char CK_BYTE;
    typedef CK_BYTE CK_CHAR;
    typedef CK_BYTE CK_UTF8CHAR;
    typedef CK_BYTE CK_BBOOL;
    typedef unsigned long int CK_ULONG;
    typedef long int CK_LONG;
    typedef CK_ULONG CK_FLAGS;
    typedef CK_ULONG CK_RV;
    typedef CK_ULONG CK_SLOT_ID;
    typedef CK_ULONG CK_SESSION_HANDLE;
    typedef CK_ULONG CK_STATE;
    typedef CK_ULONG CK_USER_TYPE;
    typedef CK_ULONG CK_OBJECT_HANDLE;
    typedef CK_ULONG CK_ATTRIBUTE_TYPE;
    typedef CK_ULONG CK_KEY_TYPE;
    typedef CK_ULONG CK_MECHANISM_TYPE;

    typedef void * CK_VOID_PTR;
    typedef CK_ULONG * CK_ULONG_PTR;
    typedef CK_UTF8CHAR * CK_UTF8CHAR_PTR;
    typedef CK_SLOT_ID * CK_SLOT_ID_PTR;
    typedef CK_SESSION_HANDLE * CK_SESSION_HANDLE_PTR;
    typedef ... * CK_NOTIFY;

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

    typedef struct CK_SLOT_INFO {
        CK_UTF8CHAR slotDescription[64];
        CK_UTF8CHAR manufacturerID[32];
        CK_FLAGS flags;
        CK_VERSION hardwareVersion;
        CK_VERSION firmwareVersion;
    } CK_SLOT_INFO;

    typedef struct CK_SESSION_INFO {
        CK_SLOT_ID slotID;
        CK_STATE state;
        CK_FLAGS flags;
        CK_ULONG ulDeviceError;
    } CK_SESSION_INFO;

    typedef struct CK_ATTRIBUTE {
        CK_ATTRIBUTE_TYPE type;
        CK_VOID_PTR pValue;
        CK_ULONG ulValueLen;
    } CK_ATTRIBUTE;

    typedef CK_INFO * CK_INFO_PTR;
    typedef CK_SLOT_INFO * CK_SLOT_INFO_PTR;
    typedef CK_SESSION_INFO * CK_SESSION_INFO_PTR;
    typedef CK_OBJECT_HANDLE * CK_OBJECT_HANDLE_PTR;
    typedef CK_ATTRIBUTE * CK_ATTRIBUTE_PTR;
    typedef CK_MECHANISM_TYPE * CK_MECHANISM_TYPE_PTR;
""")

_ffi.cdef("""
    CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
    CK_RV C_Finalize(CK_VOID_PTR pReserved);
    CK_RV C_GetInfo(CK_INFO_PTR pInfo);
    CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                        CK_SLOT_ID_PTR pSlotList,
                        CK_ULONG_PTR pulCount);
    CK_RV C_GetSlotInfo(CK_SLOT_ID slotID,
                        CK_SLOT_INFO_PTR pInfo);
    CK_RV C_OpenSession(CK_SLOT_ID slotID,
                        CK_FLAGS flags,
                        CK_VOID_PTR pApplication,
                        CK_NOTIFY Notify,
                        CK_SESSION_HANDLE_PTR phSession);
    CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);
    CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession,
                           CK_SESSION_INFO_PTR pInfo);
    CK_RV C_Login(CK_SESSION_HANDLE hSession,
                  CK_USER_TYPE userType,
                  CK_UTF8CHAR_PTR pPin,
                  CK_ULONG ulPinLen);
    CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                            CK_ATTRIBUTE_PTR pTemplate,
                            CK_ULONG ulCount);
    CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE_PTR phObject,
                        CK_ULONG ulMaxObjectCount,
                        CK_ULONG_PTR pulObjectCount);
    CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);
    CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                             CK_MECHANISM_TYPE_PTR pMechanismList,
                             CK_ULONG_PTR pulCount);
""")

cryptoki = _ffi.dlopen('/usr/local/lib/libykcs11.dylib')


def error_check(value):
    if value != CKR_OK:
        print('Uh oh {}'.format(_ERRORS[value]))


@click.group()
def cli():
    rv = cryptoki.C_Initialize(_ffi.NULL)

@cli.command()
def slots():
    count_pt = _ffi.new('CK_ULONG_PTR')
    rv = cryptoki.C_GetSlotList(CK_FALSE, _ffi.NULL, count_pt)
    error_check(rv)
    count = count_pt[0]

    if count > 0:
        #slots = _ffi.new('CK_SLOT_ID[{}]'.format(count))
        slots_ptr = _ffi.new('CK_SLOT_ID_PTR')
        rv = cryptoki.C_GetSlotList(CK_FALSE, slots_ptr, count_pt)
        error_check(rv)
        click.echo('ID:{}'.format(slots_ptr[0]))

        slot_info = _ffi.new('CK_SLOT_INFO_PTR')
        rv = cryptoki.C_GetSlotInfo(slots_ptr[0], slot_info)
        error_check(rv)
        click.echo(_ffi.string(slot_info.slotDescription))
        click.echo(_ffi.string(slot_info.manufacturerID))
        click.echo('HW: {}.{}'.format(slot_info.hardwareVersion.major,
                                      slot_info.hardwareVersion.minor))
        click.echo('FW: {}.{}'.format(slot_info.firmwareVersion.major,
                                      slot_info.firmwareVersion.minor))

    click.echo(count)
    rv = cryptoki.C_Finalize(_ffi.NULL)
    error_check(rv)

@cli.command()
def mechanisms():
    count_pt = _ffi.new('CK_ULONG_PTR')
    rv = cryptoki.C_GetSlotList(CK_FALSE, _ffi.NULL, count_pt)
    error_check(rv)
    count = count_pt[0]

    if count > 0:
        slots_ptr = _ffi.new('CK_SLOT_ID_PTR')
        rv = cryptoki.C_GetSlotList(CK_FALSE, slots_ptr, count_pt)
        error_check(rv)
        slot_id = slots_ptr[0]

        session_ptr = _ffi.new('CK_SESSION_HANDLE_PTR')
        rv = cryptoki.C_OpenSession(slot_id,
                                    CKF_RW_SESSION | CKF_SERIAL_SESSION,
                                    _ffi.NULL,
                                    _ffi.NULL,
                                    session_ptr)
        error_check(rv)
        session = session_ptr[0]

        info_ptr = _ffi.new('CK_SESSION_INFO_PTR')

        rv = cryptoki.C_GetSessionInfo(session, info_ptr)
        error_check(rv)
        click.echo(_SESSION_STATES[info_ptr.state])

        #pin = _ffi.new('CK_UTF8CHAR[]', [52, 51, 49, 48, 54, 49])
        pin = b'123456'

        rv = cryptoki.C_Login(session,
                              CKU_USER,
                              pin,
                              len(pin))
        error_check(rv)

        rv = cryptoki.C_GetSessionInfo(session, info_ptr)
        error_check(rv)
        click.echo(_SESSION_STATES[info_ptr.state])

        #rsa_type = _ffi.new('CK_KEY_TYPE *')
        #rsa_type[0] = CKK_RSA
        #template = _ffi.new('CK_ATTRIBUTE[]', 1)
        #template[0].type = CKA_KEY_TYPE
        #template[0].pValue = rsa_type
        #template[0].ulValueLen = _ffi.sizeof(rsa_type)

        #rv = cryptoki.C_FindObjectsInit(session,
        #                                template,
        #                                0)
        #error_check(rv)

        #obj_handle = _ffi.new('CK_OBJECT_HANDLE_PTR')
        #results_ptr = _ffi.new('CK_ULONG_PTR')
        #rv = cryptoki.C_FindObjects(session,
        #                            obj_handle,
        #                            1,
        #                            results_ptr)
        #error_check(rv)
        #results = results_ptr[0]
        #click.echo(results)

        #rv = cryptoki.C_FindObjectsFinal(session)
        #error_check(rv)

        ct_ptr = _ffi.new('CK_ULONG_PTR')
        rv = cryptoki.C_GetMechanismList(slot_id, _ffi.NULL, ct_ptr)
        error_check(rv)
        ct = ct_ptr[0]
        click.echo('Mecha {}'.format(ct))

        mechanisms = _ffi.new('CK_MECHANISM_TYPE[]', ct)
        rv = cryptoki.C_GetMechanismList(slot_id, mechanisms, ct_ptr)
        error_check(rv)

        for x in range(ct):
            click.echo(_MECHANISMS[(mechanisms[x])])

        rv = cryptoki.C_CloseSession(session)
        error_check(rv)
        rv = cryptoki.C_Finalize(_ffi.NULL)
        error_check(rv)


@cli.command()
def version():
    info = _ffi.new('CK_INFO_PTR')
    rv = cryptoki.C_GetInfo(info)
    error_check(rv)
    click.echo(_ffi.string(info.manufacturerID))
    click.echo(_ffi.string(info.libraryDescription))
    click.echo('Library Version {}.{}'.format(
        info.libraryVersion.major, info.libraryVersion.minor
    ))
    click.echo('Cryptoki (PKCS#11) Version {}.{}'.format(
        info.cryptokiVersion.major, info.cryptokiVersion.minor
    ))
    rv = cryptoki.C_Finalize(_ffi.NULL)
    error_check(rv)
