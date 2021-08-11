from flask import Flask, Response, request
import base64 as b64
import struct, hmac
import hashlib

NTLM_NEGOTIATE_UNICODE                      =  0x00000001
NTLM_NEGOTIATE_NTLM                         =  0x00000002
NTLMSSP_REQUEST_TARGET                      =  0x00000004
NTLMSSP_NEGOTIATE_SIGN                      =  0x00000010
NTLMSSP_NEGOTIATE_SEAL                      =  0x00000020
NTLMSSP_NEGOTIATE_DATAGRAM                  =  0x00000040
NTLMSSP_NEGOTIATE_LM_KEY                    =  0x00000080
NTLMSSP_NEGOTIATE_NTLM                      =  0x00000200
NTLMSSP_ANONYMOUS                           =  0x00000800
NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED       =  0x00001000
NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED  =  0x00002000
NTLMSSP_NEGOTIATE_ALWAYS_SIGN               =  0x00008000
NTLMSSP_TARGET_TYPE_DOMAIN                  =  0x00010000
NTLMSSP_TARGET_TYPE_SERVER                  =  0x00020000
NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY  =  0x00080000
NTLMSSP_NEGOTIATE_IDENTIFY                  =  0x00100000
NTLMSSP_REQUEST_NON_NT_SESSION_KEY          =  0x00400000
NTLMSSP_NEGOTIATE_TARGET_INFO               =  0x00800000
NTLMSSP_NEGOTIATE_VERSION                   =  0x02000000
NTLMSSP_NEGOTIATE_128                       =  0x20000000
NTLMSSP_NEGOTIATE_KEY_EXCH                  =  0x40000000
NTLMSSP_NEGOTIATE_56                        =  0x80000000

NTLM_FLAGS = NTLM_NEGOTIATE_UNICODE | \
             NTLMSSP_REQUEST_TARGET | \
             NTLMSSP_NEGOTIATE_NTLM
             NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
             NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY | \
             NTLMSSP_NEGOTIATE_TARGET_INFO | \
             NTLMSSP_NEGOTIATE_VERSION | \
             NTLMSSP_NEGOTIATE_128 | \
             NTLMSSP_NEGOTIATE_KEY_EXCH | \
             NTLMSSP_NEGOTIATE_56


MSV_AV_EOL                  =   struct.pack('<H', 0x0000)
MSV_AV_NB_COMPUTER_NAME     =   struct.pack('<H', 0x0001)
MSV_AV_NB_DOMAIN_NAME       =   struct.pack('<H', 0x0002)
MSV_AV_DNS_COMPUTER_NAME    =   struct.pack('<H', 0x0003)
MSV_AV_DNS_DOMAIN_NAME      =   struct.pack('<H', 0x0004)
MSV_AV_DNS_TREE_NAME        =   struct.pack('<H', 0x0005)
MSV_AV_FLAGS                =   struct.pack('<H', 0x0006)
MSV_AV_TIMESTAMP            =   struct.pack('<H', 0x0007)
MSV_AV_SINGLE_HOST          =   struct.pack('<H', 0x0008)
MSV_AV_TARGET_NAME          =   struct.pack('<H', 0x0009)
MSV_AV_CHANNEL_BINDINGS     =   struct.pack('<H', 0x000A)
hosts = []

app = Flask(__name__)
ServerChallenge = b'\x11\x22\x33\x44\x55\x66\x77\x88'
def Uppercase(string):
    return string.upper()
def MD4(data):
    d = hashlib.new('md4')
    d.update(data)
    return d.digest()

def ConcatenationOf(*args):
    if isinstance(args[0], str):
        out = ''
    else:
        out = b''
    for arg in args:
        out += arg
    return out
def UNICODE(string):
    return string.encode('UTF-16LE')

def NTOWFv2(Passwd, User, UserDom):
    ResponseKeyNT = HMAC_MD5(MD4(UNICODE(Passwd)), UNICODE(ConcatenationOf(Uppercase(User),UserDom)))
    return ResponseKeyNT

def LMOWFv2(Passwd, User, UserDom):
    return NTOWFv2(Passwd, User, Userdom)

def Z(M):
    return b'\0' * M

def HMAC_MD5(key, data):
    return hmac.new(key, data, digestmod=hashlib.md5).digest()

def ComputeResponse(NegotiateFlags, ResponseKeyNT, ServerChallenge, ClientChallenge, Time, ServerName):
    Responserversion = b'\x01'
    HiResponserversion = b'\x01'
    ResponseKeyLM = ResponseKeyNT
    temp = ConcatenationOf(Responserversion, HiResponserversion, Z(6), struct.pack('<Q', Time), ClientChallenge, Z(4), ServerName)
    NTProofStr = HMAC_MD5(ResponseKeyNT, ConcatenationOf(ServerChallenge,temp))
    NtChallengeResponse = ConcatenationOf(NTProofStr, temp)
    LmChallengeResponse = ConcatenationOf(HMAC_MD5(ResponseKeyLM, ConcatenationOf(ServerChallenge, ClientChallenge)),ClientChallenge )
    SessionBaseKey = HMAC_MD5(ResponseKeyNT, NTProofStr)
    return NtChallengeResponse, LmChallengeResponse, SessionBaseKey

@app.route('/')
def index():
    try:
        if "Authorization" in request.headers:
            auth = request.headers['Authorization']
        else:
            auth = None
        if auth:
            if "NTLM" in auth:
                message = auth.split(" ")

                data = b64.b64decode(message[1].encode())
                sig = data[:8]
                message_type    = data[8:12]
                nut = struct.unpack('<I',message_type)
                if struct.unpack('<I',message_type)[0] == 0x3:
                    (
                        Signature,  MessageType,
                        LmChallengeResponseLen      ,   LmChallengeResponseMaxLen       ,   LmChallengeResponseBufferOffset ,
                        NtChallengeResponseLen      ,   NtChallengeResponseMaxLen       ,   NtChallengeResponseBufferOffset ,
                        DomainNameLen               ,   DomainNameMaxLen                ,   DomainNameBufferOffset          ,
                        UserNameLen                 ,   UserNameMaxLen                  ,   UserNameBufferOffset            ,
                        WorkstationLen              ,   WorkstationMaxLen               ,   WorkstationBufferOffset         ,
                        EncryptedRandomSessionKeyLen,   EncryptedRandomSessionKeyMaxLen ,   EncryptedRandomSessionKeyBufferOffset,
                        NegotiateFlags
                    ) = struct.unpack('<8sIHHIHHIHHIHHIHHIHHII', data[:64])
                    FORMAT_SIZE = struct.calcsize('<8sIHHIHHIHHIHHIHHIHHII')
                    if NtChallengeResponseLen > 0x0018:

                        AV_PAIRS = {}
                        NTLM_CLIENT_CHALLENGE_HEADER = data[NtChallengeResponseBufferOffset:NtChallengeResponseBufferOffset+44]
                        nut = struct.calcsize('<BBHIQQI')
                        (
                            NtChallengeResponse,
                            RespType,
                            HiRespType,
                            Reserved1,
                            Reserved2, 
                            TimeStamp,
                            ClientChallenge,
                            Reserved3
                        )  =   struct.unpack('<16sBBHIQQI', NTLM_CLIENT_CHALLENGE_HEADER)
                        
                        avdata      =   data[NtChallengeResponseBufferOffset+16+28:NtChallengeResponseBufferOffset+28+NtChallengeResponseLen]
                        offset = 0
                        AvId        =   avdata[0:2]
                        AvLen       =   struct.unpack('<H', avdata[2:4])[0]
                        offset = 4
                        while AvId != MSV_AV_EOL:
                            AvStr = avdata[offset:offset+AvLen]
                            AV_PAIRS[AvId] = AvStr
                            offset = offset+AvLen
                            AvId    =   avdata[offset+0 :   offset+2]
                            AvLen   =   avdata[offset+2 :   offset+4][0]
                            offset += 4
                        DomainName                  =   struct.unpack(f'<{DomainNameLen}s',             data[DomainNameBufferOffset                 :   DomainNameBufferOffset                  +   DomainNameLen])[0]
                        UserName                    =   struct.unpack(f'<{UserNameLen}s',               data[UserNameBufferOffset                   :   UserNameBufferOffset                    +   UserNameLen])[0]
                        Workstation                 =   struct.unpack(f'<{WorkstationLen}s',            data[WorkstationBufferOffset                :   WorkstationBufferOffset                 +   WorkstationLen])[0]
                        EncryptedRandomSessionKey   =   struct.unpack(f'<{EncryptedRandomSessionKeyLen}s',  data[EncryptedRandomSessionKeyBufferOffset  :   EncryptedRandomSessionKeyBufferOffset   +   EncryptedRandomSessionKeyLen])[0]
                        ServerName                  =   AV_PAIRS.get(MSV_AV_NB_COMPUTER_NAME, None)
                        Passwd = 'Password'
                        ServerName = data[NtChallengeResponseBufferOffset+16+28:NtChallengeResponseBufferOffset+28+NtChallengeResponseLen]
                        ClientChallengeU = struct.pack('<Q', ClientChallenge)
                        ResponseKeyNT = NTOWFv2(Passwd, UserName.decode('UTF-16LE'), DomainName.decode('UTF-16LE'))
                        authed = ComputeResponse(NegotiateFlags,ResponseKeyNT, ServerChallenge, ClientChallengeU, TimeStamp, ServerName)[0] == data[NtChallengeResponseBufferOffset:NtChallengeResponseBufferOffset+NtChallengeResponseLen]
                        if ComputeResponse(NegotiateFlags,ResponseKeyNT, ServerChallenge, ClientChallengeU, TimeStamp, ServerName)[0] == data[NtChallengeResponseBufferOffset:NtChallengeResponseBufferOffset+NtChallengeResponseLen]:
                            return f"Successfully authenticated as {UserName.decode('utf-16le')}", 200
                        else:
                            return "Please try again", 401
                    elif NegotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                        ClientChallenge = None
                    else:
                        ClientChallenge = None

                    return f"Successfully authenticated as {UserName.decode('utf-16le')}", 200
                nego_field      = data[12:16] 
                
                domain_data     = data[16:24]
                domain_fields = struct.unpack('HHI', domain_data)
                wks_data = data[24:32]
                wks_fields = struct.unpack('HHI', wks_data)
                vers = data[32:40]
                payload = data[40:]
                if sig != b'NTLMSSP\x00':
                    return "fcukoff", 401
                
                DOMAIN_FQDN     =   'domain.local'
                COMPUTER_NAME   =   'Server'
                COMPUTER_FQDN   =   'Server.Domain.local'
                TARGET_NAME     =   'Server'
                
                CHALLENGE_NEGOTIATE_FLAGS = b'\x05\x02\x89\xa2'



                ENCODED_TARGET_NAME             =   TARGET_NAME.encode('utf-16-le')
                ENCODED_TARGET_NAME_LENGTH      =   struct.pack('<H',len(ENCODED_TARGET_NAME))
                
                ENCODED_COMPUTER_NAME           =   COMPUTER_NAME.encode('utf-16-le')
                ENCODED_COMPUTER_NAME_LENGTH    =   struct.pack('<H',len(ENCODED_COMPUTER_NAME))

                ENCODED_DOMAIN_FQDN             =   DOMAIN_FQDN.encode('utf-16-le')
                ENCODED_DOMAIN_FQDN_LENGTH      =   struct.pack('<H',len(ENCODED_DOMAIN_FQDN))

                ENCODED_COMPUTER_FQDN           =   COMPUTER_FQDN.encode('utf-16-le')
                ENCODED_COMPUTER_FQDN_LENGTH     =   struct.pack('<H',len(ENCODED_COMPUTER_FQDN))

                AV_PAIRS = [
                    MSV_AV_NB_DOMAIN_NAME       + ENCODED_TARGET_NAME_LENGTH        + ENCODED_TARGET_NAME   ,
                    MSV_AV_NB_COMPUTER_NAME     + ENCODED_COMPUTER_NAME_LENGTH      + ENCODED_COMPUTER_NAME ,
                    MSV_AV_DNS_DOMAIN_NAME      + ENCODED_DOMAIN_FQDN_LENGTH        + ENCODED_DOMAIN_FQDN   ,
                    MSV_AV_DNS_COMPUTER_NAME    + ENCODED_COMPUTER_FQDN_LENGTH      + ENCODED_COMPUTER_FQDN ,
                    MSV_AV_DNS_TREE_NAME        + ENCODED_DOMAIN_FQDN_LENGTH        + ENCODED_DOMAIN_FQDN   ,
                    MSV_AV_EOL                  + MSV_AV_EOL
                ]
                TARGET_INFO = b''.join(AV_PAIRS)
                TARGET_INFO_LENGTH = struct.pack('<H',len(TARGET_INFO))
                PAYLOAD = b''
                CHALLENGE_STATIC_OFFSET = 0x38
                MESSAGE_TYPE = 0x00000002
                CHALLENGE_MESSAGE = b''
                CHALLENGE_MESSAGE += b'NTLMSSP\x00'                                 # Signature                 8B
                CHALLENGE_MESSAGE += struct.pack('<I', MESSAGE_TYPE)                # MessageType               4B

                TARGET_NAME_BUFFER_OFFSET = CHALLENGE_STATIC_OFFSET + len(PAYLOAD)
                PAYLOAD += ENCODED_TARGET_NAME
                                                                                    # TargetNameFields:         8B
                CHALLENGE_MESSAGE += ENCODED_TARGET_NAME_LENGTH                     #       TargetNameLen      
                CHALLENGE_MESSAGE += ENCODED_TARGET_NAME_LENGTH                     #       TargetNameMaxLen
                CHALLENGE_MESSAGE += struct.pack('<I', TARGET_NAME_BUFFER_OFFSET)   #       TargetNameBufferOffset

                CHALLENGE_MESSAGE += CHALLENGE_NEGOTIATE_FLAGS                      # NegotiateFlags            4B

                CHALLENGE_MESSAGE += b'\x11\x22\x33\x44\x55\x66\x77\x88'            # ServerChallenge           8B
                CHALLENGE_MESSAGE += b'\x00\x00\x00\x00\x00\x00\x00\x00'            # Reserved                  8B
                                                                                    # TargetInfoFields:         8B
                TARGET_INFO_BUFFER_OFFSET = CHALLENGE_STATIC_OFFSET + len(PAYLOAD)
                PAYLOAD += TARGET_INFO
                CHALLENGE_MESSAGE += TARGET_INFO_LENGTH                             #       TargetInfoLen      
                CHALLENGE_MESSAGE += TARGET_INFO_LENGTH                             #       TargetInfoMaxLen
                CHALLENGE_MESSAGE += struct.pack('<I', TARGET_INFO_BUFFER_OFFSET)   #       TargetInfoBufferOffset
                CHALLENGE_MESSAGE += b'\x05\x02\xce\x0e\x00\x00\x00\x0f'            # Version                   8B
                
                CHALLENGE_MESSAGE += PAYLOAD
                resp = Response("uwu")
                resp.headers["www-authenticate"] = 'NTLM ' + b64.b64encode(CHALLENGE_MESSAGE).decode('latin1')

                return resp, 401
                
        else:
            resp = Response("uwu")
            resp.headers["www-authenticate"] = 'NTLM'
            return resp, 401
    except Exception as e:
        return f"{e}", 400
    
app.run('0.0.0.0', 8072)
