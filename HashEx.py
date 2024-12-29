

"""

Hashing Function:
https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/Win32.c
https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/include/core/Win32.h

Defines:
https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/payloads/Demon/include/common/Defines.h#L44


Get all /* Win32 Functions */ 
cat api_temp.txt | cut -d "_" -f3 | awk '{printf "\"%s\",\n", $1}'



Evading this yara rule:
rule Windows_Trojan_Generic_9997489c {
    meta:
        author = "Elastic Security"
        id = "9997489c-4e22-4df1-90cb-dd098ca26505"
        fingerprint = "4c872be4e5eaf46c92e6f7d62ed0801992c36fee04ada1a1a3039890e2893d8c"
        creation_date = "2024-01-31"
        last_modified = "2024-02-08"
        threat_name = "Windows.Trojan.Generic"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $ldrload_dll = { 43 6A 45 9E }
        $loadlibraryw = { F1 2F 07 B7 }
        $ntallocatevirtualmemory = { EC B8 83 F7 }
        $ntcreatethreadex = { B0 CF 18 AF }
        $ntqueryinformationprocess = { C2 5D DC 8C }
        $ntprotectvirtualmemory = { 88 28 E9 50 }
        $ntreadvirtualmemory = { 03 81 28 A3 }
        $ntwritevirtualmemory = { 92 01 17 C3 }
        $rtladdvectoredexceptionhandler = { 89 6C F0 2D }
        $rtlallocateheap = { 5A 4C E9 3B }
        $rtlqueueworkitem = { 8E 02 92 AE }
        $virtualprotect = { 0D 50 57 E8 }
    condition:
        4 of them
}



"""


def hash_ex(input_string, length=0, upper=False, hash_key=5381):
    """
    Reimplementation of the HashEx function in Python.

    Args:
        input_string (str): The string to hash.
        length (int): Length of the string to hash. If 0, treat as null-terminated.
        upper (bool): Whether to convert characters to uppercase.
        hash_key (int): Initial hash value (default 5381).

    Returns:
        int: The computed hash value in Little Endian format.
    """
    if not input_string:
        return 0

    hash_value = hash_key
    for i, char in enumerate(input_string):
        if length and i >= length:
            break

        # Convert to uppercase if needed
        character = ord(char)
        if upper and 'a' <= char <= 'z':
            character -= 0x20

        # Update hash
        hash_value = ((hash_value << 5) + hash_value) + character  # Hash * 33 + character

    # Convert to Little Endian format
    hash_value = hash_value & 0xFFFFFFFF  # Ensure 32-bit overflow
    return int.from_bytes(hash_value.to_bytes(4, 'big'), 'little')


# Funktionen in ein Array packen
functions = [
    "LDRLOADDLL",
    "LDRGETPROCEDUREADDRESS",
    "NTADDBOOTENTRY",
    "NTALLOCATEVIRTUALMEMORY",
    "NTFREEVIRTUALMEMORY",
    "NTUNMAPVIEWOFSECTION",
    "NTWRITEVIRTUALMEMORY",
    "NTSETINFORMATIONVIRTUALMEMORY",
    "NTQUERYVIRTUALMEMORY",
    "NTOPENPROCESSTOKEN",
    "NTOPENTHREADTOKEN",
    "NTQUERYOBJECT",
    "NTTRACEEVENT",
    "NTOPENPROCESS",
    "NTTERMINATEPROCESS",
    "NTOPENTHREAD",
    "NTOPENTHREADTOKEN",
    "NTSETCONTEXTTHREAD",
    "NTGETCONTEXTTHREAD",
    "NTCLOSE",
    "NTCONTINUE",
    "NTSETEVENT",
    "NTCREATEEVENT",
    "NTWAITFORSINGLEOBJECT",
    "NTSIGNALANDWAITFORSINGLEOBJECT",
    "NTGETNEXTTHREAD",
    "NTRESUMETHREAD",
    "NTSUSPENDTHREAD",
    "NTDUPLICATEOBJECT",
    "NTQUERYINFORMATIONTHREAD",
    "NTCREATETHREADEX",
    "NTQUEUEAPCTHREAD",
    "NTQUERYSYSTEMINFORMATION",
    "NTQUERYINFORMATIONTOKEN",
    "NTQUERYINFORMATIONPROCESS",
    "NTSETINFORMATIONTHREAD",
    "NTSETINFORMATIONVIRTUALMEMORY",
    "NTPROTECTVIRTUALMEMORY",
    "NTREADVIRTUALMEMORY",
    "NTFREEVIRTUALMEMORY",
    "NTTERMINATETHREAD",
    "NTWRITEVIRTUALMEMORY",
    "NTDUPLICATETOKEN",
    "NTALERTRESUMETHREAD",
    "NTTESTALERT",
    "RTLALLOCATEHEAP",
    "RTLREALLOCATEHEAP",
    "RTLFREEHEAP",
    "RTLEXITUSERPROCESS",
    "RTLRANDOMEX",
    "RTLRANDOMEX",
    "RTLNTSTATUSTODOSERROR",
    "RTLGETVERSION",
    "RTLADDVECTOREDEXCEPTIONHANDLER",
    "RTLREMOVEVECTOREDEXCEPTIONHANDLER",
    "RTLCREATETIMERQUEUE",
    "RTLDELETETIMERQUEUE",
    "RTLCREATETIMER",
    "RTLQUEUEWORKITEM",
    "RTLREGISTERWAIT",
    "RTLCAPTURECONTEXT",
    "RTLCOPYMAPPEDMEMORY",
    "RTLFILLMEMORY",
    "RTLEXITUSERTHREAD",
    "RTLSUBAUTHORITYSID",
    "RTLSUBAUTHORITYCOUNTSID",
    "LOADLIBRARYW",
    "GETCOMPUTERNAMEEXA",
    "WAITFORSINGLEOBJECTEX",
    "VIRTUALPROTECT",
    "GETMODULEHANDLEA",
    "GETPROCADDRESS",
    "GETCURRENTDIRECTORYW",
    "FINDFIRSTFILEW",
    "FINDNEXTFILEW",
    "FINDCLOSE",
    "FILETIMETOSYSTEMTIME",
    "SYSTEMTIMETOTZSPECIFICLOCALTIME",
    "OUTPUTDEBUGSTRINGA",
    "DEBUGBREAK",
    "SYSTEMFUNCTION032",
    "LOOKUPACCOUNTSIDW",
    "LOGONUSEREXW",
    "VSNPRINTF",
    "GETADAPTERSINFO",
    "WINHTTPOPEN",
    "WINHTTPCONNECT",
    "WINHTTPOPENREQUEST",
    "WINHTTPSETOPTION",
    "WINHTTPSENDREQUEST",
    "WINHTTPRECEIVERESPONSE",
    "WINHTTPADDREQUESTHEADERS",
    "WINHTTPREADDATA",
    "WINHTTPQUERYHEADERS",
    "WINHTTPCLOSEHANDLE",
    "WINHTTPGETIEPROXYCONFIGFORCURRENTUSER",
    "WINHTTPGETPROXYFORURL",
    "VIRTUALPROTECTEX",
    "LOCALALLOC",
    "LOCALREALLOC",
    "LOCALFREE",
    "CREATEREMOTETHREAD",
    "CREATETOOLHELP32SNAPSHOT",
    "PROCESS32FIRSTW",
    "PROCESS32NEXTW",
    "CREATEPIPE",
    "CREATEPROCESSW",
    "CREATEFILEW",
    "GETFULLPATHNAMEW",
    "GETFILESIZE",
    "GETFILESIZEEX",
    "CREATENAMEDPIPEW",
    "CONVERTFIBERTOTHREAD",
    "CREATEFIBEREX",
    "READFILE",
    "VIRTUALALLOCEX",
    "WAITFORSINGLEOBJECTEX",
    "GETCOMPUTERNAMEEXA",
    "EXITPROCESS",
    "GETEXITCODEPROCESS",
    "GETEXITCODETHREAD",
    "CONVERTTHREADTOFIBEREX",
    "SWITCHTOFIBER",
    "DELETEFIBER",
    "ALLOCCONSOLE",
    "FREECONSOLE",
    "GETCONSOLEWINDOW",
    "GETSTDHANDLE",
    "SETSTDHANDLE",
    "WAITNAMEDPIPEW",
    "PEEKNAMEDPIPE",
    "DISCONNECTNAMEDPIPE",
    "WRITEFILE",
    "CONNECTNAMEDPIPE",
    "FREELIBRARY",
    "GETCURRENTDIRECTORYW",
    "GETFILEATTRIBUTESW",
    "FINDFIRSTFILEW",
    "FINDNEXTFILEW",
    "FINDCLOSE",
    "FILETIMETOSYSTEMTIME",
    "SYSTEMTIMETOTZSPECIFICLOCALTIME",
    "REMOVEDIRECTORYW",
    "DELETEFILEW",
    "CREATEDIRECTORYW",
    "COPYFILEW",
    "MOVEFILEEXW",
    "SETCURRENTDIRECTORYW",
    "WOW64DISABLEWOW64FSREDIRECTION",
    "WOW64REVERTWOW64FSREDIRECTION",
    "GETMODULEHANDLEA",
    "GETSYSTEMTIMEASFILETIME",
    "GETLOCALTIME",
    "DUPLICATEHANDLE",
    "ATTACHCONSOLE",
    "WRITECONSOLEA",
    "TERMINATEPROCESS",
    "VIRTUALPROTECT",
    "GETTOKENINFORMATION",
    "CREATEPROCESSWITHTOKENW",
    "CREATEPROCESSWITHLOGONW",
    "REVERTTOSELF",
    "GETUSERNAMEA",
    "LOGONUSERW",
    "LOOKUPACCOUNTSIDA",
    "LOOKUPACCOUNTSIDW",
    "OPENTHREADTOKEN",
    "OPENPROCESSTOKEN",
    "ADJUSTTOKENPRIVILEGES",
    "LOOKUPPRIVILEGENAMEA",
    "SYSTEMFUNCTION032",
    "FREESID",
    "SETSECURITYDESCRIPTORSACL",
    "SETSECURITYDESCRIPTORDACL",
    "INITIALIZESECURITYDESCRIPTOR",
    "ADDMANDATORYACE",
    "INITIALIZEACL",
    "ALLOCATEANDINITIALIZESID",
    "CHECKTOKENMEMBERSHIP",
    "SETENTRIESINACLW",
    "SETTHREADTOKEN",
    "LSANTSTATUSTOWINERROR",
    "EQUALSID",
    "CONVERTSIDTOSTRINGSIDW",
    "GETSIDSUBAUTHORITYCOUNT",
    "GETSIDSUBAUTHORITY",
    "LOOKUPPRIVILEGEVALUEA",
    "SAFEARRAYACCESSDATA",
    "SAFEARRAYUNACCESSDATA",
    "SAFEARRAYCREATE",
    "SAFEARRAYPUTELEMENT",
    "SAFEARRAYCREATEVECTOR",
    "SAFEARRAYDESTROY",
    "SYSALLOCSTRING",
    "COMMANDLINETOARGVW",
    "SHOWWINDOW",
    "GETSYSTEMMETRICS",
    "GETDC",
    "RELEASEDC",
    "GETCURRENTOBJECT",
    "GETOBJECTW",
    "CREATECOMPATIBLEDC",
    "CREATEDIBSECTION",
    "SELECTOBJECT",
    "BITBLT",
    "DELETEOBJECT",
    "DELETEDC",
    "SETPROCESSVALIDCALLTARGETS",
    "CLRCREATEINSTANCE",
    "GETADAPTERSINFO",
    "NETLOCALGROUPENUM",
    "NETGROUPENUM",
    "NETUSERENUM",
    "NETWKSTAUSERENUM",
    "NETSESSIONENUM",
    "NETSHAREENUM",
    "NETAPIBUFFERFREE",
    "WSASTARTUP",
    "WSACLEANUP",
    "WSASOCKETA",
    "WSAGETLASTERROR",
    "IOCTLSOCKET",
    "BIND",
    "LISTEN",
    "ACCEPT",
    "CLOSESOCKET",
    "RECV",
    "SEND",
    "CONNECT",
    "GETADDRINFO",
    "FREEADDRINFO",
    "LSAREGISTERLOGONPROCESS",
    "LSALOOKUPAUTHENTICATIONPACKAGE",
    "LSADEREGISTERLOGONPROCESS",
    "LSACONNECTUNTRUSTED",
    "LSAFREERETURNBUFFER",
    "LSACALLAUTHENTICATIONPACKAGE",
    "LSAGETLOGONSESSIONDATA",
    "LSAENUMERATELOGONSESSIONS",
    "SLEEP",
    "CREATETHREAD",
    "AMSISCANBUFFER",
    "GLOBALFREE",
    "SWPRINTF_S"
]

# Beispiel: Loop über das Array und Ausgabe der Funktionsnamen

#  define H_FUNC_LDRLOADDLL                            0x9e456a43


def reverse_hash(original_hash):
    # Umwandlung des Hashes in Bytes und Umkehrung der Byte-Reihenfolge
    return original_hash.to_bytes(4, 'little').hex().upper()
    


def all_functions():

    for func in functions:
        test_string = func
        hash_key = 5381
        # Berechnung des Hash-Werts
        hash_value = hash_ex(test_string, upper=True, hash_key=hash_key)
        
        # Ausgabe des Original-Hashes in Kleinbuchstaben
        # print(f"Hash of '{test_string}': 0x{hash_value:08X}".lower())
        
        # Umkehren des Hashes und Umwandlung in Kleinbuchstaben
        reversed_hash = reverse_hash(hash_value)
        
        # Ausgabe des #define Makros im gewünschten Format in Kleinbuchstaben
        print(f"#define H_FUNC_{test_string.upper():<30} 0x{reversed_hash.lower()}")




# Example Usage
"""
test_string = "WINHTTPSETOPTION"
hash_key = 5381
# Berechnung des Hash-Werts
hash_value = hash_ex(test_string, upper=True, hash_key=hash_key)

# Ausgabe des Original-Hashes in Kleinbuchstaben
# print(f"Hash of '{test_string}': 0x{hash_value:08X}".lower())

# Umkehren des Hashes und Umwandlung in Kleinbuchstaben
reversed_hash = reverse_hash(hash_value)

# Ausgabe des #define Makros im gewünschten Format in Kleinbuchstaben
print(f"#define H_FUNC_{test_string.upper():<30} 0x{reversed_hash.lower()}")
"""

all_functions()





