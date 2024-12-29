

"""

Hashing Function:
https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/src/core/Win32.c
https://github.com/HavocFramework/Havoc/blob/main/payloads/Demon/include/core/Win32.h

Defines:
https://github.com/HavocFramework/Havoc/blob/41a5d45c2b843d19be581a94350c532c1cd7fd49/payloads/Demon/include/common/Defines.h#L44

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
    "LdrGetProcedureAddress",
    "LdrLoadDll",
    "RtlAllocateHeap",
    "RtlReAllocateHeap",
    "RtlFreeHeap",
    "RtlExitUserThread",
    "RtlExitUserProcess",
    "RtlRandomEx",
    "RtlNtStatusToDosError",
    "RtlGetVersion",
    "RtlCreateTimerQueue",
    "RtlCreateTimer",
    "RtlQueueWorkItem",
    "RtlRegisterWait",
    "RtlDeleteTimerQueue",
    "RtlCaptureContext",
    "RtlAddVectoredExceptionHandler",
    "RtlRemoveVectoredExceptionHandler",
    "RtlCopyMappedMemory",
    "NtClose",
    "NtCreateEvent",
    "NtSetEvent",
    "NtSetInformationThread",
    "NtSetInformationVirtualMemory",
    "NtGetNextThread",
    "NtOpenProcess",
    "NtTerminateProcess",
    "NtQueryInformationProcess",
    "NtQuerySystemInformation",
    "NtAllocateVirtualMemory",
    "NtQueueApcThread",
    "NtOpenThread",
    "NtOpenThreadToken",
    "NtResumeThread",
    "NtSuspendThread",
    "NtCreateEvent",
    "NtDuplicateObject",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtWaitForSingleObject",
    "NtAlertResumeThread",
    "NtSignalAndWaitForSingleObject",
    "NtTestAlert",
    "NtCreateThreadEx",
    "NtOpenProcessToken",
    "NtDuplicateToken",
    "NtProtectVirtualMemory",
    "NtTerminateThread",
    "NtWriteVirtualMemory",
    "NtContinue",
    "NtReadVirtualMemory",
    "NtFreeVirtualMemory",
    "NtUnmapViewOfSection",
    "NtQueryVirtualMemory",
    "NtQueryInformationToken",
    "NtQueryInformationThread",
    "NtQueryObject",
    "NtTraceEvent"
]

# Example Usage
"""
test_string = "LdrLoadDll"
hash_key = 5381
print(f"Hash of '{test_string}': 0x{hash_ex(test_string, upper=True, hash_key=hash_key):08X}")
"""


# Beispiel: Loop über das Array und Ausgabe der Funktionsnamen

#  define H_FUNC_LDRLOADDLL                            0x9e456a43


def reverse_hash(original_hash):
    # Umwandlung des Hashes in Bytes und Umkehrung der Byte-Reihenfolge
    return original_hash.to_bytes(4, 'little').hex().upper()
    

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
