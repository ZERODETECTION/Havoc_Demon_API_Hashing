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


# Example Usage
test_string = "LdrLoadDll"
hash_key = 5381
print(f"Hash of '{test_string}': 0x{hash_ex(test_string, upper=True, hash_key=hash_key):08X}")
