from Crypto.Cipher import AES

key_hex = "36f18357be4dbd77f050515c73fcf9f2"
ct_hex = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c3445"

key = bytes.fromhex(key_hex)
ct = bytes.fromhex(ct_hex)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

print("Total:", len(ct))
print("IV:", len(ct[:16]))
print("Ciphertext:", len(ct[16:]))
print("Remainder:", len(ct[16:]) % 16)


def decrypt_cbc(key, ct):
    iv = ct[:16]
    ciphertext = ct[16:]

    cipher = AES.new(key, AES.MODE_ECB)

    plaintext = b""
    previous = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]

        decrypted_block = cipher.decrypt(block)
        plaintext_block = xor_bytes(decrypted_block, previous)

        plaintext += plaintext_block
        previous = block

    return plaintext

def remove_pkcs_padding(data):
    pad_len = data[-1]

    if pad_len < 1 or pad_len > 16:
        raise ValueError("Padding non valido")

    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding non valido")

    return data[:-pad_len]

plaintext = decrypt_cbc(key, ct)
plaintext = remove_pkcs_padding(plaintext)

print(plaintext.decode("utf-8"))