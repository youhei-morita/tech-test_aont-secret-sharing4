from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

# 共有鍵と平文の定義
k = b'ThisIsASecretKey'
plaintext = "私は現在、転職活動中です"

# 入力１：文字列
print("入力1_AONT 平文:", plaintext)

def pad(data):
    padding_length = AES.block_size - len(data) % AES.block_size
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    if padding_length < 1 or padding_length > AES.block_size:
        raise ValueError("Invalid padding length")
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid padding bytes")
    return data[:-padding_length]

def encrypt(key, plaintext):
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode()))
    return iv + ciphertext

def decrypt(key, ciphertext):
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:])).decode()
    return plaintext

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aont_encrypt_xor(key, plaintext):
    # 分割するブロック数を設定
    num_blocks = 4
    # ハッシュ関数を使って共有鍵からブロック鍵を生成
    block_keys = [hashlib.sha256(key + bytes([i])).digest() for i in range(1, num_blocks+1)]
    # 平文をブロックに分割
    block_size = len(plaintext) // num_blocks
    plaintext_blocks = [plaintext[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
    # ブロックごとに暗号化
    ciphertext_blocks = [encrypt(block_keys[i], block) for i, block in enumerate(plaintext_blocks)]
    # ブロックごとの暗号文を表示
    for i, block in enumerate(ciphertext_blocks):
        print("(参考)ブロックごとの暗号化:"f"ブロック {i+1} ciphertext: {block}")
    # ブロック鍵を削除
    del block_keys
    # 復号化に必要な情報を付加
    return b''.join(ciphertext_blocks), num_blocks

# AONT暗号化（XORを使用）
ciphertext_xor, num_blocks_xor = aont_encrypt_xor(k, plaintext)
print("出力1及び入力2_AONT 暗号文:", ciphertext_xor)

def aont_decrypt_xor(key, ciphertext, num_blocks):
    # ハッシュ関数を使って共有鍵からブロック鍵を生成
    block_keys = [hashlib.sha256(key + bytes([i])).digest() for i in range(1, num_blocks+1)]
    # 暗号文をブロックごとに分割
    block_size = len(ciphertext) // num_blocks
    ciphertext_blocks = [ciphertext[i*block_size:(i+1)*block_size] for i in range(num_blocks)]
    # ブロックごとに復号化
    plaintext_blocks = [decrypt(block_keys[i], block) for i, block in enumerate(ciphertext_blocks)]
    # ブロックごとの復号化を表示
    for i, block in enumerate(plaintext_blocks):
        print("(参考)ブロックごとの復号化:"f"ブロック {i+1} ciphertext: {block}")
    # ブロックを結合して平文を取得
    return ''.join(plaintext_blocks)

# AONT復号化（XORを使用）
decrypted_text_xor = aont_decrypt_xor(k, ciphertext_xor, num_blocks_xor)
print("出力2_AONT 復号化:", decrypted_text_xor)
