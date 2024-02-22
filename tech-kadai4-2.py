import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# データmの準備
data = "私は転職活動中です"

# 共通鍵暗号の鍵k
key_k = os.urandom(32)  # 256ビットのランダムな鍵を生成
print("共通鍵暗号の鍵k:", key_k)

# 公開された共通鍵暗号の鍵k_0の生成
key_k_0 = os.urandom(32)  # 32バイト（256ビット）のランダムな鍵を生成する例
print("公開された共通鍵暗号の鍵k_0:", key_k_0)

def split_data_into_blocks(data, num_blocks):
    block_size = len(data) // num_blocks
    # 分割されたブロックを格納するリスト
    blocks = []
    # データをブロックサイズごとに分割
    for i in range(num_blocks):
        if i == num_blocks - 1:
            # 最後のブロックはデータの残りすべてを含む
            blocks.append(data[i * block_size:])
        else:
            blocks.append(data[i * block_size: (i + 1) * block_size])
    return blocks

# ブロック数s
num_blocks = 3

# データをブロックに分割
blocks = split_data_into_blocks(data, num_blocks)
print("分割されたブロック:")
for i, block in enumerate(blocks):
    print(f"Block {i + 1}: {block}")

def generate_share(block, key, index):
    # インデックスをバイト列に変換
    index_bytes = index.to_bytes(4, byteorder='big')
    
    # ブロックをバイト列に変換
    block_bytes = block.encode() if isinstance(block, str) else block
    
    # パディング
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(block_bytes + index_bytes) + padder.finalize()
    
    # 共通鍵暗号を使用して暗号化
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    # シェアを生成
    share = bytes(a ^ b for a, b in zip(padded_data, encrypted_data))
    
    return share

# 分割されたブロック
blocks = [b"block1", b"block2", b"block3"]
# 分割されたブロックの数
num_blocks = len(blocks)

# シェアに変換
shares = []
for i, block in enumerate(blocks, start=1):
    share = generate_share(block, key_k, i)
    shares.append(share)

print("シェア:")
for i, share in enumerate(shares):
    print(f"Share {i + 1}: {share}")

ef generate_hash(share, key_k_0, index):
    # シェアとインデックスを結合
    combined_data = bytes(a ^ b for a, b in zip(share, index.to_bytes(4, byteorder='big')))
    
    # パディング
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(combined_data) + padder.finalize()
    
    # 共通鍵暗号を使用して暗号化
    cipher = Cipher(algorithms.AES(key_k_0), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data

# 公開された共通鍵暗号の鍵k_0
key_k_0 = os.urandom(32)  # 256ビットのランダムな鍵を生成

# シェア
shares = [b"share1", b"share2", b"share3"]
# シェアの数
num_shares = len(shares)

# ハッシュ値を生成
hashes = []
for i, share in enumerate(shares, start=1):
    hash_value = generate_hash(share, key_k_0, i)
    hashes.append(hash_value)

print("ハッシュ値:")
for i, hash_value in enumerate(hashes):
    print(f"Hash {i + 1}: {hash_value}")

def generate_final_share(key_k, hashes):
    # 初期化
    final_share = key_k
    
    # 共通鍵暗号の鍵とハッシュ値を順番に排他的論理和を取る
    for hash_value in hashes:
        final_share = bytes(a ^ b for a, b in zip(final_share, hash_value))
    
    return final_share

# ハッシュ値のリスト（仮のダミーデータ）
hashes = [os.urandom(16) for _ in range(3)]  # 16バイトのランダムなダミーデータ

# s+1番目のブロックをシェアに変換
final_share = generate_final_share(key_k, hashes)

print("s+1番目のシェア:", final_share)

# 共通鍵kを破棄
key_k = None
print("共通鍵kを破棄しました。")

ef recover_key(final_share, hashes):
    # 初期化
    key_k = final_share
    
    # ハッシュ値を順番に排他的論理和を取る
    for hash_value in hashes:
        key_k = bytes(a ^ b for a, b in zip(key_k, hash_value))
    
    return key_k

# s+1番目のブロック（シェア）とハッシュ値のリスト（仮のダミーデータ）
final_share = b"final_share"  # 仮のダミーデータ
hashes = [os.urandom(16) for _ in range(3)]  # 16バイトのランダムなダミーデータ

# key_kを復元
recovered_key_k = recover_key(final_share, hashes)

print("復元されたkey_k:", recovered_key_k)

def decrypt_share(share, key_k, index):
    # シェアとインデックスを結合
    combined_data = bytes(a ^ b for a, b in zip(share, index.to_bytes(4, byteorder='big')))
    
    # 共通鍵暗号を使用して復号化
    cipher = Cipher(algorithms.AES(key_k), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(combined_data)
    
    # パディングを削除
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data)
    
    # パディングの検証
    try:
        unpadder.finalize()
    except ValueError:
        raise ValueError("Invalid padding bytes.")
    
    return unpadded_data

# 復元された共通鍵暗号の鍵key_k
recovered_key_k = os.urandom(32)  # 仮のダミーデータ

# シェアのリスト（仮のダミーデータ）
shares = [os.urandom(16) for _ in range(3)]  # 16バイトのランダムなダミーデータ

# データを復号
decrypted_data = []
for i, share in enumerate(shares, start=1):
    try:
        decrypted_block = decrypt_share(share, recovered_key_k, i)
        decrypted_data.append(decrypted_block)
    except ValueError as e:
        print(f"Error decrypting block {i}: {e}")
        # パディングの検証に失敗した場合、エラーを処理するか、デフォルト値を返すことができます。

# 復号された文章を1つにまとめる
full_decrypted_text = b''.join(filter(None, decrypted_data)).decode()

# 出力
print("復号された文章:")
print(full_decrypted_text)
