# security_mods.py – AES-256-GCM + RSA-2048 destekli güvenlik yardımcıları
# -------------------------------------------------------------------------
# Bu modül, dosya aktarımında veri şifreleme (confidentiality),
# bütünlük doğrulama (integrity) ve RSA anahtar yönetimini sağlar.

from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass
import json, secrets, hashlib

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# RSA-2048 anahtarları üret ve kaydet
def generate_keys():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    Path("keys").mkdir(exist_ok=True)

    # Özel anahtar (private.pem) oluştur
    with open("keys/private.pem", "wb") as f:
        f.write(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Açık anahtar (public.pem) oluştur
    with open("keys/public.pem", "wb") as f:
        f.write(pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Anahtarlar oluşturuldu: keys/private.pem, keys/public.pem")


# Anahtar dosyalarının yolu
KEY_DIR = Path("keys")
KEY_DIR.mkdir(exist_ok=True)
PRIV_PEM = KEY_DIR / "private.pem"
PUB_PEM  = KEY_DIR / "public.pem"


# Anahtar yoksa otomatik oluştur
def _ensure_keys():
    if PRIV_PEM.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    PRIV_PEM.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    PUB_PEM.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    print("[+] RSA anahtar çifti üretildi (keys/)")


# Başlık yapısı (dosya adı, boyut, hash ve AES anahtarı)
@dataclass
class Header:
    name: str
    size: int
    sha: str
    aes_key: bytes


class CryptoBox:
    """Dosya başlıklarını ve içerik parçalarını şifreleyip çözmek için sınıf"""

    def __init__(self):
        _ensure_keys()
        # RSA özel ve açık anahtarları yükle
        self._priv = serialization.load_pem_private_key(PRIV_PEM.read_bytes(), None)
        self._pub  = serialization.load_pem_public_key(PUB_PEM.read_bytes())

    # -------- Dosya başlığı koruma (şifreleme) -------- #
    def protect_header(self, path: Path) -> tuple[bytes, bytes]:
        # AES anahtarı oluştur
        aes_key = AESGCM.generate_key(256)
        # SHA-256 hash hesapla (bütünlük kontrolü için)
        sha = hashlib.sha256(path.read_bytes()).hexdigest()
        # Meta bilgileri json olarak hazırla
        meta = {"name": path.name, "size": path.stat().st_size, "sha": sha}
        meta_json = json.dumps(meta).encode()
        # AES anahtarını RSA ile şifrele
        wrapped = self._pub.encrypt(
            aes_key,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None))
        # Başlığı döndür: uzunluk bilgisi + meta + şifrelenmiş AES
        return len(meta_json).to_bytes(2, "big") + meta_json + wrapped, aes_key

    # -------- Dosya başlığı çözme -------- #
    def unprotect_header(self, blob: bytes) -> Header:
        meta_len = int.from_bytes(blob[:2], "big")
        meta = json.loads(blob[2:2 + meta_len])
        wrapped = blob[2 + meta_len:]
        # RSA ile AES anahtarını çöz
        aes_key = self._priv.decrypt(
            wrapped,
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None))
        return Header(aes_key=aes_key, **meta)

    # -------- AES ile veri şifreleme -------- #
    def aes_encrypt(self, data: bytes, key: bytes) -> bytes:
        aes = AESGCM(key)
        nonce = secrets.token_bytes(12)  # rastgele nonce
        return nonce + aes.encrypt(nonce, data, None)

    # -------- AES ile veri çözme -------- #
    def aes_decrypt(self, blob: bytes, key: bytes) -> bytes:
        nonce, ct = blob[:12], blob[12:]
        return AESGCM(key).decrypt(nonce, ct, None)

    # -------- SHA-256 ile doğrulama -------- #
    @staticmethod
    def validate_file(path: Path, sha_expected: str) -> bool:
        return hashlib.sha256(path.read_bytes()).hexdigest() == sha_expected


# Eğer bu dosya doğrudan çalıştırılırsa, RSA anahtarları üret
if __name__ == "__main__":
    generate_keys()
