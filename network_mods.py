# network_mods.py – dosya parçalama, ağ ölçümleri, ARP-spoof kontrolü
# -------------------------------------------------------------------
from __future__ import annotations
from pathlib import Path
import subprocess, statistics, sys, hashlib # hashlib eklendi

# Scapy'yi eklemek için import satırını ekleyin
try:
    from scapy.all import IP, ICMP, sr1, conf, ARP, Ether, srp # ARP, Ether, srp da ARPGuard için gerekli
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    print("[-] Scapy yüklü değil. Düşük seviyeli IP işlemleri ve ARP Spoof kontrolü kullanılamayacak.")


CHUNK = 1 << 20  # 1 MiB (1 megabayt) boyutunda parçalar kullanılacak

# ───────── DOSYA PARÇALAMA ─────────
def chunk_file(path: Path, size: int = CHUNK):
    """
    Verilen dosyayı belirtilen boyutta parçalara ayırır.
    Her parçayı yield ile döndürür (generator).
    """
    with path.open("rb") as f:
        total = path.stat().st_size
        print(f"[DEBUG] Dosya {path.name} toplam {total} byte. Parçalanıyor...")

        parca_no = 1
        while True:
            data = f.read(size)
            if not data:
                break
            print(f"[PARÇA {parca_no}] {len(data)} byte")
            parca_no += 1
            yield data

def merge_chunks(chunks: list[bytes], output: Path):
    """
    Alınan parça listesini (bytes) birleştirerek hedef dosyayı yazar.
    """
    with output.open("wb") as f:
        for c in chunks:
            f.write(c)

# ───────── AĞ PERFORMANSI ─────────
class RTTMeter:
    def measure(self, host: str, count: int = 4) -> float:
        """
        Ping komutuyla RTT (Round Trip Time) ortalamasını milisaniye cinsinden hesaplar.
        """
        rtt = []
        flag = "-n" if sys.platform.startswith("win") else "-c"
        for _ in range(count):
            out = subprocess.run(["ping", flag, "1", host],
                                 capture_output=True, text=True).stdout
            # Ping çıktısında "time=" ifadesini arayın
            if "time=" in out:
                part = out.split("time=")[-1].split("ms")[0]
                try:
                    rtt.append(float(part))
                except ValueError:
                    pass
        return statistics.mean(rtt) if rtt else float("nan")

class BandwidthMeter:
    def measure(self, host: str, seconds: int = 10) -> float:
        """
        iperf3 aracını kullanarak bant genişliğini Mbps cinsinden ölçer.
        Sunucunun host:5201 portunda iperf3 ile dinlemede olması gerekir.
        """
        try:
            out = subprocess.check_output(
                ["iperf3", "-c", host, "-t", str(seconds), "-J"],
                text=True)
            # JSON çıktısından Mbit/s değeri çekilir
            import json
            # iperf3 çıktısının yapısı değişebilir, güvenli bir şekilde erişin
            data = json.loads(out)
            if "end" in data and "sum_received" in data["end"] and "bits_per_second" in data["end"]["sum_received"]:
                mbps = data["end"]["sum_received"]["bits_per_second"] / 1_000_000
                return mbps
            else:
                return float("nan") # Beklenen JSON yapısı bulunamadı
        except Exception as e:
            print(f"[ERROR] BandwidthMeter: {e}")
            return float("nan")

# ───────── IP HEADER İŞLEMLERİ (YENİ EKLENEN KISIM) ─────────
class IPHeaderTool:
    def send_custom_ping(self, host: str, ttl: int = 64, flags: int = 0) -> dict:
        """
        Scapy kullanarak özel IP başlığına sahip bir ICMP (ping) paketi gönderir.
        Manuel TTL ve IP Bayrakları ayarı örneği.
        Dönüş değeri, alınan paketin bilgilerini içerir.
        """
        if not _SCAPY_AVAILABLE:
            return {"error": "Scapy yüklü değil."}

        conf.verb = 0 # Scapy'nin detaylı çıktısını kapat

        # IP başlığını manuel olarak oluşturma ve ayarlama
        # IP(dst=host, ttl=ttl, flags=flags)
        # flags:
        #   0x02 (DF - Don't Fragment)
        #   0x04 (MF - More Fragments)
        # Checksum Scapy tarafından otomatik hesaplanır.
        packet = IP(dst=host, ttl=ttl, flags=flags) / ICMP()

        # Paketi gönder ve yanıtı al
        # sr1: Send Receive 1st answer
        ans = sr1(packet, timeout=2)

        if ans:
            # Alınan paketin IP başlık bilgilerini okuma
            ip_header_info = {
                "source_ip": ans.src,
                "destination_ip": ans.dst,
                "ttl": ans.ttl,
                "id": ans.id,
                "flags": ans.flags,
                "checksum": ans.chksum, # Scapy otomatik hesapladığı checksum
                "len": ans.len,
                "rtt_ms": (ans.time - packet.sent_time) * 1000 # Gidiş-dönüş süresi
            }
            return {"status": "success", "response": ip_header_info}
        else:
            return {"status": "timeout", "response": "Yanıt alınamadı."}

    def simulate_fragment_reconstruction(self, data: bytes, chunk_size: int) -> list[bytes]:
        """
        Bu fonksiyon, mevcut uygulamanızdaki 'chunk_file' ve 'merge_chunks'
        fonksiyonlarının temel mantığını kullanarak, uygulama katmanında
        parçalanmış verinin nasıl "yeniden birleştirildiğini" gösterir.
        Bu, IP fragmantasyonu DEĞİLDİR, uygulama katmanı parçalamadır.
        """
        if not data:
            return []

        # Veriyi belirli boyutlarda parçalara ayırma (uygulama katmanı)
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        print(f"[DEBUG] Simülasyon: {len(chunks)} uygulama parçasına bölündü.")

        # Parçaları yeniden birleştirme
        reconstructed_data = b"".join(chunks)
        print(f"[DEBUG] Simülasyon: Parçalar yeniden birleştirildi. Boyut: {len(reconstructed_data)} byte")

        # Doğrulama (basit bir boyut ve hash kontrolü)
        if len(reconstructed_data) == len(data) and \
           hashlib.sha256(reconstructed_data).hexdigest() == hashlib.sha256(data).hexdigest():
            print("[DEBUG] Simülasyon: Yeniden birleştirilen veri doğrulandı (boyut ve hash eşleşiyor).")
            return [reconstructed_data] # Başarılıysa tek bir bütün parça döndür
        else:
            print("[DEBUG] Simülasyon: Yeniden birleştirme veya doğrulama HATASI!")
            return []


# ───────── ARP SPOOF TESPİTİ ─────────
class ARPGuard:
    def scan(self, iface: str) -> bool:
        """
        Scapy ile yerel ağda ARP paketleri gönderir.
        Aynı IP'den farklı MAC adresi dönerse spoofing tespiti yapılmış olur.
        """
        try:
            from scapy.all import ARP, Ether, srp, conf
        except ImportError:
            # Scapy zaten modül başında kontrol edildi, burası redundant olabilir.
            # Ancak yine de defensive programming için bırakılabilir.
            return False
        if not _SCAPY_AVAILABLE: # Ana importta hata oluştuysa burayı da engelle
            return False

        conf.verb = 0
        try:
            # Geniş bir alt ağ yerine, varsayılan ağ geçidini veya bilinen hostları taramak daha spesifik olabilir.
            # Ancak genel bir tarama için bu da geçerli.
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"),
                         timeout=2, iface=iface)
            seen = {}
            for _, r in ans:
                ip, mac = r.psrc, r.hwsrc
                if ip in seen and seen[ip] != mac:
                    return True  # Aynı IP için farklı MAC varsa spoofing olabilir
                seen[ip] = mac
            return False
        except Exception as e:
            print(f"[ERROR] ARPGuard: {e}. Yetki sorunu olabilir mi?")
            return False # Scapy'nin çalışmasında hata oluştu

# ───────── ARAYÜZ LİSTESİ ─────────
def list_ifaces() -> list[str]:
    """
    Sistemdeki ağ arayüzlerini listeler. Psutil yüklü değilse varsayılan "eth0" döner.
    """
    try:
        import psutil
        return list(psutil.net_if_addrs().keys())
    except ImportError:
        # Geriye dönük çözüm: tek bir arayüz varsay
        return ["eth0"]
