# network_mods.py – dosya parçalama, ağ ölçümleri, ARP-spoof kontrolü
# -------------------------------------------------------------------
from __future__ import annotations
from pathlib import Path
import subprocess, statistics, sys

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
            mbps = json.loads(out)["end"]["sum_received"]["bits_per_second"] / 1_000_000
            return mbps
        except Exception:
            return float("nan")

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
            return False
        conf.verb = 0
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst="192.168.1.0/24"),
                     timeout=2, iface=iface)
        seen = {}
        for _, r in ans:
            ip, mac = r.psrc, r.hwsrc
            if ip in seen and seen[ip] != mac:
                return True  # Aynı IP için farklı MAC varsa spoofing olabilir
            seen[ip] = mac
        return False

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