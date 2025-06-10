# Secure-File-Transfer-Python

**Güvenli Dosya Aktarımı ve Ağ Analiz Aracı (Python)**

Bu proje, uçtan uca güvenli dosya aktarımı ve temel ağ analiz yeteneklerini bir arada sunan, Python ile yazılmış kapsamlı bir uygulamadır. Veri gizliliği, bütünlüğü ve ağ performansı ölçümleri üzerine odaklanır.

---

## 🚀 Özellikler

### 🔒 1. Güvenli Dosya Aktarımı
- **Hibrit Şifreleme**  
  - AES-256-GCM ile simetrik içeriği şifreler  
  - RSA-2048 (OAEP+SHA-256) ile oturum anahtarını sarar  
- **Dosya Bütünlüğü**  
  - SHA-256 hash hesaplayıp transfer öncesi/sonrası doğrular  
- **Parçalama & Birleştirme**  
  - `chunk_file()` / `merge_chunks()` ile 1 KB’lık fragmanlara ayırma ve yeniden montaj  

### 📊 2. Ağ Performans Ölçümleri
- **Gecikme (RTT)**  
  - `network_mods.py` içindeki `RTTMeter` ile ping bazlı ortalama hesaplama  
- **Bant Genişliği**  
  - `BandwidthMeter` sınıfı ile `iperf3` kullanarak Mbps ölçümü  

### 🛡️ 3. Güvenlik Analizi & Simülasyonları
- **Wireshark Uyumluluğu**  
  - Şifrelenmiş trafiğin ağda okunamaz (ciphertext) olduğunu gözlemler  
- **MITM Tespiti**  
  - `ARPGuard` sınıfı ile ARP zehirlenmesi denetimi  
- **Düşük Seviyeli IP İnceleme**  
  - Scapy ile özel TTL, Flags ayarlı ICMP paketleri gönderme/alma  

### 💻 4. Grafiksel Kullanıcı Arayüzü (BONUS)
- **Tkinter GUI**  
  - Dosya seçimi, gönder/al, RTT, bant ölçümü ve MITM testlerini tek pencerede sunar  
  - Progressbar ve dinamik status label ile görsel geri bildirim  

---

## ⚙️ Kurulum

1. **Depoyu Klonlayın**  
    ```bash
    git clone https://github.com/ceydagulen/Secure-File-Transfer-Python.git
    cd Secure-File-Transfer-Python
    ```

2. **Gerekli Python Paketlerini Kurun**  
    ```bash
    pip install cryptography scapy psutil
    ```
    - `cryptography`: AES / RSA  
    - `scapy`: Düşük seviyeli paket işlemleri  
    - `psutil`: Ağ arayüzü listesi  

3. **Harici Araçlar**  
    - **iperf3** (bant ölçümü)  
      - **Linux**: `sudo apt install iperf3`  
      - **Windows**: [iperf.fr](https://iperf.fr/)’den indir, PATH’e ekleyin  
    - **Clumsy** (Windows için paket kaybı simülasyonu)  
      - https://jagt.github.io/clumsy/  

4. **Scapy Yetkisi (Linux)**  
    ```bash
    sudo setcap cap_net_raw+ep $(which python3)
    ```

5. **Npcap (Windows)**  
    - “Install Npcap in WinPcap API-compatible Mode” seçin  

---
GUI üzerinden:

Dosya Seç: “Seç…”

Ağ Ayarları: Host / Port girin

Gönder / Al: Şifreli transfer

RTT Ölç / Bant Ölç: Ping / iperf3 sonuçları

MITM Test / IP Test: Güvenlik ve IP başlık simülasyonları

---
📂 Dosya Yapısı


├── main.py               # GUI ve iş akışı

├── security_mods.py      # AES-GCM, RSA-OAEP, SHA-256

├── network_mods.py       # chunk, RTTMeter, BandwidthMeter, ARPGuard, IPHeaderTool

└── keys/                 # RSA anahtar dizini (otomatik oluşturulur)


## 🚀 Kullanım

```bash
python main.py
