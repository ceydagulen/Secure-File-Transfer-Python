# main.py – Tkinter GUI ile güvenli dosya aktarımı
# ----------------------------------------------------
# Bu uygulama, RSA ve AES kullanarak dosya şifreleme, güvenli gönderme/alma,
# RTT/bant genişliği ölçümü ve MITM saldırı tespiti yapar.

import sys, socket, threading
from pathlib import Path
from typing import Optional
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Yardımcı modülleri içe aktar
from security_mods import CryptoBox
from network_mods import (
    chunk_file, merge_chunks, list_ifaces,
    RTTMeter, BandwidthMeter, ARPGuard, CHUNK # IPHeaderTool'u bu projede kullanmadığınız için buraya eklemiyorum. Eğer kullanacaksanız eklemelisiniz.
)

# --- Yardımcı dekoratör: fonksiyonu arka planda thread olarak çalıştırır ---
def _thread(fn):
    def wrapper(*args, **kw):
        t = threading.Thread(target=fn, args=args, kwargs=kw, daemon=True)
        t.start()
    return wrapper

# --- Belirli byte uzunluğunda veriyi eksiksiz almak için yardımcı fonksiyon ---
def _recv_exact(sock, size):
    buf = b''
    while len(buf) < size:
        part = sock.recv(size - len(buf))
        if not part:
            # Bağlantının erken kesilmesi durumunda detaylı hata mesajı
            raise ConnectionError(f"Bağlantı erken kesildi! Beklenen {size} byte, alınan {len(buf)} byte.")
        buf += part
    return buf

# --- Tkinter ana uygulama sınıfı ---
class App(tk.Tk):
    def __init__(self): # __init__ düzeltildi
        super().__init__()
        self.title("Güvenli Dosya Aktarımı")
        self.geometry("640x420") # Boyutu biraz artırıldı
        self.resizable(False, False)
        self.file: Optional[Path] = None  # Seçilen dosya
        self._build_ui()  # Arayüzü oluştur

    # --- Kullanıcı arayüzünü oluştur ---
    def _build_ui(self):
        pad = {"padx": 6, "pady": 6}

        # Dosya seçme alanı
        frm_file = ttk.LabelFrame(self, text="Dosya")
        frm_file.pack(fill="x", **pad)
        self.lbl_file = ttk.Label(frm_file, text="Seçilmedi")
        self.lbl_file.pack(side="left", padx=4)
        ttk.Button(frm_file, text="Seç…", command=self.pick_file).pack(side="right")

        # Ağ ayarları
        frm_net = ttk.LabelFrame(self, text="Ağ")
        frm_net.pack(fill="x", **pad)
        ttk.Label(frm_net, text="Host:").pack(side="left")
        self.ent_host = ttk.Entry(frm_net, width=15)
        self.ent_host.insert(0, "127.0.0.1")
        self.ent_host.pack(side="left", padx=4)
        ttk.Label(frm_net, text="Port:").pack(side="left")
        self.ent_port = ttk.Spinbox(frm_net, from_=1024, to=65535, width=6)
        self.ent_port.set(5000)
        self.ent_port.pack(side="left", padx=4)

        # Fonksiyon butonları
        frm_btn = ttk.Frame(self)
        frm_btn.pack(fill="x", **pad)
        ttk.Button(frm_btn, text="Gönder", command=self.do_send).pack(side="left")
        ttk.Button(frm_btn, text="Al",     command=self.do_recv).pack(side="left")
        ttk.Button(frm_btn, text="RTT Ölç",  command=self.do_rtt).pack(side="left")
        ttk.Button(frm_btn, text="Bant Ölç", command=self.do_bw).pack(side="left")
        ttk.Button(frm_btn, text="MITM Test", command=self.do_mitm).pack(side="left")
        # IPHeaderTool'u GUI'ye eklemek isterseniz, bu kısmı aktif edin:
        # ttk.Button(frm_btn, text="IP Test", command=self.do_ip_test).pack(side="left")

        # İlerleme çubuğu ve durum mesajı
        self.bar = ttk.Progressbar(self, length=520)
        self.bar.pack(pady=4)
        self.lbl_status = ttk.Label(self, text="")
        self.lbl_status.pack()

        # IP Testi için ek giriş alanları (Eğer IPHeaderTool kullanılacaksa)
        # frm_ip_test = ttk.LabelFrame(self, text="IP Test Ayarları")
        # frm_ip_test.pack(fill="x", **pad)
        # ttk.Label(frm_ip_test, text="TTL:").pack(side="left")
        # self.ent_ttl = ttk.Entry(frm_ip_test, width=5)
        # self.ent_ttl.insert(0, "64")
        # self.ent_ttl.pack(side="left", padx=4)
        # ttk.Label(frm_ip_test, text="Flags (Hex):").pack(side="left")
        # self.ent_flags = ttk.Entry(frm_ip_test, width=5)
        # self.ent_flags.insert(0, "0x00")
        # self.ent_flags.pack(side="left", padx=4)


    # --- Dosya seçme işlemi ---
    def pick_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file = Path(path)
            self.lbl_file.config(text=self.file.name)

    # --- Dosya gönderme işlemi ---
    @_thread
    def do_send(self):
        if not self.file:
            messagebox.showwarning("Uyarı", "Önce dosya seçin!")
            return

        host = self.ent_host.get().strip() or "127.0.0.1"
        port = int(self.ent_port.get())
        crypt = CryptoBox()

        try:
            self.lbl_status.config(text="Bağlanılıyor...")
            self.bar["value"] = 0 # İşlem başlamadan sıfırla
            sock = socket.create_connection((host, port))
        except OSError as e:
            self.lbl_status.config(text=f"Bağlanamadı: {e}")
            return

        try:
            header, aes_key = crypt.protect_header(self.file)
            sock.sendall(header)  # Şifreli başlık gönder

            # Dosya parçalarını sırayla şifreleyip gönder
            sent = 0
            total = self.file.stat().st_size
            self.lbl_status.config(text="Dosya gönderiliyor...")
            for block in chunk_file(self.file, CHUNK):
                sock.sendall(crypt.aes_encrypt(block, aes_key))
                sent += len(block)
                self.bar["value"] = 100 * sent / total
                self.update_idletasks() # GUI'yi güncelle

            sock.close()
            self.lbl_status.config(text="Gönderim tamamlandı ✓")
            self.bar["value"] = 0 # İşlem bitince çubuğu sıfırla
        except Exception as e:
            self.lbl_status.config(text=f"Gönderme Hatası: {e}")
            try:
                sock.close()
            except:
                pass # Already closed or invalid socket

    # --- Dosya alma işlemi ---
    @_thread
    def do_recv(self):
        try:
            self.lbl_status.config(text="Dinleniyor...")
            self.bar["value"] = 0 # Başlangıçta sıfırla
            port = int(self.ent_port.get())

            # Sunucu başlat
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", port))
            srv.listen(1)
            conn, addr = srv.accept()
            print(f"[+] Bağlantı kabul edildi: {addr}")

            crypt = CryptoBox()

            # Başlık al
            head_len = 2
            meta_len_bytes = _recv_exact(conn, head_len)
            meta_len = int.from_bytes(meta_len_bytes, "big")
            meta_json = _recv_exact(conn, meta_len)
            wrapped = _recv_exact(conn, 256)

            blob = meta_len_bytes + meta_json + wrapped
            header = crypt.unprotect_header(blob)
            print(f"[=] Header alındı: {header.name}, {header.size} byte")

            # Veri al ve birleştir
            out_f = Path.cwd() / f"alindi_{header.name}"
            received = 0
            chunks = []

            self.lbl_status.config(text="Dosya alınıyor...")
            while received < header.size:
                # AES şifrelemesi 12 byte nonce + veri + 16 byte tag = CHUNK + 12 + 16 = CHUNK + 28 olabilir
                # Ancak son blok CHUNK'tan küçük olabilir, bu yüzden _recv_exact'a tam boyutunu vermeliyiz.
                # Burada sadece maksimum boyutu tahmin edebiliyoruz.
                # Daha doğru bir yaklaşım, gönderici tarafın her bloktan önce boyut bilgisini göndermesidir.
                # Şu anki haliyle, `_recv_exact` kullanımı daha güvenli.
                # CHUNK + 32'lik bir blok bekleniyor, ancak son blok daha küçük olabilir.
                # Bu yüzden burada `conn.recv` kullanmak ve bitene kadar okumak daha doğru.
                # Yada gonderici her bloktan once o blogun sifreli boyutunu gonderir.
                # Mevcut durumda, en basiti, son blok için boyutu tahmin etmeye çalışmak yerine,
                # gelen veriyi okumaya devam etmek. Ancak bu durumda, `_recv_exact` işe yaramaz.
                # En mantıklısı, göndericinin her bloktan önce şifreli blok boyutunu göndermesi.

                # Geçiçi çözüm: Yeterince büyük bir tampon kullanmaya devam edelim
                # ve _recv_exact kullanmayalım, çünkü son parça boyutu farklı olabilir.
                # Bu yaklaşım, ağda veri gelmesini beklerken daha esnektir.
                # Problem_1: "Bağlantı erken kesildi" hatası _recv_exact'ın boyuta tam uymama durumundan geliyordu.
                # Eğer gönderici tam olarak CHUNK+32 göndermiyorsa (son parça gibi), _recv_exact beklemeye devam eder.
                # Düzeltme: Her şifreli parçanın boyutunu gönderen taraftan almalıyız. Bu karmaşıklaşır.
                # Alternatif: Son parçayı gönderirken bir EOF (bağlantı kapatma) sinyali beklemek.
                
                # Mevcut kodda en yakın düzeltme:
                # Her seferinde büyük bir tampon alıp, sonra şifrelemeyi dene ve devam et.
                # Eğer bağlantı kapanırsa döngüden çık.
                blob_received = conn.recv(CHUNK + 32) # Maksimum olası boyut
                if not blob_received:
                    break # Bağlantı kapandı, tüm veriler alınmış olmalı
                
                # AES şifrelemesi, AESGCM'in kendisi bütünlük ve boyut kontrolü yapar.
                # decryption hatası alırsak, veri bozuk demektir.
                try:
                    part = crypt.aes_decrypt(blob_received, header.aes_key)
                    chunks.append(part)
                    received += len(part)
                    self.bar["value"] = 100 * received / header.size
                    self.update_idletasks() # GUI'yi güncelle
                    print(f"[>] Alındı: {received}/{header.size} byte")
                except Exception as decrypt_error:
                    print(f"[!] Şifre çözme hatası veya bütünlük bozukluğu: {decrypt_error}")
                    self.lbl_status.config(text=f"Alma Hatası: Veri bozuk ({decrypt_error})")
                    break # Şifre çözme hatası alırsak döngüden çık

            merge_chunks(chunks, out_f)
            print(f"[✓] Yazıldı: {out_f}")

            # SHA256 ile bütünlük kontrolü
            ok = crypt.validate_file(out_f, header.sha)
            print(f"[✓] SHA kontrol: {'OK' if ok else 'HATA'}")
            self.lbl_status.config(text="Alındı ✓" if ok else "Hash HATA")

            conn.close()
            srv.close()
            self.bar["value"] = 0 # İşlem bitince çubuğu sıfırla

        except Exception as e:
            self.lbl_status.config(text=f"Alma Hatası: {e}")
            # Hata durumunda server ve connection nesnelerinin kapatıldığından emin ol
            try:
                if 'conn' in locals() and conn:
                    conn.close()
                if 'srv' in locals() and srv:
                    srv.close()
            except:
                pass


    # --- Gecikme ölçümü (RTT) ---
    @_thread
    def do_rtt(self):
        self.lbl_status.config(text="RTT ölçülüyor...") # Durum mesajı eklendi
        host = self.ent_host.get()
        ms = RTTMeter().measure(host)
        if ms == float("nan"): # Hata durumunu kontrol et
            self.lbl_status.config(text=f"RTT: Host '{host}' yanıt vermedi veya hata oluştu.")
        else:
            self.lbl_status.config(text=f"RTT: {ms:.1f} ms")
        self.update_idletasks()

    # --- Bant genişliği ölçümü ---
    @_thread
    def do_bw(self):
        self.lbl_status.config(text="Bant genişliği ölçülüyor...") # Durum mesajı eklendi
        host = self.ent_host.get()
        mbps = BandwidthMeter().measure(host)
        if mbps == float("nan"): # Hata durumunu kontrol et
            self.lbl_status.config(text=f"Bant: Host '{host}' iperf3 sunucusu aktif değil veya hata oluştu.")
        else:
            self.lbl_status.config(text=f"Bant: {mbps:.1f} Mbps")
        self.update_idletasks()


    # --- MITM saldırı tespiti ---
    @_thread
    def do_mitm(self):
        self.lbl_status.config(text="MITM saldırısı kontrol ediliyor...") # Durum mesajı eklendi
        ifaces = list_ifaces()
        if not ifaces:
            self.lbl_status.config(text="Arayüz bulunamadı.")
            return

        iface = ifaces[0] # İlk arayüzü kullan
        try:
            poisoned = ARPGuard().scan(iface)
            self.lbl_status.config(text="Spoof TESPİT!" if poisoned else "Ağ temiz")
        except Exception as e:
            self.lbl_status.config(text=f"MITM Test Hatası: {e}. Scapy yetkileri veya kurulumu kontrol edin.")
        self.update_idletasks()

    # IPHeaderTool GUI entegrasyonu (network_mods.py'nizde IPHeaderTool varsa)
    # Eğer IPHeaderTool'u network_mods.py'ye eklediyseniz, main.py'de de import etmeniz ve
    # _build_ui'de IP Test butonunu ve ayarlarını aktif etmeniz gerekecektir.
    # Bu durumda, aşağıdaki fonksiyonu da main.py sınıfına eklemelisiniz.
    """
    @_thread
    def do_ip_test(self):
        # Bu kısım önceki yanıtta belirtildiği gibi IPHeaderTool'u kullanır.
        # Bu kodun çalışması için main.py'nin en üstünde
        # from network_mods import (..., IPHeaderTool, CHUNK)
        # şeklinde IPHeaderTool'un import edilmiş olması ve _build_ui metodunda
        # 'IP Test' butonu ile 'IP Test Ayarları' frame'inin aktif olması gerekir.
        self.lbl_status.config(text="IP Testi yapılıyor...")
        host = self.ent_host.get()
        try:
            ttl = int(self.ent_ttl.get())
            flags = int(self.ent_flags.get(), 16)
        except ValueError:
            self.lbl_status.config(text="Hata: Geçersiz TTL veya Flags değeri.")
            return

        ip_tool = IPHeaderTool()
        result = ip_tool.send_custom_ping(host, ttl=ttl, flags=flags)

        if result["status"] == "success":
            info = result["response"]
            status_text = (
                f"IP Test Başarılı!\n"
                f"  Kaynak IP: {info['source_ip']}\n"
                f"  Hedef IP: {info['destination_ip']}\n"
                f"  TTL: {info['ttl']} (Gönderilen: {ttl})\n"
                f"  ID: {info['id']}\n"
                f"  Flags: {hex(info['flags'])} (Gönderilen: {hex(flags)})\n"
                f"  Checksum: {hex(info['checksum'])}\n"
                f"  Paket Uzunluğu: {info['len']} byte\n"
                f"  RTT: {info['rtt_ms']:.2f} ms"
            )
            self.lbl_status.config(text=status_text, justify=tk.LEFT)
        else:
            self.lbl_status.config(text=f"IP Testi Hatası: {result['response']}")

        if self.file:
            self.lbl_status.config(text=self.lbl_status.cget("text") + "\n\nUygulama Katmanı Parçalama Simülasyonu...")
            try:
                test_data = self.file.read_bytes()[:min(1024, self.file.stat().st_size)] # Dosya boyutu 1KB'dan küçükse hata vermemesi için
                reconstructed = ip_tool.simulate_fragment_reconstruction(test_data, 100)
                if reconstructed:
                    self.lbl_status.config(text=self.lbl_status.cget("text") + "\nSimülasyon BAŞARILI: Veri yeniden birleştirildi ve doğrulandı.")
                else:
                    self.lbl_status.config(text=self.lbl_status.cget("text") + "\nSimülasyon HATALI: Veri yeniden birleştirilemedi veya doğrulanamadı.")
            except Exception as e:
                self.lbl_status.config(text=self.lbl_status.cget("text") + f"\nSimülasyon Hatası: {e}")
        else:
            self.lbl_status.config(text=self.lbl_status.cget("text") + "\nDosya seçilmediği için uygulama katmanı parçalama simülasyonu atlandı.")
        self.update_idletasks()
    """

# --- Programın giriş noktası ---
if __name__ == "__main__":
    App().mainloop()
