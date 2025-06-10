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
    RTTMeter, BandwidthMeter, ARPGuard, CHUNK
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
            raise ConnectionError("Bağlantı erken kesildi.")
        buf += part
    return buf

# --- Tkinter ana uygulama sınıfı ---
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Güvenli Dosya Aktarımı")
        self.geometry("540x380")
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

        # İlerleme çubuğu ve durum mesajı
        self.bar = ttk.Progressbar(self, length=520)
        self.bar.pack(pady=4)
        self.lbl_status = ttk.Label(self, text="")
        self.lbl_status.pack()

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
            sock = socket.create_connection((host, port))
        except OSError as e:
            self.lbl_status.config(text=f"Bağlanamadı: {e}")
            return

        header, aes_key = crypt.protect_header(self.file)
        sock.sendall(header)  # Şifreli başlık gönder

        # Dosya parçalarını sırayla şifreleyip gönder
        sent = 0
        total = self.file.stat().st_size
        for block in chunk_file(self.file, CHUNK):
            sock.sendall(crypt.aes_encrypt(block, aes_key))
            sent += len(block)
            self.bar["value"] = 100 * sent / total

        sock.close()
        self.lbl_status.config(text="Gönderim tamamlandı ✓")

    # --- Dosya alma işlemi ---
    @_thread
    def do_recv(self):
        try:
            self.lbl_status.config(text="Dinleniyor...")
            port = int(self.ent_port.get())

            # Sunucu başlat
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("", port))
            srv.listen(1)
            conn, addr = srv.accept()
            print(f"[+] Bağlantı kabul edildi: {addr}")  # 1. BAĞLANTI LOGU

            crypt = CryptoBox()

            # Başlık al
            head_len = 2
            meta_len_bytes = _recv_exact(conn, head_len)
            meta_len = int.from_bytes(meta_len_bytes, "big")
            meta_json = _recv_exact(conn, meta_len)
            wrapped = _recv_exact(conn, 256)

            blob = meta_len_bytes + meta_json + wrapped
            header = crypt.unprotect_header(blob)
            print(f"[=] Header alındı: {header.name}, {header.size} byte")  # 2. HEADER LOGU

            # Veri al ve birleştir
            out_f = Path.cwd() / f"alindi_{header.name}"
            received = 0
            chunks = []

            while received < header.size:
                blob = conn.recv(CHUNK + 32)
                if not blob:
                    break
                part = crypt.aes_decrypt(blob, header.aes_key)
                chunks.append(part)
                received += len(part)
                self.bar["value"] = 100 * received / header.size
                print(f"[>] Alındı: {received}/{header.size} byte")  # 3. PARÇA LOGU

            merge_chunks(chunks, out_f)
            print(f"[✓] Yazıldı: {out_f}")  # 4. DOSYA YAZILDI LOGU

            # SHA256 ile bütünlük kontrolü
            ok = crypt.validate_file(out_f, header.sha)
            print(f"[✓] SHA kontrol: {'OK' if ok else 'HATA'}")  # 5. HASH LOGU
            self.lbl_status.config(text="Alındı ✓" if ok else "Hash HATA")

            conn.close()
            srv.close()

        except Exception as e:
            self.lbl_status.config(text=f"Alma Hatası: {e}")

    # --- Gecikme ölçümü (RTT) ---
    @_thread
    def do_rtt(self):
        ms = RTTMeter().measure(self.ent_host.get())
        self.lbl_status.config(text=f"RTT: {ms:.1f} ms")

    # --- Bant genişliği ölçümü ---
    @_thread
    def do_bw(self):
        mbps = BandwidthMeter().measure(self.ent_host.get())
        self.lbl_status.config(text=f"Bant: {mbps:.1f} Mbps")

    # --- MITM saldırı tespiti ---
    @_thread
    def do_mitm(self):
        iface = list_ifaces()[0]
        poisoned = ARPGuard().scan(iface)
        self.lbl_status.config(text="Spoof TESPİT!" if poisoned else "Ağ temiz")


# --- Programın giriş noktası ---
if __name__ == "__main__":
    App().mainloop()