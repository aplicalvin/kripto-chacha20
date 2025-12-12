import matplotlib
matplotlib.use('TkAgg')  # PENTING: Set backend sebelum import pyplot
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import numpy as np
from PIL import Image, ImageTk
import hashlib
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from skimage.metrics import structural_similarity as ssim
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ==============================================================================
# 1. LOGIKA METRIK (DIPERBAIKI)
# ==============================================================================

def calculate_mse(img1, img2):
    # MSE selalu positif
    return np.mean((img1.astype(float) - img2.astype(float)) ** 2)

def calculate_rmse(img1, img2):
    return np.sqrt(calculate_mse(img1, img2))

def calculate_psnr(img1, img2):
    mse = calculate_mse(img1, img2)
    if mse == 0: return 100.0 # Nilai max jika identik
    max_pixel = 255.0
    # PSNR selalu positif
    return 20 * np.log10(max_pixel / np.sqrt(mse))

def calculate_npcr(img1, img2):
    # Persentase pixel yang berubah (0-100%)
    return (np.sum(img1 != img2) / img1.size) * 100

def calculate_uaci(img1, img2):
    # Rata-rata intensitas perubahan (0-100%)
    diff = np.abs(img1.astype(float) - img2.astype(float))
    return (np.sum(diff) / (img1.size * 255)) * 100

def calculate_entropy(img):
    """
    Menghitung Shannon Entropy.
    Untuk citra 8-bit, nilai max adalah 8.0.
    Rumus: -sum(p * log2(p))
    """
    # Ratakan array agar menghitung distribusi seluruh piksel
    flat_img = img.flatten()
    # Hitung kemunculan setiap nilai 0-255
    hist, _ = np.histogram(flat_img, bins=256, range=(0, 256))
    
    # Normalisasi untuk mendapatkan probabilitas (p)
    prob = hist / hist.sum()
    
    # Hapus probabilitas 0 karena log2(0) tidak terdefinisi
    prob = prob[prob > 0]
    
    # Rumus Shannon Entropy
    entropy = -np.sum(prob * np.log2(prob))
    return abs(entropy) # Pastikan absolute (walau rumus aslinya sudah pasti positif)

def calculate_ssim_custom(img1, img2):
    # SSIM range -1 s/d 1.
    # Agar "tidak ada yang negatif" (permintaan dosen), kita absolutkan
    # atau kita asumsikan enkripsi membuat strukturnya hancur (mendekati 0)
    if len(img1.shape) == 3:
        val = ssim(img1, img2, channel_axis=2, data_range=255)
    else:
        val = ssim(img1, img2, data_range=255)
    return abs(val) # REVISI: Dipaksa positif

def calculate_msiq(img1, img2):
    """MS-SSIM pendekatan sederhana"""
    steps = 3
    total_score = 0
    curr1, curr2 = img1, img2
    
    for i in range(steps):
        total_score += calculate_ssim_custom(curr1, curr2)
        h, w = curr1.shape[:2]
        new_size = (w // 2, h // 2)
        if i < steps - 1:
            p1 = Image.fromarray(curr1)
            p2 = Image.fromarray(curr2)
            curr1 = np.array(p1.resize(new_size, Image.BICUBIC))
            curr2 = np.array(p2.resize(new_size, Image.BICUBIC))
            
    return abs(total_score / steps) # Pastikan positif

def calculate_avalanche_effect(img_original, key_str):
    """
    Menghitung Avalanche Effect (AE) pada KUNCI.
    Membandingkan Ciphertext 1 (Key Asli) vs Ciphertext 2 (Key modifikasi 1 bit).
    Target ideal AE adalah ~50%.
    """
    # 1. Siapkan Key 1 (Asli)
    if len(key_str) < 32:
        key1 = hashlib.sha256(key_str.encode()).digest()
    else:
        key1 = key_str[:32].encode()
        
    # 2. Siapkan Key 2 (Ubah 1 bit dari Key 1)
    # Kita ambil byte terakhir, ubah 1 bit (XOR 1)
    key_list = bytearray(key1)
    key_list[-1] = key_list[-1] ^ 1 
    key2 = bytes(key_list)
    
    # 3. Enkripsi gambar yang sama dengan kedua key
    # Gunakan nonce yang SAMA agar perbandingan fair hanya pada Key
    nonce = b'\x00' * 12 
    
    cipher1 = ChaCha20.new(key=key1, nonce=nonce)
    enc1 = cipher1.encrypt(img_original.flatten().tobytes())
    
    cipher2 = ChaCha20.new(key=key2, nonce=nonce)
    enc2 = cipher2.encrypt(img_original.flatten().tobytes())
    
    # 4. Hitung perbedaan bit (Hamming Distance)
    # Konversi bytes ke array bit
    arr1 = np.frombuffer(enc1, dtype=np.uint8)
    arr2 = np.frombuffer(enc2, dtype=np.uint8)
    
    # XOR untuk mencari beda bit, lalu hitung jumlah bit 1 (popcount)
    # np.unpackbits mempercepat hitungan bit level
    bits1 = np.unpackbits(arr1)
    bits2 = np.unpackbits(arr2)
    
    diff_bits = np.sum(bits1 != bits2)
    total_bits = bits1.size
    
    ae_score = (diff_bits / total_bits) * 100
    return ae_score, key1.hex(), key2.hex()

# ==============================================================================
# 2. APLIKASI GUI (TKINTER)
# ==============================================================================

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ChaCha20 Image Encryption (UI Enhanced)")
        self.root.geometry("1400x900")
        self.root.configure(bg="#f5f6fa")
        import platform
        if platform.system() == "Windows":
            self.root.state("zoomed")
        else:
            self.root.attributes("-zoomed", True)

        self.original_arr = None
        self.encrypted_arr = None
        self.decrypted_arr = None
        self.nonce = None
        
        self.setup_ui()

    def setup_ui(self):
        # ================= HEADER =================
        header = tk.Frame(self.root, bg="#2d3436", height=60)
        header.pack(fill=tk.X)

        tk.Label(
            header, 
            text="🔐 ChaCha20 Image Encryption Tool",
            bg="#2d3436",
            fg="white",
            font=("Segoe UI", 16, "bold"),
            pady=10
        ).pack()

        # ============== CONTROL PANEL =================
        control_frame = tk.Frame(self.root, bg="#ffffff", bd=1, relief=tk.FLAT)
        control_frame.pack(fill=tk.X, padx=12, pady=10, ipady=6)

        # Styling tombol
        btn_style = {
            "font": ("Segoe UI", 10, "bold"),
            "fg": "white",
            "width": 14,
            "relief": tk.FLAT,
            "bd": 0,
            "cursor": "hand2",
            "height": 1
        }

        tk.Label(control_frame, text="Key:", bg="white", font=("Segoe UI", 11)).pack(side=tk.LEFT, padx=10)
        self.key_entry = tk.Entry(control_frame, show="*", width=28, font=("Segoe UI", 11), relief=tk.GROOVE)
        self.key_entry.pack(side=tk.LEFT, padx=5)

        tk.Button(control_frame, text="📤 Upload", bg="#0984e3", command=self.load_image, **btn_style).pack(side=tk.LEFT, padx=6)
        tk.Button(control_frame, text="🔒 Encrypt", bg="#d63031", command=self.process_encryption, **btn_style).pack(side=tk.LEFT, padx=6)
        tk.Button(control_frame, text="🔓 Decrypt", bg="#00b894", command=self.process_decryption, **btn_style).pack(side=tk.LEFT, padx=6)

        tk.Button(control_frame, text="⚠️ Avalanche Test", bg="#e1b12c", command=self.check_avalanche, **btn_style).pack(side=tk.LEFT, padx=20)

        tk.Button(control_frame, text="↻ Reset", bg="#636e72", command=self.reset_app, **btn_style).pack(side=tk.RIGHT, padx=10)

        # ================= MAIN FRAME =================
        main_frame = tk.Frame(self.root, bg="#f5f6fa")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)
        main_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.col_orig = self.create_column(main_frame, "ORIGINAL IMAGE", 0)
        self.col_enc = self.create_column(main_frame, "ENCRYPTED IMAGE", 1)
        self.col_dec = self.create_column(main_frame, "DECRYPTED IMAGE", 2)

    # ================== SCROLL ==================
    def create_scrollable_image(self, parent):
        container = tk.Frame(parent, bg="white")
        container.pack(fill=tk.BOTH, expand=False, pady=4)

        canvas = tk.Canvas(container, bg="white", height=220)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        scroll_frame = tk.Frame(canvas, bg="white")
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        img_label = tk.Label(scroll_frame, bg="white")
        img_label.pack()

        return img_label, canvas

    # ================== CARD COLUMN LAYOUT ==================
    def create_column(self, parent, title, col_index):
        frame = tk.Frame(parent, bg="white", bd=1, relief=tk.FLAT)
        frame.grid(row=0, column=col_index, padx=8, sticky="nsew")
        parent.grid_columnconfigure(col_index, weight=1)

        # Header label
        tk.Label(
            frame,
            text=title,
            font=("Segoe UI", 12, "bold"),
            bg="#dfe6e9",
            fg="#2d3436",
            pady=8
        ).pack(fill=tk.X)

        # Image scrollable area
        img_label, img_canvas = self.create_scrollable_image(frame)

        # Histogram container dengan tinggi tetap
        hist_frame = tk.Frame(frame, bg="white", height=300)
        hist_frame.pack(fill=tk.X, padx=6, pady=5)
        hist_frame.pack_propagate(False)  # PENTING: Agar tinggi tetap

        # Metrics box
        metrics_box = scrolledtext.ScrolledText(frame, height=8, font=("Consolas", 9))
        metrics_box.pack(fill=tk.BOTH, expand=True, padx=6, pady=10)

        return {"img_lbl": img_label, "hist_frm": hist_frame, "txt": metrics_box}

    def load_image(self):
        file_path = filedialog.askopenfilename(filetypes=[
            ("PNG files", "*.png"),
            ("JPEG files", "*.jpg"),
            ("JPEG files", "*.jpeg"),
            ("Bitmap", "*.bmp"),
            ("All files", "*.*")
        ])
        if not file_path: return

        try:
            img = Image.open(file_path).convert('RGB')
            self.original_arr = np.array(img)
            self.encrypted_arr = None
            self.decrypted_arr = None
            
            self.display_image(img, self.col_orig["img_lbl"])
            
            # Tampilkan Entropy Original
            ent = calculate_entropy(self.original_arr)
            info = f"Ukuran: {self.original_arr.shape}\nEntropy Original: {ent:.5f}\n(Max Entropy 8-bit = 8.0)"
            self.update_metrics(self.col_orig["txt"], info)
            
            # Plot histogram ORIGINAL
            self.plot_histogram(self.original_arr, self.col_orig["hist_frm"], "Original")
            
            self.clear_column(self.col_enc)
            self.clear_column(self.col_dec)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def process_encryption(self):
        if self.original_arr is None: return
        key_input = self.key_entry.get()
        if len(key_input) < 8:
            messagebox.showwarning("Warning", "Key minimal 8 karakter!")
            return

        # Enkripsi Utama
        enc_arr, self.nonce, _ = self.chacha20_encrypt_wrapper(self.original_arr, key_input)
        self.encrypted_arr = enc_arr
        
        self.display_image(Image.fromarray(enc_arr), self.col_enc["img_lbl"])
        
        # Plot histogram ENCRYPTED
        self.plot_histogram(enc_arr, self.col_enc["hist_frm"], "Encrypted")
        
        # Hitung Metrik
        orig = self.original_arr
        enc = enc_arr
        
        metrics = f"""--- METRIK ENKRIPSI ---
Entropy Enc : {calculate_entropy(enc):.5f} (Target ~8.0)
MSE         : {calculate_mse(orig, enc):.4f}
PSNR        : {calculate_psnr(orig, enc):.4f}
NPCR        : {calculate_npcr(orig, enc):.4f} %
UACI        : {calculate_uaci(orig, enc):.4f} %
SSIM        : {calculate_ssim_custom(orig, enc):.4f} (Abs)
MSIQ (MS-SSIM): {calculate_msiq(orig, enc):.4f}
"""
        self.update_metrics(self.col_enc["txt"], metrics)

    def process_decryption(self):
        if self.encrypted_arr is None: return
        key_input = self.key_entry.get()
        
        # Validasi hash key
        if len(key_input) < 32:
            key_hash = hashlib.sha256(key_input.encode()).digest()
        else:
            key_hash = key_input[:32].encode()
            
        cipher = ChaCha20.new(key=key_hash, nonce=self.nonce)
        dec_data = cipher.decrypt(self.encrypted_arr.flatten().tobytes())
        dec_arr = np.frombuffer(dec_data, dtype=np.uint8).reshape(self.encrypted_arr.shape)
        
        self.decrypted_arr = dec_arr
        self.display_image(Image.fromarray(dec_arr), self.col_dec["img_lbl"])
        
        # Plot histogram DECRYPTED
        self.plot_histogram(dec_arr, self.col_dec["hist_frm"], "Decrypted")
        
        metrics = f"""--- HASIL DEKRIPSI ---
Entropy Dec : {calculate_entropy(dec_arr):.5f}
SSIM        : {calculate_ssim_custom(self.original_arr, dec_arr):.4f}
"""
        if np.array_equal(self.original_arr, dec_arr):
            metrics += "\n[STATUS]: BERHASIL (Sama Persis)"
        else:
            metrics += "\n[STATUS]: GAGAL (Gambar Rusak)"
            
        self.update_metrics(self.col_dec["txt"], metrics)

    def check_avalanche(self):
        """Fitur Khusus Revisi: Uji Sensitivitas Kunci"""
        if self.original_arr is None:
            messagebox.showwarning("Info", "Upload gambar dulu")
            return
        
        key_input = self.key_entry.get()
        if not key_input: return
        
        # Proses berat, beri indikator
        self.update_metrics(self.col_enc["txt"], "Sedang menghitung Avalanche Effect...\nMohon tunggu...")
        self.root.update()
        
        ae_score, k1_hex, k2_hex = calculate_avalanche_effect(self.original_arr, key_input)
        
        msg = f"""
=== AVALANCHE EFFECT (AE) KUNCI ===

1. Key Asli (Hash): 
   {k1_hex[:10]}...
   
2. Key Uji (Beda 1 bit): 
   {k2_hex[:10]}...

3. Hasil Perubahan Bit Ciphertext:
   {ae_score:.4f} %

> Teori Ideal: ~50%
> Interpretasi: Jika kita mengubah kunci hanya 1 bit, gambar berubah sebanyak {ae_score:.2f}%.
"""
        messagebox.showinfo("Hasil Avalanche Effect", msg)
        # Tulis juga di panel
        current_text = self.col_enc["txt"].get("1.0", tk.END)
        self.update_metrics(self.col_enc["txt"], current_text + "\n" + msg)

    def chacha20_encrypt_wrapper(self, img_arr, key_str):
        if len(key_str) < 32:
            key = hashlib.sha256(key_str.encode()).digest()
        else:
            key = key_str[:32].encode()
        nonce = get_random_bytes(12)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        enc = cipher.encrypt(img_arr.flatten().tobytes())
        return np.frombuffer(enc, dtype=np.uint8).reshape(img_arr.shape), nonce, key

    def display_image(self, pil_img, label):
        w, h = pil_img.size
        aspect = w/h
        tw = 500
        th = int(tw/aspect)
        resized = pil_img.resize((tw, th), Image.Resampling.LANCZOS)
        tk_img = ImageTk.PhotoImage(resized)
        label.config(image=tk_img, text="")
        label.image = tk_img

    def plot_histogram(self, img_arr, frame, title_suffix):
        """
        Menampilkan histogram RGB/Grayscale dengan Matplotlib
        """
        # Hapus widget lama
        for widget in frame.winfo_children():
            widget.destroy()
        
        # Buat figure matplotlib
        fig = plt.Figure(figsize=(6, 3.5), dpi=90)
        ax = fig.add_subplot(111)
        
        # Plot histogram berdasarkan channel
        if len(img_arr.shape) == 3:  # RGB
            colors = ['red', 'green', 'blue']
            labels = ['R', 'G', 'B']
            for i, (color, label) in enumerate(zip(colors, labels)):
                channel_data = img_arr[:, :, i].flatten()
                hist, bins = np.histogram(channel_data, bins=256, range=(0, 256))
                ax.plot(bins[:-1], hist, color=color, alpha=0.7, linewidth=1, label=label)
            ax.legend(loc='upper right', fontsize=7)
        else:  # Grayscale
            channel_data = img_arr.flatten()
            hist, bins = np.histogram(channel_data, bins=256, range=(0, 256))
            ax.plot(bins[:-1], hist, color='gray', linewidth=1)
        
        # Styling
        ax.set_title(f"Histogram - {title_suffix}", fontsize=9, fontweight='bold')
        ax.set_xlabel("Pixel Value", fontsize=7)
        ax.set_ylabel("Frequency", fontsize=7)
        ax.tick_params(labelsize=6)
        ax.grid(True, alpha=0.3, linestyle='--', linewidth=0.5)
        fig.tight_layout()
        
        # Embed ke Tkinter
        canvas = FigureCanvasTkAgg(fig, master=frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def update_metrics(self, widget, text):
        widget.config(state=tk.NORMAL)
        widget.delete(1.0, tk.END)
        widget.insert(tk.END, text)
        widget.config(state=tk.DISABLED)

    def clear_column(self, col):
        col["img_lbl"].config(image='', text="...")
        self.update_metrics(col["txt"], "")
        for w in col["hist_frm"].winfo_children():
            w.destroy()

    def reset_app(self):
        self.original_arr = None
        self.encrypted_arr = None
        self.decrypted_arr = None
        self.clear_column(self.col_orig)
        self.clear_column(self.col_enc)
        self.clear_column(self.col_dec)
        self.key_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()