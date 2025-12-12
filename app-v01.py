import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from tkinter import ttk
import numpy as np
from PIL import Image, ImageTk
import io
import hashlib
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from skimage.metrics import structural_similarity as ssim
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ==============================================================================
# 1. LOGIKA METRIK & KRIPTOGRAFI (Sama seperti revisi terakhir)
# ==============================================================================

def calculate_mse(img1, img2):
    return np.mean((img1.astype(float) - img2.astype(float)) ** 2)

def calculate_rmse(img1, img2):
    return np.sqrt(calculate_mse(img1, img2))

def calculate_psnr(img1, img2):
    mse = calculate_mse(img1, img2)
    if mse == 0: return 99.9999
    return 20 * np.log10(255.0 / np.sqrt(mse))

def calculate_npcr(img1, img2):
    return (np.sum(img1 != img2) / img1.size) * 100

def calculate_uaci(img1, img2):
    diff = np.abs(img1.astype(float) - img2.astype(float))
    return (np.sum(diff) / (img1.size * 255)) * 100

def calculate_entropy(img):
    hist, _ = np.histogram(img.flatten(), bins=256, range=(0, 256))
    prob = hist / hist.sum()
    prob = prob[prob > 0]
    return -np.sum(prob * np.log2(prob))

def calculate_ncc(img1, img2):
    f1, f2 = img1.flatten().astype(float), img2.flatten().astype(float)
    m1, m2 = f1.mean(), f2.mean()
    num = np.sum((f1 - m1) * (f2 - m2))
    den = np.sqrt(np.sum((f1 - m1)**2) * np.sum((f2 - m2)**2))
    return 0 if den == 0 else num / den

def calculate_nc(img1, img2):
    f1, f2 = img1.flatten().astype(float), img2.flatten().astype(float)
    num = np.sum(f1 * f2)
    den = np.sqrt(np.sum(f1**2) * np.sum(f2**2))
    return 0 if den == 0 else num / den

def calculate_ssim_custom(img1, img2):
    if len(img1.shape) == 3:
        return ssim(img1, img2, channel_axis=2, data_range=255)
    return ssim(img1, img2, data_range=255)

def calculate_msiq(img1, img2):
    """Implementasi MS-SSIM sederhana (Multi-Scale) sesuai revisi."""
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
            
    return total_score / steps

def calculate_nice(img1, img2):
    return abs(calculate_entropy(img1) - calculate_entropy(img2)) / 8.0

# --- FUNGSI KRIPTO ---
def chacha20_encrypt(image_array, key_str):
    if len(key_str) < 32:
        key = hashlib.sha256(key_str.encode()).digest()
    else:
        key = key_str[:32].encode()
    
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    encrypted_data = cipher.encrypt(image_array.flatten().tobytes())
    return np.frombuffer(encrypted_data, dtype=np.uint8).reshape(image_array.shape), nonce, key

def chacha20_decrypt(encrypted_array, key_bytes, nonce):
    cipher = ChaCha20.new(key=key_bytes, nonce=nonce)
    decrypted_data = cipher.decrypt(encrypted_array.flatten().tobytes())
    return np.frombuffer(decrypted_data, dtype=np.uint8).reshape(encrypted_array.shape)

# ==============================================================================
# 2. APLIKASI GUI (TKINTER)
# ==============================================================================

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Aplikasi Enkripsi Gambar ChaCha20 (Desktop)")
        self.root.geometry("1300x850")
        self.root.state('zoomed') # Fullscreen windowed

        # STATE VARIABLES
        self.original_arr = None
        self.encrypted_arr = None
        self.decrypted_arr = None
        self.nonce = None
        self.key_bytes = None # Kunci yang sudah di-hash/encode

        self.setup_ui()

    def setup_ui(self):
        # --- FRAME CONTROLS (ATAS) ---
        control_frame = tk.Frame(self.root, bg="#f0f0f0", bd=2, relief=tk.GROOVE)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(control_frame, text="Key (min 8 char):", bg="#f0f0f0", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=5)
        self.key_entry = tk.Entry(control_frame, show="*", width=30)
        self.key_entry.pack(side=tk.LEFT, padx=5)

        tk.Button(control_frame, text="1. Upload Gambar", command=self.load_image, bg="#3498db", fg="white").pack(side=tk.LEFT, padx=10)
        tk.Button(control_frame, text="2. Enkripsi", command=self.process_encryption, bg="#e74c3c", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="3. Dekripsi", command=self.process_decryption, bg="#2ecc71", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(control_frame, text="Reset", command=self.reset_app, bg="gray", fg="white").pack(side=tk.RIGHT, padx=10)

        # --- FRAME UTAMA (TENGAH) ---
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Bagi menjadi 3 Kolom (Original, Encrypted, Decrypted)
        self.col_orig = self.create_column(main_frame, "ORIGINAL", 0)
        self.col_enc = self.create_column(main_frame, "ENCRYPTED", 1)
        self.col_dec = self.create_column(main_frame, "DECRYPTED", 2)

    def create_column(self, parent, title, col_index):
        frame = tk.Frame(parent, bd=1, relief=tk.RIDGE)
        frame.grid(row=0, column=col_index, sticky="nsew", padx=2)
        parent.grid_columnconfigure(col_index, weight=1)

        # Judul
        tk.Label(frame, text=title, font=("Arial", 12, "bold"), bg="#ddd").pack(fill=tk.X)

        # Tempat Gambar
        img_label = tk.Label(frame, text="Belum ada gambar", bg="white", height=15)
        img_label.pack(fill=tk.X, padx=5, pady=5)
        
        # Tempat Histogram
        hist_frame = tk.Frame(frame, height=200)
        hist_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Tempat Metrics
        metrics_text = scrolledtext.ScrolledText(frame, height=15, font=("Consolas", 9))
        metrics_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        return {"img_lbl": img_label, "hist_frm": hist_frame, "txt": metrics_text}

    # --- LOGIKA UI ---

    def load_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not file_path:
            return

        try:
            img = Image.open(file_path).convert('RGB')
            self.original_arr = np.array(img)
            
            # Reset state lain
            self.encrypted_arr = None
            self.decrypted_arr = None
            
            # Tampilkan Gambar Original
            self.display_image(img, self.col_orig["img_lbl"])
            
            # Hitung & Tampilkan Metrik Awal (Termasuk Entropy Original - REVISI)
            ent = calculate_entropy(self.original_arr)
            info = f"Dimensi: {self.original_arr.shape}\nEntropy Original: {ent:.4f}\n"
            self.update_metrics(self.col_orig["txt"], info)
            
            # Tampilkan Histogram Original
            self.plot_histogram(self.original_arr, self.col_orig["hist_frm"], "red")

            # Bersihkan kolom lain
            self.clear_column(self.col_enc)
            self.clear_column(self.col_dec)

        except Exception as e:
            messagebox.showerror("Error", f"Gagal memuat gambar: {str(e)}")

    def process_encryption(self):
        if self.original_arr is None:
            messagebox.showwarning("Peringatan", "Upload gambar dulu!")
            return
        
        key_input = self.key_entry.get()
        if len(key_input) < 8:
            messagebox.showwarning("Peringatan", "Key minimal 8 karakter!")
            return

        try:
            # Proses Enkripsi
            enc_arr, nonce, key_bytes = chacha20_encrypt(self.original_arr, key_input)
            self.encrypted_arr = enc_arr
            self.nonce = nonce
            self.key_bytes = key_bytes

            # Tampilkan Gambar
            self.display_image(Image.fromarray(enc_arr), self.col_enc["img_lbl"])
            self.plot_histogram(enc_arr, self.col_enc["hist_frm"], "blue")

            # Hitung Metrics (Sesuai Revisi: Tidak ada Entropy Original disini)
            orig = self.original_arr
            enc = self.encrypted_arr
            
            metrics = f"""--- ANALISIS ENKRIPSI ---
MSE  : {calculate_mse(orig, enc):.4f}
RMSE : {calculate_rmse(orig, enc):.4f}
PSNR : {calculate_psnr(orig, enc):.4f}
SSIM : {calculate_ssim_custom(orig, enc):.4f}
MSIQ : {calculate_msiq(orig, enc):.4f} (Multi-Scale)
NPCR : {calculate_npcr(orig, enc):.4f} %
UACI : {calculate_uaci(orig, enc):.4f} %
NCC  : {calculate_ncc(orig, enc):.4f}
NC   : {calculate_nc(orig, enc):.4f}
NICE : {calculate_nice(orig, enc):.4f}
Ent. Enc: {calculate_entropy(enc):.4f}
"""
            self.update_metrics(self.col_enc["txt"], metrics)

        except Exception as e:
            messagebox.showerror("Error", f"Enkripsi Gagal: {str(e)}")

    def process_decryption(self):
        if self.encrypted_arr is None:
            messagebox.showwarning("Peringatan", "Lakukan enkripsi dulu!")
            return

        key_input = self.key_entry.get()
        # Validasi key sederhana (membandingkan hash input dengan key tersimpan)
        input_key_hash = hashlib.sha256(key_input.encode()).digest() if len(key_input) < 32 else key_input[:32].encode()
        
        # Di dunia nyata kita tidak menyimpan key_bytes di memori app seperti ini untuk validasi,
        # tapi untuk simulasi ini kita cek apakah key-nya cocok.
        # ChaCha20 tidak akan error jika key salah, hasilnya cuma acak.
        # Tapi disini kita biarkan user melihat hasilnya walau salah (sesuai sifat stream cipher).

        try:
            dec_arr = chacha20_decrypt(self.encrypted_arr, input_key_hash, self.nonce)
            self.decrypted_arr = dec_arr

            self.display_image(Image.fromarray(dec_arr), self.col_dec["img_lbl"])
            self.plot_histogram(dec_arr, self.col_dec["hist_frm"], "green")

            # Metrics Validasi
            orig = self.original_arr
            dec = dec_arr
            
            metrics = f"""--- ANALISIS DEKRIPSI ---
MSE  : {calculate_mse(orig, dec):.4f}
PSNR : {calculate_psnr(orig, dec):.4f}
SSIM : {calculate_ssim_custom(orig, dec):.4f}
NCC  : {calculate_ncc(orig, dec):.4f}
Ent. Dec: {calculate_entropy(dec):.4f}
"""
            # Cek keberhasilan visual
            if np.array_equal(orig, dec):
                metrics += "\n[STATUS]: SUKSES SEMPURNA (100% Mirip)"
            else:
                metrics += "\n[STATUS]: GAGAL / KEY SALAH"

            self.update_metrics(self.col_dec["txt"], metrics)

        except Exception as e:
            messagebox.showerror("Error", f"Dekripsi Gagal: {str(e)}")

    # --- HELPERS ---
    def display_image(self, pil_img, label_widget):
        # Resize agar muat di GUI
        w, h = pil_img.size
        aspect = w / h
        target_w = 300
        target_h = int(target_w / aspect)
        
        resized = pil_img.resize((target_w, target_h), Image.Resampling.LANCZOS)
        tk_img = ImageTk.PhotoImage(resized)
        
        label_widget.config(image=tk_img, text="")
        label_widget.image = tk_img # Keep reference

    def update_metrics(self, text_widget, text):
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, text)
        text_widget.config(state=tk.DISABLED)

    def plot_histogram(self, img_arr, frame_widget, color_code):
        # Bersihkan histogram lama jika ada
        for widget in frame_widget.winfo_children():
            widget.destroy()

        fig = plt.Figure(figsize=(4, 2.5), dpi=100)
        ax = fig.add_subplot(111)
        
        if len(img_arr.shape) == 3:
            for i, c in enumerate(['r', 'g', 'b']):
                hist, bins = np.histogram(img_arr[:,:,i].flatten(), bins=256, range=(0,256))
                ax.plot(bins[:-1], hist, color=c, alpha=0.7, linewidth=1)
        else:
            hist, bins = np.histogram(img_arr.flatten(), bins=256, range=(0,256))
            ax.plot(bins[:-1], hist, color='gray')
            
        ax.set_title("Histogram", fontsize=8)
        ax.tick_params(axis='both', which='major', labelsize=6)
        ax.grid(True, alpha=0.2)
        plt.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=frame_widget)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def clear_column(self, col_dict):
        col_dict["img_lbl"].config(image='', text="Menunggu proses...")
        col_dict["txt"].config(state=tk.NORMAL)
        col_dict["txt"].delete(1.0, tk.END)
        col_dict["txt"].config(state=tk.DISABLED)
        for widget in col_dict["hist_frm"].winfo_children():
            widget.destroy()
            
    def reset_app(self):
        self.original_arr = None
        self.encrypted_arr = None
        self.decrypted_arr = None
        self.key_entry.delete(0, tk.END)
        self.clear_column(self.col_orig)
        self.clear_column(self.col_enc)
        self.clear_column(self.col_dec)
        self.col_orig["img_lbl"].config(text="Belum ada gambar")

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()