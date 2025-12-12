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
# 1. LOGIKA METRIK (TIDAK BERUBAH)
# ==============================================================================

def calculate_mse(img1, img2):
    return np.mean((img1.astype(float) - img2.astype(float)) ** 2)

def calculate_rmse(img1, img2):
    return np.sqrt(calculate_mse(img1, img2))

def calculate_psnr(img1, img2):
    mse = calculate_mse(img1, img2)
    if mse == 0: return 100.0 
    max_pixel = 255.0
    return 20 * np.log10(max_pixel / np.sqrt(mse))

def calculate_npcr(img1, img2):
    return (np.sum(img1 != img2) / img1.size) * 100

def calculate_uaci(img1, img2):
    diff = np.abs(img1.astype(float) - img2.astype(float))
    return (np.sum(diff) / (img1.size * 255)) * 100

def calculate_entropy(img):
    flat_img = img.flatten()
    hist, _ = np.histogram(flat_img, bins=256, range=(0, 256))
    prob = hist / hist.sum()
    prob = prob[prob > 0]
    entropy = -np.sum(prob * np.log2(prob))
    return abs(entropy)

def calculate_ssim_custom(img1, img2):
    if len(img1.shape) == 3:
        val = ssim(img1, img2, channel_axis=2, data_range=255)
    else:
        val = ssim(img1, img2, data_range=255)
    return abs(val)

def calculate_msiq(img1, img2):
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
            
    return abs(total_score / steps)

def calculate_avalanche_effect(img_original, key_str):
    if len(key_str) < 32:
        key1 = hashlib.sha256(key_str.encode()).digest()
    else:
        key1 = key_str[:32].encode()
        
    key_list = bytearray(key1)
    key_list[-1] = key_list[-1] ^ 1 
    key2 = bytes(key_list)
    
    nonce = b'\x00' * 12 
    
    cipher1 = ChaCha20.new(key=key1, nonce=nonce)
    enc1 = cipher1.encrypt(img_original.flatten().tobytes())
    
    cipher2 = ChaCha20.new(key=key2, nonce=nonce)
    enc2 = cipher2.encrypt(img_original.flatten().tobytes())
    
    arr1 = np.frombuffer(enc1, dtype=np.uint8)
    arr2 = np.frombuffer(enc2, dtype=np.uint8)
    
    bits1 = np.unpackbits(arr1)
    bits2 = np.unpackbits(arr2)
    
    diff_bits = np.sum(bits1 != bits2)
    total_bits = bits1.size
    
    ae_score = (diff_bits / total_bits) * 100
    return ae_score, key1.hex(), key2.hex()

# ==============================================================================
# 2. APLIKASI GUI (TKINTER) - REVISI SCROLLABLE
# ==============================================================================

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("ChaCha20 Image Encryption (Scrollable UI)")
        self.root.geometry("1400x900")
        self.root.configure(bg="#f5f6fa")
        # self.root.state('zoomed') # Opsional: Fullscreen

        self.original_arr = None
        self.encrypted_arr = None
        self.decrypted_arr = None
        self.nonce = None
        
        self.setup_ui()

    def setup_ui(self):
        # ---------------------------------------------------------
        # 1. MEMBUAT STRUKTUR SCROLLABLE (Canvas Wrapper)
        # ---------------------------------------------------------
        
        # Container utama
        main_container = tk.Frame(self.root, bg="#f5f6fa")
        main_container.pack(fill=tk.BOTH, expand=True)

        # Canvas untuk area scroll
        my_canvas = tk.Canvas(main_container, bg="#f5f6fa")
        my_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Scrollbar Vertikal
        my_scrollbar = tk.Scrollbar(main_container, orient=tk.VERTICAL, command=my_canvas.yview)
        my_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Konfigurasi Canvas
        my_canvas.configure(yscrollcommand=my_scrollbar.set)
        my_canvas.bind('<Configure>', lambda e: my_canvas.configure(scrollregion=my_canvas.bbox("all")))

        # Frame KONTEN (Semua widget akan masuk ke sini, bukan ke self.root)
        self.scrollable_content = tk.Frame(my_canvas, bg="#f5f6fa")

        # Masukkan Frame Konten ke dalam Canvas Window
        canvas_window = my_canvas.create_window((0, 0), window=self.scrollable_content, anchor="nw")

        # Trik agar Frame Konten melebar mengikuti lebar Canvas (Responsif width)
        def _configure_frame_width(event):
            canvas_width = event.width
            my_canvas.itemconfig(canvas_window, width=canvas_width)

        my_canvas.bind('<Configure>', _configure_frame_width)

        # Binding Mousewheel agar bisa scroll pakai mouse
        def _on_mousewheel(event):
            my_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        # Bind mousewheel ke canvas dan root
        my_canvas.bind_all("<MouseWheel>", _on_mousewheel)

        # ---------------------------------------------------------
        # 2. ISI WIDGET (Parent diganti ke self.scrollable_content)
        # ---------------------------------------------------------

        # ================= HEADER =================
        header = tk.Frame(self.scrollable_content, bg="#2d3436", height=60)
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
        control_frame = tk.Frame(self.scrollable_content, bg="#ffffff", bd=1, relief=tk.FLAT)
        control_frame.pack(fill=tk.X, padx=12, pady=10, ipady=6)

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
        main_frame = tk.Frame(self.scrollable_content, bg="#f5f6fa")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)
        main_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self.col_orig = self.create_column(main_frame, "ORIGINAL IMAGE", 0)
        self.col_enc = self.create_column(main_frame, "ENCRYPTED IMAGE", 1)
        self.col_dec = self.create_column(main_frame, "DECRYPTED IMAGE", 2)
        
        # Tambahan padding bawah agar tidak mentok saat scroll paling bawah
        tk.Label(self.scrollable_content, text="", bg="#f5f6fa", height=2).pack()


    # ================== SCROLLABLE IMAGE PREVIEW ==================
    def create_scrollable_image(self, parent):
        # Fungsi ini untuk scroll gambar individual (preview gambar)
        container = tk.Frame(parent, bg="white")
        container.pack(fill=tk.BOTH, expand=False, pady=4)

        canvas = tk.Canvas(container, bg="white", height=250)  # Height preview gambar
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind('<Configure>', lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        scroll_frame = tk.Frame(canvas, bg="white")
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")

        img_label = tk.Label(scroll_frame, bg="white")
        img_label.pack()
        
        # Binding mousewheel khusus untuk area gambar ini jika pointer ada di atasnya
        def _on_img_mousewheel(event):
             canvas.yview_scroll(int(-1*(event.delta/120)), "units")
             return "break" # Mencegah scroll root ikut bergerak

        canvas.bind("<MouseWheel>", _on_img_mousewheel)

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

        # Histogram container
        hist_frame = tk.Frame(frame, bg="white")
        hist_frame.pack(fill=tk.X, padx=6, pady=5)

        # Metrics box
        metrics_box = scrolledtext.ScrolledText(frame, height=18, font=("Consolas", 9))
        metrics_box.pack(fill=tk.BOTH, expand=True, padx=6, pady=10)

        return {"img_lbl": img_label, "hist_frm": hist_frame, "txt": metrics_box}

    # ========================================================
    # LOGIC FUNGSI (TIDAK BERUBAH)
    # ========================================================
 
    def load_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not file_path: return

        try:
            img = Image.open(file_path).convert('RGB')
            self.original_arr = np.array(img)
            self.encrypted_arr = None
            self.decrypted_arr = None
            
            self.display_image(img, self.col_orig["img_lbl"])
            
            ent = calculate_entropy(self.original_arr)
            info = f"Ukuran: {self.original_arr.shape}\nEntropy Original: {ent:.5f}\n(Max Entropy 8-bit = 8.0)"
            self.update_metrics(self.col_orig["txt"], info)
            
            self.plot_histogram(self.original_arr, self.col_orig["hist_frm"], "red")
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

        enc_arr, self.nonce, _ = self.chacha20_encrypt_wrapper(self.original_arr, key_input)
        self.encrypted_arr = enc_arr
        
        self.display_image(Image.fromarray(enc_arr), self.col_enc["img_lbl"])
        self.plot_histogram(enc_arr, self.col_enc["hist_frm"], "blue")
        
        orig = self.original_arr
        enc = enc_arr
        
        metrics = f"""--- METRIK ENKRIPSI ---
Entropy Enc : {calculate_entropy(enc):.5f}
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
        
        if len(key_input) < 32:
            key_hash = hashlib.sha256(key_input.encode()).digest()
        else:
            key_hash = key_input[:32].encode()
            
        cipher = ChaCha20.new(key=key_hash, nonce=self.nonce)
        dec_data = cipher.decrypt(self.encrypted_arr.flatten().tobytes())
        dec_arr = np.frombuffer(dec_data, dtype=np.uint8).reshape(self.encrypted_arr.shape)
        
        self.decrypted_arr = dec_arr
        self.display_image(Image.fromarray(dec_arr), self.col_dec["img_lbl"])
        self.plot_histogram(dec_arr, self.col_dec["hist_frm"], "green")
        
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
        if self.original_arr is None:
            messagebox.showwarning("Info", "Upload gambar dulu")
            return
        
        key_input = self.key_entry.get()
        if not key_input: return
        
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
"""
        messagebox.showinfo("Hasil Avalanche Effect", msg)
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

    # Helpers UI (Resize Image for Preview)
    def display_image(self, pil_img, label):
        w, h = pil_img.size
        # Batasi lebar preview
        tw = 350
        # Hitung aspect ratio
        aspect = w/h
        th = int(tw/aspect)
        
        resized = pil_img.resize((tw, th), Image.Resampling.LANCZOS)
        tk_img = ImageTk.PhotoImage(resized)
        label.config(image=tk_img, text="")
        label.image = tk_img

    def plot_histogram(self, img_arr, frame, color):
        for w in frame.winfo_children(): w.destroy()
        fig = plt.Figure(figsize=(4, 2), dpi=100)
        ax = fig.add_subplot(111)
        if len(img_arr.shape) == 3:
            for i, c in enumerate(['r','g','b']):
                h, b = np.histogram(img_arr[:,:,i].flatten(), bins=256, range=(0,256))
                ax.plot(b[:-1], h, color=c, alpha=0.7)
        else:
            h, b = np.histogram(img_arr.flatten(), bins=256, range=(0,256))
            ax.plot(b[:-1], h, color='gray')
        ax.set_title("Histogram", fontsize=8)
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
        for w in col["hist_frm"].winfo_children(): w.destroy()

    def reset_app(self):
        self.original_arr = None
        self.encrypted_arr = None
        self.clear_column(self.col_orig)
        self.clear_column(self.col_enc)
        self.clear_column(self.col_dec)
        self.key_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()