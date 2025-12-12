
# ChaCha20 Image Encryption Desktop App 🔐

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Educational-orange)

A desktop-based application for encrypting and decrypting images using the **ChaCha20 Stream Cipher** algorithm. This project was developed to fulfill the **Cryptography** course assignment.

The application provides a graphical interface (GUI) to visualize the encryption process, analyze image histograms, and calculate cryptographic quality metrics (MSE, PSNR, SSIM, Entropy, etc.).




## ✨ Features

* **User-Friendly GUI**: Built with Python `tkinter` for easy interaction.
* **ChaCha20 Algorithm**: Secure stream cipher implementation using `pycryptodome`.
* **Visual Analysis**:
    * Side-by-side comparison (Original vs Encrypted vs Decrypted).
    * Real-time RGB Histogram plotting.
* **Comprehensive Cryptographic Metrics**:
    * **MSE & RMSE**: Mean Squared Error analysis.
    * **PSNR**: Peak Signal-to-Noise Ratio.
    * **SSIM & MS-SSIM (MSIQ)**: Structural Similarity Index (Single & Multi-Scale).
    * **Entropy**: To measure the randomness of the encrypted image.
    * **NPCR & UACI**: Sensitivity analysis metrics.


## 🛠️ Requirements

Ensure you have **Python 3.x** installed on your machine.

### Dependencies
* `pycryptodome`: For the ChaCha20 algorithm.
* `scikit-image`: For calculating SSIM and other image metrics.
* `pillow`: For image processing (PIL).
* `matplotlib`: For plotting histograms.
* `numpy`: For numerical calculations.
* `tkinter`: Standard Python GUI library (usually included with Python).


## 🚀 How to Run

Follow these steps to set up and run the application:

### 1. Clone the Repository
```bash
git clone [https://github.com/username/project-repo-name.git](https://github.com/username/project-repo-name.git)
cd project-repo-name
````

### 2\. Install Dependencies

It is recommended to use a virtual environment, but you can install directly:

```bash
pip install pycryptodome scikit-image pillow matplotlib numpy
```

### 3\. Run the Application

```bash
python app.py
```


## 📊 Understanding the Metrics

This application calculates several metrics to validate the encryption quality:

| Metric | Description | Desired Result for Encryption |
| :--- | :--- | :--- |
| **Entropy** | Measures randomness. | Should be close to **8.0** (max randomness). |
| **SSIM** | Structural Similarity. | Should be close to **0** (no similarity to original). |
| **PSNR** | Peak Signal-to-Noise Ratio. | Should be **low** for encryption (high noise). |
| **MSE** | Mean Squared Error. | Should be **high** (large difference). |
| **NPCR/UACI** | Sensitivity to key changes. | High percentage indicates good diffusion. |


<!-- ## 👤 Author -->
<!-- 
  * **Name**: [Nama Kamu]
  * **NIM**: [NIM Kamu]
  * **University**: [Nama Kampus] -->


> **Note**: This application is for educational purposes only.

