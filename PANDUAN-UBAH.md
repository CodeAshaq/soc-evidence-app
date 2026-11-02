# Panduan mengubah aplikasi sendiri (hemat token)

## 1. Siapkan VS Code (sekali saja)
1. Pasang VS Code di komputer Windows/Mac Anda: https://code.visualstudio.com
2. Pasang ekstensi **Remote - SSH** (`ms-vscode-remote.remote-ssh`).
3. Tekan `F1` → **Remote-SSH: Connect to Host…** → ketik `user@IP-VM` → masukkan password.
4. **File → Open Folder** → pilih `/home/user/soc-evidence-app`.
5. Saat muncul "Install recommended extensions" klik **Install** (Prettier, Docker, Live Server).
   Pengaturan sudah ada di folder `.vscode/`, tidak perlu diatur manual.
6. Buka terminal bawaan: `Ctrl+`` ` (sudah berada di VM, langsung bisa `docker compose ...`).

Dengan cara ini Anda mengedit file langsung di VM. Tidak perlu scp atau unzip lagi.

## 2. Alur kerja
| Yang diubah | Cara menerapkan |
|---|---|
| `public/*` (tampilan) | Simpan → **Ctrl+F5** di browser. Tanpa build (berkat `docker-compose.override.yml`). Aktifkan sekali: `docker compose up -d` |
| `rules.json`, `.env` | Simpan → `docker compose restart` |
| `server/*.js` | Simpan → `docker compose up -d --build` |

Tekan `Ctrl+Shift+P` → **Tasks: Run Task** untuk menjalankan build, restart, log, dan cek sintaks.

## 3. Peta file: ingin ubah apa → buka file mana
| Ingin mengubah | File | Cari kata |
|---|---|---|
| Warna, font, ukuran, jarak | `public/style.css` | `:root{` (variabel warna di baris pertama) |
| Istilah/label (True positive, Terindikasi, dll.) | `public/app.js` | `const VERDICT`, `CONF`, `NARR`, `PRESETS` |
| Pilihan rentang waktu cepat | `public/app.js` | `const PRESETS` (menit, label) |
| Susunan halaman detail | `public/app.js` | `function renderDetail` |
| Tombol di banner verdict | `public/app.js` | `function verdictBanner` |
| Kolom tabel IOC / TTP | `public/app.js` | `function iocTable`, `function ttpTable` |
| Kalimat narasi analisa | `server/analyzer.js` | `narrative` |
| Pemetaan teknik MITRE otomatis | `server/analyzer.js` | `const TECH` |
| Bobot skor, ambang verdict, allowlist | `rules.json` | tanpa build, cukup restart |
| Tata letak / isi report PDF | `server/pdf.js` | `async function toPdf` |
| Warna report PDF | `server/pdf.js` | `const C`, `const TONE` |
| Interval, severity, rentang crawling | `.env` | `AUTO_*` |

## 4. Tips hemat token saat meminta bantuan Claude
- Sebutkan **satu file dan satu fungsi**: "di `public/app.js` fungsi `verdictBanner`, ubah ...". Jangan tempel seluruh proyek.
- Untuk perubahan kecil (warna, teks, urutan), ubah sendiri memakai peta di atas dengan `Ctrl+F`. Tidak perlu Claude.
- Tempel hanya potongan kode yang bermasalah dan pesan error-nya (`docker compose logs --tail=30`).
- Minta hasil berupa **potongan yang diganti**, bukan file utuh.
- Cek sintaks sebelum build ulang: `Ctrl+Shift+P` → Tasks: Run Task → **Cek sintaks JS**.
- Sebelum bereksperimen: `cp -r ~/soc-evidence-app ~/soc-evidence-app.bak`.
