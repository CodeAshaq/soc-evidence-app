# SOC Evidence Collector

Aplikasi web untuk mengumpulkan evidence dari alert Elastic Security (IP, port, host, user, proses, hash, event terkait), melakukan triage, dan memvalidasi IOC. Struktur dan daftar library lengkap ada di `docs/architecture.html`.

## Menjalankan

Butuh Node.js 18 atau lebih baru.

```bash
npm install
cp .env.example .env      # isi koneksi Elasticsearch
npm start                 # buka http://127.0.0.1:3000
```

Coba dulu tanpa Elasticsearch (data contoh):

```bash
npm run demo
```

## Konfigurasi minimum (`.env`)

```
ES_NODE=https://elasticsearch.contoh.local:9200
ES_API_KEY=<API key read-only>
ES_CA_CERT=/path/ke/http_ca.crt
ES_EVENT_INDEX=logs-fortinet*,logs-sangfor*,logs-o365*,logs-m365_defender*
```

API key sebaiknya read-only pada `.alerts-security.alerts-*` dan index log di atas. Nama index log sesuaikan dengan data stream pada cluster Anda.

Opsional: `VT_API_KEY`, `ABUSEIPDB_API_KEY` (validasi IOC), `KIBANA_URL` + `KIBANA_API_KEY` (ubah status alert), `APP_TOKEN` (proteksi akses).

## Catatan keamanan

- Jangan membuka aplikasi ke jaringan tanpa `APP_TOKEN` atau reverse proxy HTTPS + autentikasi.
- IP privat tidak pernah dikirim ke layanan threat intel. Domain/URL internal bisa terkirim bila terdeteksi sebagai IOC; tinjau sebelum mengaktifkan API key.
- Jangan gunakan `ES_TLS_REJECT_UNAUTHORIZED=false` di produksi.
