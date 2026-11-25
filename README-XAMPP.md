# Menjalankan Flowaut di XAMPP

1. Salin folder ini ke `C:\\xampp\\htdocs\\flowaut`.
2. Di XAMPP Control Panel, jalankan Apache dan MySQL. Pastikan ekstensi `pdo_mysql` aktif di `C:\\xampp\\php\\php.ini`.
3. Buka `http://localhost/phpmyadmin`, pilih tab **Import**, lalu impor `flowaut.sql`. Skrip membuat database `flowaut` beserta tabel `rooms`, `files`, dan `contents`.
4. Buka `http://localhost/flowaut/`.

## Konfigurasi database

Nilai bawaan di `config/database.php` mengikuti instalasi XAMPP lokal: host `127.0.0.1`, port `3306`, database `flowaut`, user `root`, dan password kosong. Jika kredensial MySQL berbeda, atur variabel lingkungan `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, dan `DB_PASSWORD` untuk Apache.

## Dashboard super admin (demo kuliah)

Buka `http://localhost/flowaut/admin` dan masuk dengan password default `123`. Untuk demo lokal, password dapat diganti dengan mengatur variabel lingkungan Apache `SUPERADMIN_PASSWORD`. Dashboard menampilkan daftar vault dan metadata aktivitas enkripsi. Untuk uji dekripsi, pilih vault lalu masukkan password vault tersebut. Catatan, nama file, dan file hanya didekripsi di browser; dashboard tidak menyimpan password vault atau plaintext. Ganti password demo ini sebelum aplikasi dipakai di lingkungan publik.

## Penyimpanan upload

File disimpan di `storage/files/` di dalam folder proyek. Data yang disimpan adalah ciphertext hasil enkripsi browser. Direktori `storage` ditolak oleh `.htaccess`; jangan hapus aturan tersebut. Jika Apache tidak dapat menyimpan file, berikan akun yang menjalankan Apache izin **Modify** pada `C:\\xampp\\htdocs\\flowaut\\storage\\files`.

Batas aplikasi adalah 25 MB per file. Di `C:\\xampp\\php\\php.ini`, gunakan setidaknya `upload_max_filesize = 26M` dan `post_max_size = 27M`, lalu restart Apache. Storage dapat dipindahkan ke direktori lain dengan mengatur `FILE_STORAGE_PATH` untuk Apache/PHP dan memberi akun Apache izin tulis pada direktori itu.

## Catatan Apache

Pastikan `mod_rewrite` aktif dan `.htaccess` diizinkan (`AllowOverride All`) agar endpoint API dan URL `/flowaut/vault/<id>` bekerja. Gunakan HTTPS sebelum aplikasi diakses melalui jaringan publik.
