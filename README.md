# Tugas 2 Keamanan Informasi: Key Distribution Scenario (KDC, Alice, Bob) dengan AES

## Berkas

| Berkas | Isi |
|---|---|
| `aes.h` | AES-128/192/256 manual (SubBytes, ShiftRows, MixColumns, key expansion), CBC, hex, RNG, self test FIPS-197 |
| `net.h` | Pembungkus socket TCP lintas OS (Winsock dan BSD socket), protokol berbasis baris teks |
| `util.h` | Log aman-thread, split, validasi ID dan key |
| `kdc.cpp` | Program KDC (server) |
| `peer.cpp` | Program Alice dan Bob (satu program, beda ID) |
| `Makefile`, `build.bat` | Build Linux dan Windows |

## Build

Linux (Ubuntu):

    sudo apt install g++ make
    make

Windows (winlibs GCC dengan POSIX threads, sama seperti Tugas 1):

    build.bat

atau manual:

    g++ -std=c++11 -O2 -o kdc.exe kdc.cpp -lws2_32
    g++ -std=c++11 -O2 -o peer.exe peer.cpp -lws2_32

Uji kebenaran AES (vektor uji FIPS-197 untuk 128, 192, 256 bit):

    ./kdc --selftest

## Topologi 3 IP berbeda

Contoh (ganti dengan IP asli, ketiganya satu jaringan, VM memakai adapter Bridged):

| Entitas | Perangkat | IP | Perintah |
|---|---|---|---|
| KDC | VM Ubuntu 1 | 192.168.1.10 | `./kdc 5000` |
| Alice | Laptop Windows | 192.168.1.20 | `peer.exe Alice 6001 192.168.1.10 5000` |
| Bob | VM Ubuntu 2 | 192.168.1.30 | `./peer Bob 6002 192.168.1.10 5000` |

Argumen `peer`: `<ID_saya> <port_listen> <ip_kdc> <port_kdc>`.
Pastikan firewall mengizinkan port 5000 (KDC), 6001 (Alice), 6002 (Bob). Ubuntu: `sudo ufw allow 5000/tcp`.
Windows: izinkan aplikasi saat muncul dialog Windows Defender Firewall.

## Cara pakai (alur demo)

1. Di KDC, daftarkan master key (ASCII, 16/24/32 karakter, tanpa spasi):

        setkey Alice AliceMasterKey16
        setkey Bob BobMasterKeyXY16

2. Di Alice dan Bob, program meminta master key saat start (tidak ada key yang di-hardcode).
   Isi dengan key yang sama seperti yang didaftarkan di KDC.
3. Di Alice: `/connect Bob 192.168.1.30 6002`. Program menjalankan langkah (1) sampai (5) dan menampilkan
   tiap pesan beserta plaintext dan ciphertext hex.
4. Setelah muncul "autentikasi BERHASIL", ketik teks biasa lalu Enter. Pesan dikirim terenkripsi AES dengan Ks.
   Bob juga bisa mengetik balik, dan Bob juga bisa memulai sesi baru dengan `/connect Alice <ip> 6001`.

Perintah peer: `/connect`, `/setkey <key>`, `/status`, `/close`, `/help`, `/quit`.
Perintah KDC: `setkey <ID> <key>`, `delkey <ID>`, `keys`, `sessionlen <16|24|32>`, `help`, `quit`.

### Test case yang bisa didemokan tanpa restart program

* Ubah master key: `setkey Bob KeyBaruBob123456` di KDC dan `/setkey KeyBaruBob123456` di Bob, lalu `/close` dan `/connect` lagi.
* Key tidak cocok: ubah key di satu sisi saja. Hasilnya dekripsi gagal (padding tidak valid), sesi ditolak.
* Ganti ukuran AES: `sessionlen 32` di KDC, lalu `/connect` lagi (sesi memakai AES-256). Master key 24 atau 32 karakter juga diterima.
* ID tidak terdaftar: `/connect Carol ...` ditolak oleh KDC.

## Kesesuaian dengan skenario di PPT

| Langkah | Pesan | Wire format |
|---|---|---|
| 1 | A -> KDC: ID_A \|\| ID_B \|\| N1 | `KDCREQ\|Alice\|Bob\|<N1>` (plaintext) |
| 2 | KDC -> A: E(Ka,[Ks\|\|ID_A\|\|ID_B\|\|N1]) \|\| E(Kb,[Ks\|\|ID_A]) | `KDCRESP\|<hex>\|<hex>` |
| 3 | A -> B: E(Kb,[Ks\|\|ID_A]) | `STEP3\|<hex>` |
| 4 | B -> A: E(Ks,N2) | `STEP4\|<hex>` |
| 5 | A -> B: E(Ks,f(N2)), f(N2) = N2 + 1 | `STEP5\|<hex>` |
| setelah 5 | Chat dua arah, AES-CBC dengan Ks | `MSG\|<hex>` |

## Wireshark

1. Pilih interface yang dipakai koneksi antarperangkat (Wi-Fi atau Ethernet, atau adapter VM Bridged).
   Jangan loopback, karena ketiga entitas ada di IP berbeda.
2. Capture filter (opsional): `tcp port 5000 or tcp port 6001 or tcp port 6002`
3. Display filter yang berguna:

        tcp.port == 5000 || tcp.port == 6001 || tcp.port == 6002
        frame contains "KDCREQ"       (langkah 1, plaintext)
        frame contains "KDCRESP"      (langkah 2, hex)
        frame contains "STEP3" || frame contains "STEP4" || frame contains "STEP5"
        frame contains "MSG|"         (pesan AES)

4. Klik kanan paket, Follow, TCP Stream, untuk melihat seluruh alur satu koneksi. Isi `KDCREQ` terbaca jelas,
   sedangkan Ks dan isi pesan hanya tampak sebagai hex. Cocokkan hex di Wireshark dengan log `[TX]` dan `[RX]`.
