// aes.h
// Implementasi AES manual (tanpa library kriptografi) untuk Tugas 2 Keamanan Informasi.
// Mendukung kunci 128/192/256 bit (16/24/32 karakter ASCII), mode CBC, padding PKCS#7.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <mutex>
#include <iostream>
#include <stdexcept>

typedef std::vector<uint8_t> Bytes;

// ------------------------------------------------------------------
// Aritmetika GF(2^8)
// ------------------------------------------------------------------
inline uint8_t gf_xtime(uint8_t a) {
    return (uint8_t)((a << 1) ^ ((a & 0x80) ? 0x1B : 0x00));
}

inline uint8_t gf_mul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        a = gf_xtime(a);
        b >>= 1;
    }
    return r;
}

inline uint8_t rotl8(uint8_t x, int n) {
    return (uint8_t)((x << n) | (x >> (8 - n)));
}

// S-Box dibangkitkan dari definisi matematis AES:
// invers perkalian di GF(2^8) lalu transformasi affine (FIPS-197 sec. 5.1.1).
struct AesTables {
    uint8_t sbox[256];
    uint8_t inv[256];
    AesTables() {
        uint8_t p = 1, q = 1;
        do {
            // p = p * 3
            p = (uint8_t)(p ^ (p << 1) ^ ((p & 0x80) ? 0x1B : 0x00));
            // q = q / 3
            q ^= (uint8_t)(q << 1);
            q ^= (uint8_t)(q << 2);
            q ^= (uint8_t)(q << 4);
            if (q & 0x80) q ^= 0x09;
            // transformasi affine
            uint8_t x = (uint8_t)(q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4));
            sbox[p] = (uint8_t)(x ^ 0x63);
        } while (p != 1);
        sbox[0] = 0x63;
        for (int i = 0; i < 256; i++) inv[sbox[i]] = (uint8_t)i;
    }
};

inline const AesTables& aesTables() {
    static const AesTables t;
    return t;
}

// ------------------------------------------------------------------
// Blok AES
// State disimpan column-major: s[r + 4*c]
// ------------------------------------------------------------------
class AES {
public:
    explicit AES(const std::string& key) { setKey(key); }

    static bool validKeyLen(size_t n) { return n == 16 || n == 24 || n == 32; }

    void setKey(const std::string& key) {
        if (!validKeyLen(key.size())) throw std::runtime_error("panjang key AES harus 16, 24, atau 32 karakter");
        const AesTables& T = aesTables();
        int Nk = (int)key.size() / 4;
        Nr_ = Nk + 6;
        int total = 4 * (Nr_ + 1);  // jumlah word round key
        for (size_t i = 0; i < key.size(); i++) rk_[i] = (uint8_t)key[i];
        uint8_t rcon = 1;
        for (int i = Nk; i < total; i++) {
            uint8_t t[4];
            for (int j = 0; j < 4; j++) t[j] = rk_[(i - 1) * 4 + j];
            if (i % Nk == 0) {
                // RotWord, SubWord, XOR Rcon
                uint8_t t0 = t[0];
                t[0] = T.sbox[t[1]];
                t[1] = T.sbox[t[2]];
                t[2] = T.sbox[t[3]];
                t[3] = T.sbox[t0];
                t[0] ^= rcon;
                rcon = gf_xtime(rcon);
            } else if (Nk > 6 && i % Nk == 4) {
                for (int j = 0; j < 4; j++) t[j] = T.sbox[t[j]];
            }
            for (int j = 0; j < 4; j++) rk_[i * 4 + j] = (uint8_t)(rk_[(i - Nk) * 4 + j] ^ t[j]);
        }
    }

    void encryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        for (int i = 0; i < 16; i++) s[i] = in[i];
        addRoundKey(s, 0);
        for (int r = 1; r < Nr_; r++) {
            subBytes(s);
            shiftRows(s);
            mixColumns(s);
            addRoundKey(s, r);
        }
        subBytes(s);
        shiftRows(s);
        addRoundKey(s, Nr_);
        for (int i = 0; i < 16; i++) out[i] = s[i];
    }

    void decryptBlock(const uint8_t in[16], uint8_t out[16]) const {
        uint8_t s[16];
        for (int i = 0; i < 16; i++) s[i] = in[i];
        addRoundKey(s, Nr_);
        for (int r = Nr_ - 1; r >= 1; r--) {
            invShiftRows(s);
            invSubBytes(s);
            addRoundKey(s, r);
            invMixColumns(s);
        }
        invShiftRows(s);
        invSubBytes(s);
        addRoundKey(s, 0);
        for (int i = 0; i < 16; i++) out[i] = s[i];
    }

private:
    int Nr_ = 10;
    uint8_t rk_[240];

    void addRoundKey(uint8_t* s, int round) const {
        for (int i = 0; i < 16; i++) s[i] ^= rk_[round * 16 + i];
    }
    static void subBytes(uint8_t* s) {
        const AesTables& T = aesTables();
        for (int i = 0; i < 16; i++) s[i] = T.sbox[s[i]];
    }
    static void invSubBytes(uint8_t* s) {
        const AesTables& T = aesTables();
        for (int i = 0; i < 16; i++) s[i] = T.inv[s[i]];
    }
    static void shiftRows(uint8_t* s) {
        uint8_t t[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++) t[r + 4 * c] = s[r + 4 * ((c + r) % 4)];
        for (int i = 0; i < 16; i++) s[i] = t[i];
    }
    static void invShiftRows(uint8_t* s) {
        uint8_t t[16];
        for (int c = 0; c < 4; c++)
            for (int r = 0; r < 4; r++) t[r + 4 * ((c + r) % 4)] = s[r + 4 * c];
        for (int i = 0; i < 16; i++) s[i] = t[i];
    }
    static void mixColumns(uint8_t* s) {
        for (int c = 0; c < 4; c++) {
            uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
            s[4 * c]     = (uint8_t)(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
            s[4 * c + 1] = (uint8_t)(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
            s[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
            s[4 * c + 3] = (uint8_t)(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
        }
    }
    static void invMixColumns(uint8_t* s) {
        for (int c = 0; c < 4; c++) {
            uint8_t a0 = s[4 * c], a1 = s[4 * c + 1], a2 = s[4 * c + 2], a3 = s[4 * c + 3];
            s[4 * c]     = (uint8_t)(gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9));
            s[4 * c + 1] = (uint8_t)(gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13));
            s[4 * c + 2] = (uint8_t)(gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11));
            s[4 * c + 3] = (uint8_t)(gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14));
        }
    }
};

// ------------------------------------------------------------------
// Hex dan acak
// ------------------------------------------------------------------
inline std::string toHex(const Bytes& b) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(b.size() * 2);
    for (size_t i = 0; i < b.size(); i++) {
        s.push_back(d[b[i] >> 4]);
        s.push_back(d[b[i] & 15]);
    }
    return s;
}

inline int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

inline bool fromHex(const std::string& s, Bytes& out) {
    out.clear();
    if (s.size() % 2 != 0) return false;
    for (size_t i = 0; i < s.size(); i += 2) {
        int h = hexVal(s[i]), l = hexVal(s[i + 1]);
        if (h < 0 || l < 0) return false;
        out.push_back((uint8_t)(h * 16 + l));
    }
    return true;
}

inline uint64_t randomU64() {
    static std::mutex m;
    static std::mt19937_64 gen([] {
        std::random_device rd;
        uint64_t s = ((uint64_t)rd() << 32) ^ (uint64_t)rd();
        s ^= (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
        return s;
    }());
    std::lock_guard<std::mutex> l(m);
    return gen();
}

inline Bytes randomBytes(size_t n) {
    Bytes b(n);
    for (size_t i = 0; i < n; i++) b[i] = (uint8_t)(randomU64() & 0xFF);
    return b;
}

// Session key dibangkitkan dari karakter alfanumerik (ASCII) agar aman sebagai key teks.
inline std::string randomAlnum(size_t n) {
    static const char cs[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string s;
    for (size_t i = 0; i < n; i++) s.push_back(cs[randomU64() % (sizeof(cs) - 1)]);
    return s;
}

// Nonce berupa bilangan desimal (string ASCII)
inline std::string randomNonce() {
    return std::to_string((unsigned long long)(randomU64() % 4000000000ULL));
}

// ------------------------------------------------------------------
// Mode CBC + padding PKCS#7. Format keluaran: IV (16 byte) || ciphertext
// ------------------------------------------------------------------
inline Bytes cbcEncrypt(const AES& aes, const std::string& plain, const Bytes& iv) {
    Bytes data(plain.begin(), plain.end());
    uint8_t pad = (uint8_t)(16 - data.size() % 16);
    for (int i = 0; i < pad; i++) data.push_back(pad);
    Bytes out(iv);
    uint8_t prev[16];
    for (int i = 0; i < 16; i++) prev[i] = iv[i];
    for (size_t off = 0; off < data.size(); off += 16) {
        uint8_t x[16], c[16];
        for (int i = 0; i < 16; i++) x[i] = (uint8_t)(data[off + i] ^ prev[i]);
        aes.encryptBlock(x, c);
        for (int i = 0; i < 16; i++) { out.push_back(c[i]); prev[i] = c[i]; }
    }
    return out;
}

inline bool cbcDecrypt(const AES& aes, const Bytes& in, std::string& plain, std::string& err) {
    if (in.size() < 32 || in.size() % 16 != 0) { err = "panjang ciphertext tidak valid"; return false; }
    Bytes out;
    uint8_t prev[16];
    for (int i = 0; i < 16; i++) prev[i] = in[i];
    for (size_t off = 16; off < in.size(); off += 16) {
        uint8_t d[16];
        aes.decryptBlock(&in[off], d);
        for (int i = 0; i < 16; i++) { out.push_back((uint8_t)(d[i] ^ prev[i])); prev[i] = in[off + i]; }
    }
    uint8_t pad = out.back();
    if (pad < 1 || pad > 16 || pad > out.size()) { err = "padding tidak valid (key salah?)"; return false; }
    for (int i = 0; i < pad; i++)
        if (out[out.size() - 1 - i] != pad) { err = "padding tidak valid (key salah?)"; return false; }
    out.resize(out.size() - pad);
    plain.assign(out.begin(), out.end());
    return true;
}

// Pembungkus: plaintext ASCII -> hex(IV || ciphertext), IV acak baru setiap pesan
inline std::string encryptToHex(const std::string& key, const std::string& plain) {
    AES aes(key);
    return toHex(cbcEncrypt(aes, plain, randomBytes(16)));
}

inline bool decryptFromHex(const std::string& key, const std::string& hex, std::string& plain, std::string& err) {
    Bytes raw;
    if (!fromHex(hex, raw)) { err = "format hex tidak valid"; return false; }
    AES aes(key);
    return cbcDecrypt(aes, raw, plain, err);
}

// ------------------------------------------------------------------
// Self test: vektor uji FIPS-197 Appendix C
// ------------------------------------------------------------------
inline bool aesSelfTest() {
    struct V { const char* key; const char* ct; };
    const V vs[] = {
        {"000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"},
        {"000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"},
        {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"},
    };
    Bytes pt;
    fromHex("00112233445566778899aabbccddeeff", pt);
    bool all = true;
    for (int i = 0; i < 3; i++) {
        Bytes k;
        fromHex(vs[i].key, k);
        AES aes(std::string(k.begin(), k.end()));
        uint8_t c[16], p[16];
        aes.encryptBlock(&pt[0], c);
        Bytes cb(c, c + 16);
        aes.decryptBlock(c, p);
        bool ok = (toHex(cb) == vs[i].ct) && (Bytes(p, p + 16) == pt);
        std::cout << "AES-" << (k.size() * 8) << " FIPS-197: " << (ok ? "OK" : "GAGAL")
                  << "  (cipher=" << toHex(cb) << ")" << std::endl;
        all = all && ok;
    }
    std::string msg = "Halo dunia, tes CBC", back, err;
    std::string h = encryptToHex("kunci-ascii-16ch", msg);
    bool ok2 = decryptFromHex("kunci-ascii-16ch", h, back, err) && back == msg;
    std::cout << "Round trip CBC: " << (ok2 ? "OK" : "GAGAL") << std::endl;
    return all && ok2;
}
