// util.h
// Fungsi bantu: log aman-thread, split string, validasi ID dan key.
#pragma once
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

inline std::mutex& outMutex() {
    static std::mutex m;
    return m;
}

inline void say(const std::string& s) {
    std::lock_guard<std::mutex> l(outMutex());
    std::cout << s << std::endl;
}

inline std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> v;
    std::string cur;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] == d) { v.push_back(cur); cur.clear(); }
        else cur.push_back(s[i]);
    }
    v.push_back(cur);
    return v;
}

// split dengan pemisah string (dipakai untuk operator konkatenasi "||")
inline std::vector<std::string> splitStr(const std::string& s, const std::string& d) {
    std::vector<std::string> v;
    size_t start = 0, pos;
    while ((pos = s.find(d, start)) != std::string::npos) {
        v.push_back(s.substr(start, pos - start));
        start = pos + d.size();
    }
    v.push_back(s.substr(start));
    return v;
}

inline std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    return s.substr(a, b - a);
}

inline bool isDigits(const std::string& s) {
    if (s.empty() || s.size() > 18) return false;
    for (size_t i = 0; i < s.size(); i++)
        if (s[i] < '0' || s[i] > '9') return false;
    return true;
}

// ID entitas: 1..16 karakter huruf/angka/underscore
inline bool validId(const std::string& id) {
    if (id.empty() || id.size() > 16) return false;
    for (size_t i = 0; i < id.size(); i++) {
        char c = id[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return false;
    }
    return true;
}

// Key AES: ASCII tercetak tanpa spasi (0x21..0x7E), panjang 16/24/32 karakter
inline bool validKey(const std::string& k) {
    if (!(k.size() == 16 || k.size() == 24 || k.size() == 32)) return false;
    for (size_t i = 0; i < k.size(); i++)
        if ((unsigned char)k[i] < 0x21 || (unsigned char)k[i] > 0x7E) return false;
    return true;
}

inline const char* keyRule() {
    return "key harus ASCII tercetak tanpa spasi, panjang 16/24/32 karakter (AES-128/192/256)";
}
