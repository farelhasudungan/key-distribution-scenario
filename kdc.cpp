// kdc.cpp
// Key Distribution Center (KDC) untuk Tugas 2 Keamanan Informasi.
// Menyimpan master key tiap entitas (Alice, Bob, dst) dan membagikan session key Ks.
//
// Langkah (1) dan (2) pada skenario PPT:
//   (1) A -> KDC : ID_A || ID_B || N1
//   (2) KDC -> A : E(Ka, [Ks || ID_A || ID_B || N1]) || E(Kb, [Ks || ID_A])
//
// Format kawat (satu baris teks per pesan):
//   KDCREQ|ID_A|ID_B|N1
//   KDCRESP|<hex E(Ka,...)>|<hex E(Kb,...)>
//   KDCERR|<alasan>

#include <cstdlib>
#include <map>
#include <memory>
#include <sstream>
#include <thread>

#include "aes.h"
#include "net.h"
#include "util.h"

static std::mutex g_mtx;
static std::map<std::string, std::string> g_keys;  // ID -> master key
static size_t g_sessionLen = 16;                   // panjang Ks (16/24/32)

static void handleClient(std::shared_ptr<net::Conn> c, std::string who) {
    say("[KDC] koneksi masuk dari " + who);
    std::string line;
    while (c->recvLine(line)) {
        say("[KDC] (1) diterima dari " + who + " : " + line);
        std::vector<std::string> f = split(line, '|');
        if (f.size() != 4 || f[0] != "KDCREQ") {
            c->sendLine("KDCERR|format permintaan salah");
            say("[KDC] ditolak: format permintaan salah");
            continue;
        }
        const std::string ida = f[1], idb = f[2], n1 = f[3];
        if (!validId(ida) || !validId(idb) || !isDigits(n1)) {
            c->sendLine("KDCERR|ID atau nonce tidak valid");
            say("[KDC] ditolak: ID atau nonce tidak valid");
            continue;
        }

        std::string ka, kb;
        size_t klen;
        bool haveA, haveB;
        {
            std::lock_guard<std::mutex> l(g_mtx);
            std::map<std::string, std::string>::iterator ia = g_keys.find(ida), ib = g_keys.find(idb);
            haveA = ia != g_keys.end();
            haveB = ib != g_keys.end();
            if (haveA) ka = ia->second;
            if (haveB) kb = ib->second;
            klen = g_sessionLen;
        }
        if (!haveA || !haveB) {
            std::string why = std::string("ID belum terdaftar di KDC: ") + (!haveA ? ida : idb);
            c->sendLine("KDCERR|" + why);
            say("[KDC] ditolak: " + why);
            continue;
        }

        // Bangkitkan session key Ks (ASCII alfanumerik)
        std::string ks = randomAlnum(klen);
        std::string pA = ks + "||" + ida + "||" + idb + "||" + n1;
        std::string pB = ks + "||" + ida;
        std::string cA = encryptToHex(ka, pA);
        std::string cB = encryptToHex(kb, pB);

        say("[KDC] Ks dibangkitkan        : " + ks);
        say("[KDC] plaintext E(Ka,...)    : " + pA);
        say("[KDC] plaintext E(Kb,...)    : " + pB);
        say("[KDC] (2) E(Ka,[Ks||IDA||IDB||N1]) hex : " + cA);
        say("[KDC] (2) E(Kb,[Ks||IDA]) hex          : " + cB);
        c->sendLine("KDCRESP|" + cA + "|" + cB);
        say("[KDC] (2) dikirim ke " + who);
    }
    c->close();
    say("[KDC] koneksi " + who + " ditutup");
}

static void acceptLoop(sock_t ls) {
    while (true) {
        std::string addr;
        sock_t s = net::acceptOne(ls, addr);
        if (s == BAD_SOCK) break;
        std::shared_ptr<net::Conn> c(new net::Conn());
        c->s = s;
        std::thread(handleClient, c, addr).detach();
    }
}

static void help() {
    say("Perintah KDC:\n"
        "  setkey <ID> <key>   daftarkan/ubah master key entitas (mis. setkey Alice 1234567890abcdef)\n"
        "  delkey <ID>         hapus entitas\n"
        "  keys                tampilkan entitas terdaftar\n"
        "  sessionlen <n>      panjang session key Ks: 16, 24, atau 32 (default 16)\n"
        "  help                bantuan\n"
        "  quit                keluar");
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "--selftest") return aesSelfTest() ? 0 : 1;
    int port = 5000;
    if (argc >= 2) port = std::atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        std::cerr << "Pemakaian: kdc [port]   (default 5000)\n       kdc --selftest" << std::endl;
        return 1;
    }
    if (!net::init()) { std::cerr << "Gagal inisialisasi jaringan" << std::endl; return 1; }
    std::string err;
    sock_t ls = net::listenOn(port, err);
    if (ls == BAD_SOCK) { std::cerr << "Gagal listen: " << err << std::endl; return 1; }
    std::thread(acceptLoop, ls).detach();

    say("=== KDC aktif di port " + std::to_string(port) + " (semua interface) ===");
    say("Daftarkan master key Alice dan Bob dulu, contoh:");
    say("  setkey Alice <16 karakter ASCII>");
    say("  setkey Bob   <16 karakter ASCII>");
    help();

    std::string line;
    while (std::getline(std::cin, line)) {
        line = trim(line);
        if (line.empty()) continue;
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        if (cmd == "setkey") {
            std::string id, key;
            iss >> id >> key;
            if (!validId(id)) { say("ID tidak valid (huruf/angka/underscore, maks 16)"); continue; }
            if (!validKey(key)) { say(std::string("Key ditolak: ") + keyRule()); continue; }
            {
                std::lock_guard<std::mutex> l(g_mtx);
                g_keys[id] = key;
            }
            say("Master key untuk " + id + " diset: " + key);
        } else if (cmd == "delkey") {
            std::string id;
            iss >> id;
            std::lock_guard<std::mutex> l(g_mtx);
            say(g_keys.erase(id) ? "Entitas " + id + " dihapus" : "Entitas tidak ditemukan");
        } else if (cmd == "keys") {
            std::lock_guard<std::mutex> l(g_mtx);
            if (g_keys.empty()) say("(belum ada entitas terdaftar)");
            for (std::map<std::string, std::string>::iterator it = g_keys.begin(); it != g_keys.end(); ++it)
                say("  " + it->first + " : " + it->second);
            say("  panjang Ks: " + std::to_string(g_sessionLen));
        } else if (cmd == "sessionlen") {
            int n = 0;
            iss >> n;
            if (n == 16 || n == 24 || n == 32) {
                std::lock_guard<std::mutex> l(g_mtx);
                g_sessionLen = (size_t)n;
                say("Panjang Ks diset " + std::to_string(n));
            } else {
                say("Nilai harus 16, 24, atau 32");
            }
        } else if (cmd == "help") {
            help();
        } else if (cmd == "quit" || cmd == "exit") {
            break;
        } else {
            say("Perintah tidak dikenal. Ketik 'help'.");
        }
    }
    return 0;
}
