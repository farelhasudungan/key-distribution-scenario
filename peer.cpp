// peer.cpp
// Program untuk Alice dan Bob (satu program yang sama, beda ID).
// Peer bisa menjadi Initiator (memulai skenario lewat /connect) maupun Responder
// (menerima koneksi). Setelah langkah ke-5, pesan dikirim dua arah memakai AES-CBC
// dengan session key Ks dari KDC.
//
// Skenario (PPT "Key Distribution Scenario"):
//   (1) A -> KDC : ID_A || ID_B || N1
//   (2) KDC -> A : E(Ka,[Ks||ID_A||ID_B||N1]) || E(Kb,[Ks||ID_A])
//   (3) A -> B   : E(Kb,[Ks||ID_A])
//   (4) B -> A   : E(Ks,N2)
//   (5) A -> B   : E(Ks,f(N2))        dengan f(N2) = N2 + 1
//
// Format kawat (satu baris teks per pesan):
//   KDCREQ|ID_A|ID_B|N1           (langkah 1, ke KDC)
//   KDCRESP|hexA|hexB             (langkah 2, dari KDC)
//   STEP3|hex                     (langkah 3)
//   STEP4|hex                     (langkah 4)
//   STEP5|hex                     (langkah 5)
//   AUTH|OK  atau  AUTH|FAIL|... (konfirmasi hasil autentikasi dari B)
//   MSG|hex                       (pesan chat terenkripsi AES)
//   BYE                           (akhiri sesi)

#include <cstdlib>
#include <memory>
#include <sstream>
#include <thread>

#include "aes.h"
#include "net.h"
#include "util.h"

struct Session {
    std::shared_ptr<net::Conn> conn;
    std::string ks;      // session key (ASCII)
    std::string peerId;  // ID lawan bicara
};

static std::string g_myId;
static std::string g_kdcHost;
static int g_kdcPort = 5000;
static std::string g_master;  // master key milik entitas ini (Ka untuk Alice, Kb untuk Bob)
static std::mutex g_mtx;
static std::shared_ptr<Session> g_sess;

static std::string getMaster() {
    std::lock_guard<std::mutex> l(g_mtx);
    return g_master;
}

// ------------------------------------------------------------------
// Loop chat: menerima pesan AES dari lawan bicara
// ------------------------------------------------------------------
static void chatLoop(std::shared_ptr<Session> s) {
    say("[CHAT] sesi aktif dengan " + s->peerId + ". Ketik pesan lalu Enter untuk mengirim.");
    std::string line;
    while (s->conn->recvLine(line)) {
        std::vector<std::string> f = split(line, '|');
        if (f[0] == "BYE") {
            say("[CHAT] " + s->peerId + " mengakhiri sesi");
            break;
        }
        if (f[0] == "MSG" && f.size() == 2) {
            std::string plain, err;
            if (!decryptFromHex(s->ks, f[1], plain, err)) {
                say("[RX] gagal dekripsi: " + err);
                continue;
            }
            say("[RX] ciphertext (hex) : " + f[1]);
            say("[RX] " + s->peerId + " : " + plain);
        }
    }
    {
        std::lock_guard<std::mutex> l(g_mtx);
        if (g_sess == s) g_sess.reset();
    }
    s->conn->close();
    say("[CHAT] sesi dengan " + s->peerId + " berakhir");
}

static void installSession(std::shared_ptr<Session> s) {
    std::shared_ptr<Session> old;
    {
        std::lock_guard<std::mutex> l(g_mtx);
        old = g_sess;
        g_sess = s;
    }
    if (old) old->conn->close();
}

// ------------------------------------------------------------------
// Sisi Responder (B): langkah (3), (4), (5)
// ------------------------------------------------------------------
static void handleIncoming(std::shared_ptr<net::Conn> c, std::string addr) {
    say("[RESP] koneksi masuk dari " + addr);
    std::string line, err;
    if (!c->recvLine(line)) { c->close(); return; }
    std::vector<std::string> f = split(line, '|');
    if (f.size() != 2 || f[0] != "STEP3") {
        c->sendLine("AUTH|FAIL|pesan langkah 3 tidak valid");
        c->close();
        return;
    }
    say("[RESP] (3) diterima E(Kb,[Ks||IDA]) hex : " + f[1]);

    std::string kb = getMaster(), plain;
    if (!decryptFromHex(kb, f[1], plain, err)) {
        say("[RESP] gagal dekripsi langkah 3: " + err + " (master key tidak cocok dengan KDC?)");
        c->sendLine("AUTH|FAIL|dekripsi langkah 3 gagal");
        c->close();
        return;
    }
    std::vector<std::string> p = splitStr(plain, "||");
    if (p.size() != 2 || !validId(p[1]) || !AES::validKeyLen(p[0].size())) {
        say("[RESP] isi langkah 3 tidak valid: " + plain);
        c->sendLine("AUTH|FAIL|isi langkah 3 tidak valid");
        c->close();
        return;
    }
    const std::string ks = p[0], ida = p[1];
    say("[RESP] plaintext langkah 3 : Ks=" + ks + "  ID_A=" + ida);

    // Langkah 4: B -> A : E(Ks, N2)
    std::string n2 = randomNonce();
    std::string c4 = encryptToHex(ks, n2);
    say("[RESP] (4) N2 = " + n2 + "  ->  E(Ks,N2) hex : " + c4);
    c->sendLine("STEP4|" + c4);

    // Langkah 5: terima E(Ks, f(N2))
    if (!c->recvLine(line)) { c->close(); return; }
    f = split(line, '|');
    if (f.size() != 2 || f[0] != "STEP5") {
        c->sendLine("AUTH|FAIL|pesan langkah 5 tidak valid");
        c->close();
        return;
    }
    say("[RESP] (5) diterima E(Ks,f(N2)) hex : " + f[1]);
    std::string got;
    std::string expect = std::to_string(std::stoull(n2) + 1ULL);
    if (!decryptFromHex(ks, f[1], got, err) || got != expect) {
        say("[RESP] autentikasi GAGAL (diharapkan f(N2)=" + expect + ", diterima=" + (err.empty() ? got : err) + ")");
        c->sendLine("AUTH|FAIL|f(N2) salah");
        c->close();
        return;
    }
    say("[RESP] (5) plaintext f(N2) = " + got + "  -> autentikasi " + ida + " BERHASIL");
    c->sendLine("AUTH|OK");

    std::shared_ptr<Session> s(new Session());
    s->conn = c;
    s->ks = ks;
    s->peerId = ida;
    installSession(s);
    chatLoop(s);
}

static void listenLoop(sock_t ls) {
    while (true) {
        std::string addr;
        sock_t s = net::acceptOne(ls, addr);
        if (s == BAD_SOCK) break;
        std::shared_ptr<net::Conn> c(new net::Conn());
        c->s = s;
        std::thread(handleIncoming, c, addr).detach();
    }
}

// ------------------------------------------------------------------
// Sisi Initiator (A): langkah (1) sampai (5)
// ------------------------------------------------------------------
static void runInitiator(const std::string& peerId, const std::string& ip, int port) {
    std::string err, line;
    const std::string ka = getMaster();

    // Langkah 1: A -> KDC
    net::Conn kdc;
    kdc.s = net::connectTo(g_kdcHost, g_kdcPort, err);
    if (kdc.s == BAD_SOCK) { say("[INIT] gagal ke KDC: " + err); return; }
    const std::string n1 = randomNonce();
    const std::string req = "KDCREQ|" + g_myId + "|" + peerId + "|" + n1;
    say("[INIT] (1) A -> KDC : " + req);
    if (!kdc.sendLine(req) || !kdc.recvLine(line)) {
        say("[INIT] KDC tidak merespons");
        kdc.close();
        return;
    }
    kdc.close();

    // Langkah 2: KDC -> A
    std::vector<std::string> f = split(line, '|');
    if (f.size() >= 2 && f[0] == "KDCERR") { say("[INIT] KDC menolak: " + f[1]); return; }
    if (f.size() != 3 || f[0] != "KDCRESP") { say("[INIT] respons KDC tidak valid: " + line); return; }
    say("[INIT] (2) E(Ka,[Ks||IDA||IDB||N1]) hex : " + f[1]);
    say("[INIT] (2) E(Kb,[Ks||IDA]) hex          : " + f[2]);
    std::string plain;
    if (!decryptFromHex(ka, f[1], plain, err)) {
        say("[INIT] gagal dekripsi respons KDC: " + err + " (master key tidak cocok dengan KDC?)");
        return;
    }
    std::vector<std::string> p = splitStr(plain, "||");
    if (p.size() != 4 || p[1] != g_myId || p[2] != peerId || p[3] != n1 || !AES::validKeyLen(p[0].size())) {
        say("[INIT] verifikasi respons KDC GAGAL (ID atau N1 tidak cocok): " + plain);
        return;
    }
    const std::string ks = p[0];
    say("[INIT] (2) plaintext: Ks=" + ks + "  IDA=" + p[1] + "  IDB=" + p[2] + "  N1=" + p[3] + "  (N1 cocok)");

    // Langkah 3: A -> B
    std::shared_ptr<net::Conn> b(new net::Conn());
    b->s = net::connectTo(ip, port, err);
    if (b->s == BAD_SOCK) { say("[INIT] gagal ke " + peerId + ": " + err); return; }
    say("[INIT] (3) A -> B : E(Kb,[Ks||IDA]) hex : " + f[2]);
    b->sendLine("STEP3|" + f[2]);

    // Langkah 4: B -> A
    if (!b->recvLine(line)) { say("[INIT] " + peerId + " menutup koneksi"); b->close(); return; }
    std::vector<std::string> g = split(line, '|');
    if (g.size() >= 2 && g[0] == "AUTH") { say("[INIT] ditolak oleh " + peerId + ": " + line); b->close(); return; }
    if (g.size() != 2 || g[0] != "STEP4") { say("[INIT] pesan langkah 4 tidak valid"); b->close(); return; }
    say("[INIT] (4) diterima E(Ks,N2) hex : " + g[1]);
    std::string n2;
    if (!decryptFromHex(ks, g[1], n2, err) || !isDigits(n2)) {
        say("[INIT] gagal dekripsi N2: " + err);
        b->close();
        return;
    }

    // Langkah 5: A -> B : E(Ks, f(N2)), f(N2) = N2 + 1
    std::string fn2 = std::to_string(std::stoull(n2) + 1ULL);
    std::string c5 = encryptToHex(ks, fn2);
    say("[INIT] (4) N2 = " + n2 + "   (5) f(N2) = " + fn2 + "  ->  E(Ks,f(N2)) hex : " + c5);
    b->sendLine("STEP5|" + c5);

    if (!b->recvLine(line) || line != "AUTH|OK") {
        say("[INIT] autentikasi ke " + peerId + " gagal: " + line);
        b->close();
        return;
    }
    say("[INIT] autentikasi dengan " + peerId + " BERHASIL, komunikasi AES dimulai");

    std::shared_ptr<Session> s(new Session());
    s->conn = b;
    s->ks = ks;
    s->peerId = peerId;
    installSession(s);
    std::thread(chatLoop, s).detach();
}

static void help() {
    say("Perintah (diawali '/'), selain itu dianggap pesan yang dikirim ke lawan bicara:\n"
        "  /connect <ID_lawan> <ip> <port>   mulai skenario key distribution sebagai Initiator\n"
        "  /setkey <key>                     ubah master key milik entitas ini (harus sama dengan di KDC)\n"
        "  /status                           tampilkan status\n"
        "  /close                            akhiri sesi aktif\n"
        "  /help                             bantuan\n"
        "  /quit                             keluar");
}

int main(int argc, char** argv) {
    if (argc >= 2 && std::string(argv[1]) == "--selftest") return aesSelfTest() ? 0 : 1;
    if (argc < 5) {
        std::cerr << "Pemakaian: peer <ID_saya> <port_listen> <ip_kdc> <port_kdc>\n"
                     "Contoh   : peer Alice 6001 192.168.1.10 5000\n"
                     "           peer --selftest" << std::endl;
        return 1;
    }
    g_myId = argv[1];
    int listenPort = std::atoi(argv[2]);
    g_kdcHost = argv[3];
    g_kdcPort = std::atoi(argv[4]);
    if (!validId(g_myId) || listenPort <= 0 || listenPort > 65535 || g_kdcPort <= 0 || g_kdcPort > 65535) {
        std::cerr << "Argumen tidak valid" << std::endl;
        return 1;
    }
    if (!net::init()) { std::cerr << "Gagal inisialisasi jaringan" << std::endl; return 1; }

    std::string err;
    sock_t ls = net::listenOn(listenPort, err);
    if (ls == BAD_SOCK) say("Peringatan: tidak bisa listen di port " + std::to_string(listenPort) + ": " + err);
    else std::thread(listenLoop, ls).detach();

    say("=== " + g_myId + " aktif | listen port " + std::to_string(listenPort) + " | KDC " + g_kdcHost + ":" +
        std::to_string(g_kdcPort) + " ===");

    // Master key diminta saat startup (tidak di-hardcode)
    std::string line;
    while (true) {
        say("Masukkan master key " + g_myId + " (sama dengan yang didaftarkan di KDC, 16/24/32 karakter ASCII):");
        if (!std::getline(std::cin, line)) return 0;
        line = trim(line);
        if (validKey(line)) break;
        say(std::string("Key ditolak: ") + keyRule());
    }
    g_master = line;
    help();

    while (std::getline(std::cin, line)) {
        std::string t = trim(line);
        if (t.empty()) continue;
        if (t[0] != '/') {
            std::shared_ptr<Session> s;
            {
                std::lock_guard<std::mutex> l(g_mtx);
                s = g_sess;
            }
            if (!s) { say("Belum ada sesi aktif. Gunakan /connect, atau tunggu lawan bicara terhubung."); continue; }
            std::string h = encryptToHex(s->ks, t);
            if (!s->conn->sendLine("MSG|" + h)) { say("Gagal mengirim (sesi terputus?)"); continue; }
            say("[TX] plaintext        : " + t);
            say("[TX] ciphertext (hex) : " + h);
            continue;
        }
        std::istringstream iss(t);
        std::string cmd;
        iss >> cmd;
        if (cmd == "/connect") {
            std::string id, ip;
            int port = 0;
            iss >> id >> ip >> port;
            if (!validId(id) || ip.empty() || port <= 0 || port > 65535) {
                say("Pemakaian: /connect <ID_lawan> <ip> <port>");
                continue;
            }
            runInitiator(id, ip, port);
        } else if (cmd == "/setkey") {
            std::string key;
            iss >> key;
            if (!validKey(key)) { say(std::string("Key ditolak: ") + keyRule()); continue; }
            {
                std::lock_guard<std::mutex> l(g_mtx);
                g_master = key;
            }
            say("Master key diubah menjadi: " + key + "   (ingat: samakan dengan 'setkey " + g_myId + " ...' di KDC)");
        } else if (cmd == "/status") {
            std::shared_ptr<Session> s;
            std::string mk;
            {
                std::lock_guard<std::mutex> l(g_mtx);
                s = g_sess;
                mk = g_master;
            }
            say("ID: " + g_myId + " | master key: " + mk + " | KDC: " + g_kdcHost + ":" + std::to_string(g_kdcPort));
            if (s) say("Sesi aktif dengan " + s->peerId + " | Ks: " + s->ks);
            else say("Tidak ada sesi aktif");
        } else if (cmd == "/close") {
            std::shared_ptr<Session> s;
            {
                std::lock_guard<std::mutex> l(g_mtx);
                s = g_sess;
            }
            if (s) { s->conn->sendLine("BYE"); s->conn->close(); }
            else say("Tidak ada sesi aktif");
        } else if (cmd == "/help") {
            help();
        } else if (cmd == "/quit" || cmd == "/exit") {
            std::shared_ptr<Session> s;
            {
                std::lock_guard<std::mutex> l(g_mtx);
                s = g_sess;
            }
            if (s) s->conn->sendLine("BYE");
            break;
        } else {
            say("Perintah tidak dikenal. Ketik /help");
        }
    }
    return 0;
}
