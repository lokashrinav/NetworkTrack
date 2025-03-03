#include <pcap.h>
#include <iostream>
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
using namespace std;
int pk = 0;
struct eh { u_char d[6]; u_char s[6]; u_short t; };
struct ih { u_char vi; u_char to; u_short tl; u_short id; u_short ff; u_char tt; u_char pr; u_short cs; u_int sa; u_int da; };
void cb(u_char *a, const struct pcap_pkthdr *b, const u_char *c) {
    pk++;
    cout << "Pkt " << pk << " ";
    if(b->len >= sizeof(eh)) {
        eh *x = (eh*)c;
        if(ntohs(x->t) == 0x0800 && b->len >= sizeof(eh) + sizeof(ih)) {
            ih *y = (ih*)(c + sizeof(eh));
            cout << inet_ntoa(*(in_addr*)&y->sa) << " -> " << inet_ntoa(*(in_addr*)&y->da);
        }
    }
    cout << "\r";
    cout.flush();
}
int main() {
    WSADATA w;
    WSAStartup(MAKEWORD(2,2), &w);
    pcap_if_t *d;
    char e[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&d, e);
    pcap_if_t *f = d;
    pcap_t *g = pcap_open_live(f->name, 65536, 1, 1000, e);
    pcap_loop(g, 0, cb, NULL);
    pcap_freealldevs(d);
    pcap_close(g);
    return 0;
}
