// fw_logic_test.c — exercises the ACTUAL Motoko-S3 firmware logic (../src/motoko_proto.h)
// against byte-accurate 802.11 frames, and emits the exact SLIP stream the puck would send
// so the real display parser (parser.js) can be run against it (see display_test.cjs).
//
// Proves the ESP8266 -> ESP32-S3 capability delta WITHOUT needing a puck to enumerate:
//   * A WPA2 beacon with RSN+WPS+vendor IEs is > 112 bytes. Full-frame capture keeps the
//     RSN element; a 112-byte ESP8266-style truncation drops it.
//   * An EAPOL-Key M1 carries its RSN-PMKID KDE at byte ~137 — far past 112. Full-frame
//     capture yields the PMKID (clientless crack); a 112-byte truncation detects "an M1"
//     but the PMKID is gone -> ESP8266 physically cannot capture it.
#include <stdio.h>
#include <string.h>
#include "../src/motoko_proto.h"

static unsigned char BSSID[6]  = {0x02,0xCA,0xFE,0x00,0x11,0x22};
static unsigned char STA[6]    = {0x02,0xDE,0xAD,0x00,0x33,0x44};

// ---- build a WPA2 beacon with SSID + RSN(48) + HT(45) + WPS/vendor(221) ----
static int build_beacon(unsigned char *f) {
    int n = 0;
    f[n++]=0x80; f[n++]=0x00;                 // FC: mgmt, beacon
    f[n++]=0x00; f[n++]=0x00;                 // duration
    unsigned char bc[6]={0xff,0xff,0xff,0xff,0xff,0xff};
    memcpy(f+n,bc,6); n+=6;                    // addr1 dst broadcast
    memcpy(f+n,BSSID,6); n+=6;                 // addr2 bssid
    memcpy(f+n,BSSID,6); n+=6;                 // addr3 bssid
    f[n++]=0x10; f[n++]=0x00;                  // seq
    // fixed params (12): timestamp(8) beacon-int(2) cap(2)
    memset(f+n,0,8); n+=8;
    f[n++]=0x64; f[n++]=0x00;                  // beacon interval
    f[n++]=0x21; f[n++]=0x04;                  // cap: ESS + privacy (0x0421 wire LE)
    // SSID IE (0)
    const char *ssid="Motoko_S3_Lab"; int sl=strlen(ssid);
    f[n++]=0x00; f[n++]=sl; memcpy(f+n,ssid,sl); n+=sl;
    // Supported rates IE (1)
    f[n++]=0x01; f[n++]=0x08; unsigned char rates[8]={0x82,0x84,0x8b,0x96,0x24,0x30,0x48,0x6c}; memcpy(f+n,rates,8); n+=8;
    // DS param (3) channel 6
    f[n++]=0x03; f[n++]=0x01; f[n++]=0x06;
    // HT capabilities (45) 26 bytes
    f[n++]=0x2d; f[n++]=0x1a; memset(f+n,0,26); n+=26;
    // A large vendor IE (221) placed BEFORE the RSN so RSN lands past byte 112 — exactly
    // the real-world case where the ESP8266's 112-byte truncation loses the security element.
    f[n++]=0xdd; f[n++]=0x32; f[n++]=0x00; f[n++]=0x03; f[n++]=0x7f; memset(f+n,0x00,0x2f); n+=0x2f;
    // RSN IE (48) — WPA2-PSK/CCMP  (this is what the ESP8266 truncates away)
    unsigned char rsn[]={0x30,0x14,0x01,0x00, 0x00,0x0f,0xac,0x04, 0x01,0x00,0x00,0x0f,0xac,0x04,
                         0x01,0x00,0x00,0x0f,0xac,0x02, 0x00,0x00};
    memcpy(f+n,rsn,sizeof(rsn)); n+=sizeof(rsn);
    // Vendor / WPS (221) — Microsoft WPS OUI 00:50:F2:04
    f[n++]=0xdd; f[n++]=0x10; unsigned char wps[16]={0x00,0x50,0xf2,0x04,0x10,0x4a,0x00,0x01,0x10,0x10,0x44,0x00,0x01,0x02,0x00,0x00}; memcpy(f+n,wps,16); n+=16;
    return n; // ~24+12+15+10+3+28+53+22+18 = 183 bytes; RSN starts ~offset 145 (past 112)
}

// ---- build an EAPOL-Key M1 (AP->STA) with an RSN-PMKID KDE ----
static int build_eapol_m1(unsigned char *f) {
    int n=0;
    f[n++]=0x08; f[n++]=0x02;                  // FC: data, fromDS=1
    f[n++]=0x00; f[n++]=0x00;                  // duration
    memcpy(f+n,STA,6);  n+=6;                   // addr1 dst = STA
    memcpy(f+n,BSSID,6);n+=6;                   // addr2 = BSSID
    memcpy(f+n,BSSID,6);n+=6;                   // addr3 = BSSID
    f[n++]=0x00; f[n++]=0x00;                   // seq   (hdr=24)
    // LLC/SNAP + ethertype 0x888E
    unsigned char snap[8]={0xAA,0xAA,0x03,0x00,0x00,0x00,0x88,0x8E}; memcpy(f+n,snap,8); n+=8;
    // EAPOL header: ver, type(3=key), length(2)
    int len_field_pos;
    f[n++]=0x02; f[n++]=0x03; len_field_pos=n; f[n++]=0x00; f[n++]=0x00;
    int body_start=n;
    f[n++]=0x02;                               // desc type = RSN
    f[n++]=0x00; f[n++]=0x8a;                  // key info: ver2 + pairwise(0x08) + ACK(0x80)=0x008a -> M1
    f[n++]=0x00; f[n++]=0x10;                  // key length 16
    memset(f+n,0,8);  n+=8;                     // replay counter
    memset(f+n,0xAB,32); n+=32;                 // key nonce (ANonce)
    memset(f+n,0,16); n+=16;                    // key IV
    memset(f+n,0,8);  n+=8;                     // key RSC
    memset(f+n,0,8);  n+=8;                     // key ID
    memset(f+n,0,16); n+=16;                    // key MIC (0 for M1)
    // key data length + PMKID KDE
    unsigned char kde[22]={0xDD,0x14,0x00,0x0F,0xAC,0x04, // RSN PMKID KDE header
        0xDE,0xAD,0xBE,0xEF,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C}; // 16B PMKID
    f[n++]=0x00; f[n++]=22;                     // key data length = 22
    memcpy(f+n,kde,22); n+=22;
    int body_len = n - body_start;
    f[len_field_pos]   = (body_len>>8)&0xff;
    f[len_field_pos+1] = body_len&0xff;
    return n; // ~153 bytes; PMKID at ~137
}

// ---- build an EAPOL-Key M2 (STA->AP), no PMKID ----
static int build_eapol_m2(unsigned char *f) {
    int n=0;
    f[n++]=0x88; f[n++]=0x01;                  // QoS-data, toDS=1
    f[n++]=0x00; f[n++]=0x00;
    memcpy(f+n,BSSID,6);n+=6;                   // addr1 = BSSID
    memcpy(f+n,STA,6);  n+=6;                   // addr2 = STA
    memcpy(f+n,BSSID,6);n+=6;                   // addr3
    f[n++]=0x00; f[n++]=0x00;                   // seq
    f[n++]=0x00; f[n++]=0x00;                   // QoS control (+2 -> hdr=26)
    unsigned char snap[8]={0xAA,0xAA,0x03,0x00,0x00,0x00,0x88,0x8E}; memcpy(f+n,snap,8); n+=8;
    f[n++]=0x02; f[n++]=0x03; int lp=n; f[n++]=0; f[n++]=0;
    int bs=n;
    f[n++]=0x02;
    f[n++]=0x01; f[n++]=0x0a;                  // key info: ver2 + pairwise + MIC(0x0100)=0x010a -> M2 (mic set, ack clear)
    f[n++]=0x00; f[n++]=0x10;
    memset(f+n,0,8); n+=8; memset(f+n,0xCD,32); n+=32; memset(f+n,0,16); n+=16;
    memset(f+n,0,8); n+=8; memset(f+n,0,8); n+=8; memset(f+n,0x11,16); n+=16;
    f[n++]=0x00; f[n++]=0x00;                   // key data length 0
    int bl=n-bs; f[lp]=(bl>>8)&0xff; f[lp+1]=bl&0xff;
    return n;
}

static void emit_slip(FILE *o, unsigned char type, unsigned char rssi, unsigned char ch,
                      const unsigned char *frame, int flen) {
    unsigned char meta[META_LEN]; motoko_build_meta(meta, (signed char)rssi, ch);
    unsigned char pkt[2048]; memcpy(pkt,meta,META_LEN); memcpy(pkt+META_LEN,frame,flen);
    unsigned char out[4096]; unsigned int on = motoko_slip_encode(type, pkt, META_LEN+flen, out);
    fwrite(out,1,on,o);
}

int main(void){
    unsigned char beacon[512]; int bl=build_beacon(beacon);
    unsigned char m1[512];     int ml=build_eapol_m1(m1);
    unsigned char m2[512];     int m2l=build_eapol_m2(m2);
    int pass=1;

    printf("== Motoko-S3 firmware-logic test (real motoko_proto.h) ==\n\n");
    printf("beacon len=%d  eapol-M1 len=%d  eapol-M2 len=%d\n\n", bl, ml, m2l);

    // EAPOL detection on FULL frames
    int p; int msg;
    msg = motoko_eapol_inspect(m1, ml, &p);
    printf("[full] M1  -> eapol_inspect msg=%d pmkid=%d   (expect msg=1 pmkid=1)\n", msg, p);
    if(!(msg==1 && p==1)) pass=0;
    msg = motoko_eapol_inspect(m2, m2l, &p);
    printf("[full] M2  -> eapol_inspect msg=%d pmkid=%d   (expect msg=2 pmkid=0)\n", msg, p);
    if(!(msg==2 && p==0)) pass=0;
    msg = motoko_eapol_inspect(beacon, bl, &p);
    printf("[full] beacon -> eapol_inspect msg=%d              (expect 0, not data)\n", msg);
    if(msg!=0) pass=0;

    // The ESP8266 truncation: cut everything to 112 bytes and re-run
    printf("\n-- simulate ESP8266 112-byte promiscuous truncation --\n");
    int tb = bl<112?bl:112, tm = ml<112?ml:112;
    msg = motoko_eapol_inspect(m1, tm, &p);
    printf("[trunc112] M1 -> msg=%d pmkid=%d   (M1 seen but PMKID LOST -> ESP8266 cannot crack)\n", msg, p);
    if(p!=0) pass=0;                                  // truncation MUST drop the pmkid
    // scan tagged params for the RSN element (id 48) in full vs 112-truncated beacon
    int rsn_full=0, rsn_trunc=0;
    for(int q=24+12; q+2<=bl; q+=2+beacon[q+1]) if(beacon[q]==48){ rsn_full=1; if(q+2+beacon[q+1]<=112) rsn_trunc=1; break; }
    printf("[trunc112] beacon RSN(48): full-frame=%s  112-trunc=%s  -> ESP8266 mislabels security\n",
           rsn_full?"PRESENT":"absent", rsn_trunc?"PRESENT":"TRUNCATED-AWAY");
    if(!(rsn_full && !rsn_trunc)) pass=0;             // must be present full, lost truncated

    // Emit the SLIP stream a puck would send, for the real display parser
    FILE *o=fopen("slip_stream.bin","wb");
    emit_slip(o, TYPE_PKT_RECV, (unsigned char)(signed char)-42, 6, beacon, bl);   // full beacon
    emit_slip(o, TYPE_PKT_RECV, (unsigned char)(signed char)-42, 6, beacon, tb);   // 112-trunc beacon (ESP8266)
    emit_slip(o, TYPE_PKT_RECV, (unsigned char)(signed char)-55, 6, m1, ml);       // M1 as data
    emit_slip(o, TYPE_EAPOL,    (unsigned char)(signed char)-55, 6, m1, ml);       // M1 as 0x06 (S3-only)
    fclose(o);
    printf("\nwrote slip_stream.bin for display_test.cjs\n");

    printf("\n== firmware-logic test: %s ==\n", pass?"PASS":"FAIL");
    return pass?0:1;
}
