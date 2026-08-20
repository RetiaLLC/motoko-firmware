// motoko_proto.h — pure (Arduino-free) Motoko-S3 protocol + capture logic.
// Shared by the firmware (src/main.cpp) and the host test (host/fw_logic_test.c)
// so the tests exercise the EXACT code that runs on the puck.
#ifndef MOTOKO_PROTO_H
#define MOTOKO_PROTO_H
#include <stdint.h>
#include <string.h>

// ---- SLIP ----
#define SLIP_END     0xC0
#define SLIP_ESC     0xDB
#define SLIP_ESC_END 0xDC
#define SLIP_ESC_ESC 0xDD

// ---- type bytes ----
#define TYPE_PKT_INJECT  0x00
#define TYPE_CH_SWITCH   0x01
#define TYPE_FILTER_SET  0x02
#define TYPE_PKT_RECV    0x03
#define TYPE_DEBUG_MSG   0x04
#define TYPE_STATUS_REQ  0x05
#define TYPE_EAPOL       0x06
#define TYPE_HUNT        0x07
#define TYPE_HOP         0x08

#define META_LEN 12

// Build the 12-byte metadata prefix the Motoko display expects:
//   meta[0]  = RSSI (int8)          -> parser.js reads raw[1]
//   meta[10] = channel low nibble   -> parser.js reads raw[11]
static inline void motoko_build_meta(uint8_t meta[META_LEN], int8_t rssi, uint8_t channel) {
    memset(meta, 0, META_LEN);
    meta[0]  = (uint8_t)rssi;
    meta[10] = channel & 0x0f;
}

// Encode one SLIP frame: END, type, escaped(data), END. Returns bytes written to out.
// out must hold at least 2*len + 3.
static inline uint32_t motoko_slip_encode(uint8_t type, const uint8_t *data, uint32_t len,
                                          uint8_t *out) {
    uint32_t o = 0;
    out[o++] = SLIP_END;
    out[o++] = type;
    for (uint32_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        if (b == SLIP_END)      { out[o++] = SLIP_ESC; out[o++] = SLIP_ESC_END; }
        else if (b == SLIP_ESC) { out[o++] = SLIP_ESC; out[o++] = SLIP_ESC_ESC; }
        else                    { out[o++] = b; }
    }
    out[o++] = SLIP_END;
    return o;
}

// EAPOL / PMKID inspection on a captured 802.11 frame (frame bytes, len).
// Returns 0 = not EAPOL, else the EAPOL-Key message number 1..4; sets *has_pmkid on an M1 PMKID KDE.
static inline int motoko_eapol_inspect(const uint8_t *f, int flen, int *has_pmkid) {
    *has_pmkid = 0;
    if (flen < 24) return 0;
    uint8_t fc0 = f[0], fc1 = f[1];
    if (((fc0 & 0x0C) >> 2) != 2) return 0;           // not a data frame
    int toDS = fc1 & 0x01, fromDS = fc1 & 0x02;
    int qos  = (fc0 & 0x80);                            // QoS-data subtype
    int hdr = 24;
    if (toDS && fromDS) hdr += 6;                       // 4-address
    if (qos) hdr += 2;                                  // QoS control
    if (fc1 & 0x40) return 0;                           // protected -> not cleartext EAPOL
    if (flen < hdr + 8) return 0;
    if (!(f[hdr]==0xAA && f[hdr+1]==0xAA && f[hdr+2]==0x03 &&
          f[hdr+3]==0x00 && f[hdr+4]==0x00 && f[hdr+5]==0x00 &&
          f[hdr+6]==0x88 && f[hdr+7]==0x8E)) return 0;  // LLC/SNAP + ethertype 0x888E
    int e = hdr + 8;
    if (flen < e + 4) return 0;
    if (f[e+1] != 3) return 0;                          // EAPOL type 3 = EAPOL-Key
    int k = e + 4;
    if (flen < k + 3) return 0;
    uint16_t ki = (f[k+1] << 8) | f[k+2];               // Key Information (big-endian)
    int mic     = ki & 0x0100;
    int ack     = ki & 0x0080;
    int install = ki & 0x0040;
    int secure  = ki & 0x0200;
    int msg;
    // 4-way handshake message id by Key Info flags:
    //   M1 ACK,!MIC   M2 !ACK,MIC,!Secure   M3 ACK,MIC,Install   M4 !ACK,MIC,Secure
    if (ack && !mic)                       msg = 1;     // M1 (AP->STA) — carries PMKID
    else if (!ack && mic && !secure)       msg = 2;     // M2 (STA->AP)
    else if (ack && mic && install)        msg = 3;     // M3
    else                                   msg = 4;     // M4
    if (msg == 1 && flen >= k + 95) {                   // key-data length at k+93..94
        uint16_t kdlen = (f[k+93] << 8) | f[k+94];
        int kd = k + 95;
        if (kdlen > 0 && flen >= kd + (int)kdlen) {
            for (int p = kd; p + 6 <= kd + kdlen && p + 6 <= flen; p++) {
                if (f[p]==0xDD && f[p+2]==0x00 && f[p+3]==0x0F && f[p+4]==0xAC && f[p+5]==0x04) {
                    *has_pmkid = 1; break;              // RSN PMKID KDE
                }
            }
        }
    }
    return msg;
}

#endif // MOTOKO_PROTO_H
