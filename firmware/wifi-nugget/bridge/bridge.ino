#include <Arduino.h>

extern "C" {
#include "user_interface.h"
// Some (old) cores omit this declaration; declaring it is harmless on 2.7.4/3.1.2.
int wifi_send_pkt_freedom(uint8 *buf, int len, bool sys_seq);
}

// DEAUTH requires a PATCHED SDK — this stock build does NOT send deauth. Bench-verified
// 2026-08-03: on stock esp8266 core 2.7.4 AND 3.1.2, wifi_send_pkt_freedom() returns -1
// for deauth/disassoc and radiates nothing (beacons/probes/data still work). The block is
// not in wifi_send_pkt_freedom itself (it only checks freedom-mode) but in the deeper
// libnet80211 send callee it invokes. Core 2.0.0 exposes an older function but that build
// crash-loops on our D1 Mini. The shipped site/firmware/motoko-research-firmware.bin (v3)
// was built against a patched SDK (deauth-block removed) — that's why it deauths. To ship
// v3.1 (STATUS) WITH deauth, rebuild against that patched lib. The ESP32-style
// ieee80211_raw_frame_sanity_check() override does NOT work on ESP8266 (verified).

// SLIP constants
#define SLIP_END     0xC0
#define SLIP_ESC     0xDB
#define SLIP_ESC_END 0xDC
#define SLIP_ESC_ESC 0xDD

// Type Bytes (Motoko v3 Standard)
#define TYPE_PKT_INJECT  0x00
#define TYPE_CH_SWITCH   0x01
#define TYPE_FILTER_SET  0x02
#define TYPE_PKT_RECV    0x03
#define TYPE_DEBUG_MSG   0x04
#define TYPE_STATUS_REQ  0x05   // NEW: host -> board; board replies with a STATUS debug line

#define FW_VERSION 3

// Filter Mask (Local Software Filter)
// 0x01: Mgmt, 0x02: Ctrl, 0x04: Data
uint8_t current_filter_mask = 0x01 | 0x04;

// TX telemetry (answered on TYPE_STATUS_REQ; no per-inject serial overhead)
uint32_t tx_count = 0;
int      tx_last_err = 0;

// Buffer for incoming serial
#define RX_BUFFER_SIZE 2500
uint8_t rx_buffer[RX_BUFFER_SIZE];
uint16_t rx_ptr = 0;
bool rx_escaped = false;

void slip_send(uint8_t type, uint8_t *data, uint16_t len) {
    Serial.write(SLIP_END);
    Serial.write(type);
    for (uint16_t i = 0; i < len; i++) {
        if (data[i] == SLIP_END) {
            Serial.write(SLIP_ESC); Serial.write(SLIP_ESC_END);
        } else if (data[i] == SLIP_ESC) {
            Serial.write(SLIP_ESC); Serial.write(SLIP_ESC_ESC);
        } else {
            Serial.write(data[i]);
        }
    }
    Serial.write(SLIP_END);
}

void send_debug(String msg) {
    slip_send(TYPE_DEBUG_MSG, (uint8_t*)msg.c_str(), msg.length());
}

void send_status() {
    // Keep the word "Motoko v3" so the existing boot-banner handshake regex still
    // extracts the version from this reply, and append TX telemetry.
    send_debug("Motoko v" + String(FW_VERSION) + " (S-Filter) STATUS tx=" + String(tx_count) +
               " err=" + String(tx_last_err) + " ch=" + String(wifi_get_channel()) +
               " filter=" + String(current_filter_mask));
}

void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buf, uint16_t len) {
    if (len < 13) return; // Drop tiny fragments

    // First 12 bytes are metadata. 802.11 frame starts at byte 12.
    uint8_t frame_type = (buf[12] & 0x0C) >> 2;

    bool pass = false;
    if (frame_type == 0 && (current_filter_mask & 0x01)) pass = true; // Mgmt
    if (frame_type == 1 && (current_filter_mask & 0x02)) pass = true; // Ctrl
    if (frame_type == 2 && (current_filter_mask & 0x04)) pass = true; // Data

    if (pass) {
        slip_send(TYPE_PKT_RECV, buf, len);
    }
}

void setup() {
    Serial.begin(1000000);
    wifi_set_opmode(STATION_MODE);
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(sniffer_callback);
    wifi_promiscuous_enable(1);

    wifi_set_channel(1);
    send_debug("Motoko v3 (S-Filter) Ready");
}

void process_command(uint8_t *buf, uint16_t len) {
    uint8_t type = buf[0];
    uint8_t *payload = buf + 1;
    uint16_t payload_len = len - 1;

    switch(type) {
        case TYPE_PKT_INJECT: {
            int r = wifi_send_pkt_freedom(payload, payload_len, false);
            tx_count++;
            tx_last_err = r;                 // 0 = queued OK; negative = SDK error
            delay(1);
            break;
        }

        case TYPE_CH_SWITCH:
            if (payload_len >= 1) wifi_set_channel(payload[0]);
            break;

        case TYPE_FILTER_SET:
            if (payload_len >= 1) current_filter_mask = payload[0];
            break;

        case TYPE_STATUS_REQ:                // NEW: version + TX telemetry, no reset needed
            send_status();
            break;
    }
}

void loop() {
    while (Serial.available()) {
        uint8_t c = Serial.read();
        if (c == SLIP_END) {
            if (rx_ptr > 0) {
                process_command(rx_buffer, rx_ptr);
                rx_ptr = 0;
            }
        } else if (c == SLIP_ESC) {
            rx_escaped = true;
        } else if (rx_escaped) {
            // Bounds-checked (was unchecked): a corrupt escape stream must not overflow.
            if (rx_ptr < RX_BUFFER_SIZE) {
                if (c == SLIP_ESC_END) rx_buffer[rx_ptr++] = SLIP_END;
                else if (c == SLIP_ESC_ESC) rx_buffer[rx_ptr++] = SLIP_ESC;
            }
            rx_escaped = false;
        } else {
            if (rx_ptr < RX_BUFFER_SIZE) rx_buffer[rx_ptr++] = c;
            else rx_ptr = 0;                 // resync on overflow instead of wedging
        }
    }
}
