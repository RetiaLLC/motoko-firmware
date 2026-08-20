// display_test.cjs — feed the SLIP stream that Motoko-S3 emits (from fw_logic_test) through
// the REAL Motoko display code (motoko-bpi/site/js/slip.js + parser.js) with ZERO changes,
// proving (a) interop and (b) the full-frame vs ESP8266-112-truncation capability delta.
const fs = require('fs');
const path = require('path');
const SITE = path.join(process.env.HOME, 'motoko-bpi', 'site', 'js');
const { SlipDecoder } = require(path.join(SITE, 'slip.js'));
const { Dot11Parser } = require(path.join(SITE, 'parser.js'));

const bytes = fs.readFileSync(path.join(__dirname, 'slip_stream.bin'));
const parser = new Dot11Parser();
const events = [];
let rawFrames = 0;
const dec = new SlipDecoder((frame) => {
  rawFrames++;
  const pkt = parser.parse(frame);           // parser only accepts type 0x03; 0x06 -> null
  events.push({ decoded: !!pkt, pkt });
});
dec.push(new Uint8Array(bytes));

console.log('== Motoko-S3 -> real display parser (parser.js) ==\n');
console.log(`SLIP frames decoded by the display: ${rawFrames}`);
for (const e of events) {
  console.log('  ', e.pkt ? JSON.stringify(e.pkt) : '(type ignored by current display — additive, no breakage)');
}

let pass = true;
const need = (cond, msg) => { console.log(`  [${cond ? 'PASS' : 'FAIL'}] ${msg}`); if (!cond) pass = false; };

console.log('\n-- assertions --');
const full = events[0].pkt;      // full beacon
const trunc = events[1].pkt;     // 112-byte truncated beacon (what an ESP8266 delivers)
const data = events[2].pkt;      // M1 delivered as data (0x03)
const eapol = events[3];         // M1 delivered as TYPE_EAPOL 0x06

need(full && full.type === 'beacon' && full.ssid === 'Motoko_S3_Lab',
     `full beacon parses: ssid=${full && full.ssid}`);
need(full && full.rssi === -42 && full.channel === 6,
     `metadata carried through: rssi=${full && full.rssi} ch=${full && full.channel}`);
need(full && full.security === 'WPA2',
     `full-frame security = WPA2 (RSN element survived): ${full && full.security}`);
need(trunc && trunc.security !== 'WPA2',
     `ESP8266 112-trunc MISLABELS security as '${trunc && trunc.security}' (RSN truncated away)`);
need(data && data.type === 'data',
     `M1 (0x03) shows on display as data pulse: ${data && data.type}`);
need(eapol && eapol.decoded === false,
     `TYPE_EAPOL (0x06) ignored by current display -> additive, back-compatible`);

console.log(`\n== display interop test: ${pass ? 'PASS' : 'FAIL'} ==`);
process.exit(pass ? 0 : 1);
