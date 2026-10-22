#include <Arduino.h>
#include <EEPROM.h>
#include <avr/wdt.h>
#include "uECC.h"
#include "compact_sha256.h"
#include "aes256_tiny.h"

const int LED_PIN = 13;
const int BUTTON_PINS[] = {2, 3, 4, 5, 6, 7};
const int NUM_BUTTON_PINS = 6;

SHA256 sha256;

// EEPROM v2 (MAGIC_3 0x02). v1 slots had no PIN, user id, or hmac-secret.
// A mismatch wipes the whole EEPROM, including the DRBG seed.
// 0..3 magic, 4..7 counter, 8 slotCount, 9 seedFlag,
// 16..47 DRBG seed, 48 xor, 49 sum,
// 50 pinFlag, 51 pinRetries, 52..67 pinHash, 68.. slots.
#define MAGIC_0 0xF1
#define MAGIC_1 0xD0
#define MAGIC_2 0x02
#define MAGIC_3 0x02
#define SEED_FLAG_ADDR 9
#define SEED_FLAG_OK 0xA5
#define SEED_ADDR 16
#define SEED_XOR_ADDR 48
#define SEED_SUM_ADDR 49
#define PIN_FLAG_ADDR 50
#define PIN_RETRIES_ADDR 51
#define PIN_HASH_ADDR 52
#define PIN_MAX_RETRIES 8
#define USER_ID_MAX 64
#define MAX_SLOTS 5
#define SLOT_BASE_ADDR 68

struct Fido2Slot {
  uint8_t valid;          // 0xA5 if occupied
  uint8_t credProtect;    // 1, 2, or 3
  uint8_t userIdLen;
  uint8_t userId[USER_ID_MAX];
  uint8_t credId[16];
  uint8_t rpIdHash[32];
  uint8_t privKey[32];
  uint8_t credRandom[32]; // hmac-secret
};

// Session RP binding sits after the slots. The token itself stays in RAM and
// dies on power-up; only the 32-byte RP hash is persisted for that session.
#define PIN_RP_FLAG_ADDR 980
#define PIN_RP_ADDR 981
// Diagnostic record, outside every structure above (ends at 1013).
// A wedged 328P went silent for 53 minutes and only a USB replug recovered it,
// so the last command is kept here and blinked after a watchdog reset.
#define LAST_CMD_ADDR 1014
#define WDT_COUNT_ADDR 1015
static_assert(offsetof(Fido2Slot, credId) == 67, "credId offset");
static_assert(offsetof(Fido2Slot, rpIdHash) == 83, "rp offset");
static_assert(offsetof(Fido2Slot, privKey) == 115, "priv offset");
static_assert(offsetof(Fido2Slot, credRandom) == 147, "credRandom offset");
static_assert(sizeof(Fido2Slot) == 179, "slot size");
static_assert(SLOT_BASE_ADDR + MAX_SLOTS * sizeof(Fido2Slot) <= PIN_RP_FLAG_ADDR,
              "FIDO2 slots overlap the PIN RP binding");
static_assert(PIN_RP_ADDR + 32 <= 1024, "PIN RP binding exceeds EEPROM");

const uint8_t AAGUID[16] PROGMEM = {
  'E','L','E','G','O','O','_','U','N','O','_','F','I','D','O','2'
};

uint32_t g_counter = 0;
uint8_t g_slotCount = 0;

// Requests capped at 512 bytes (Windows Hello makeCredential is often >288).
// 16U2 streams HID packets over UART; scratch sits right after the message window.
#define CTAP_MAX_MSG 512
#define SCRATCH_OFF 512
// [0..511] is also the uECC workspace (see ew() in uECC.c). [512..] is scratch.
uint8_t g_ioBuf[544] __attribute__((aligned(4)));
// Snapshot during ECC (a setPIN message is ~190). After eccRestoreIo the
// same bytes are the AES-256 schedule: 240 round keys + 32 bytes of CBC state.
uint8_t g_eccHold[272];
extern "C" uint8_t *eccScratch(void) { return g_ioBuf; }
extern "C" uint8_t *eccHoldBuf(void) { return g_eccHold; }
// shared_secret / sign temps. Not the request snapshot and not the workspace.
uint8_t g_secTmp[128];
extern "C" uint8_t *eccSecBuf(void) { return g_secTmp; }
// uECC.c calls this from the point-multiplication loop. The watchdog is 8s and
// one P-256 multiply takes 20-40s, so it must be fed while that loop advances.
// uECC_vli_modInv is deliberately NOT fed: an infinite loop there has to trip
// the watchdog instead of hanging the chip with the USB bridge still alive.
extern "C" void eccFeed(void) { wdt_reset(); }
size_t rxIdx = 0;
bool g_hidMsgReady = false;

// clientPIN session. Token and key die on reset and power-up.
// RP binding hash lives in EEPROM so it does not sit in BSS next to the sign path.
uint8_t g_pinPriv[32];
uint8_t g_pinPub[64];
uint8_t g_pinToken[32];
uint8_t g_blk[64];
uint8_t g_clientHash[32];
uint8_t g_pinPerm = 0;
uint8_t g_pinProto = 0;
uint8_t g_pinConsec = 0;
uint8_t g_havePinKey = 0;
uint8_t g_pinRpBound = 0;

// Parsed fields. Offsets point into g_ioBuf and die when the response is built.
uint8_t g_reqProto = 0;
uint8_t g_credProtect = 1;
uint8_t g_hmacProto = 1;
uint8_t g_reqFlags = 0;
uint8_t g_hasAllow = 0;
uint8_t g_hasHmacGet = 0;
uint8_t g_userLen = 0;
uint8_t g_pinSub = 0;
uint8_t g_reqPerm = 0;
uint8_t g_listN = 0;
int8_t g_list[MAX_SLOTS];
int8_t g_exclIdx = -1;
int8_t g_chosen = -1;
uint16_t g_pinAuthOff = 0, g_pinAuthLen = 0;
uint8_t g_hasPinAuth = 0;
uint16_t g_bOff = 0, g_bLen = 0;
uint16_t g_cOff = 0, g_cLen = 0;
uint16_t g_xOff = 0, g_yOff = 0;
uint16_t g_rpOff = 0, g_rpLen = 0;
uint16_t g_userOff = 0;

#define RF_HASH     0x01
#define RF_RP       0x02
#define RF_UV       0x04
#define RF_UP_FALSE 0x08
#define RF_RK_FALSE 0x10
#define RF_HMAC     0x20
#define RF_ES256    0x40
#define RF_CP       0x80

// HMAC-DRBG (SHA-256, SP 800-90A) for credential IDs, P-256 keys, and ECDSA nonces.
// Entropy is ADC LSBs, derated for correlation. A stuck pin contributes nothing.
// The DRBG refuses to emit bytes until that estimate reaches 256 bits, or a
// seed previously produced by this DRBG is present in EEPROM.
static uint8_t g_drbgK[32];
static uint8_t g_drbgV[32];
static uint8_t g_drbgExtra[8];
static uint8_t g_drbgReady = 0;
static uint8_t g_entFailed = 0;
static uint8_t g_entropyHashActive = 0;
static uint8_t g_storageWiped = 0;
static uint8_t g_entPin = 0;
static uint8_t g_entPrev = 0xFF;
static uint8_t g_entRounds = 0;
static uint16_t g_entFilled = 0;
static uint16_t g_entOnes = 0;
static uint16_t g_entRun = 0;
static uint16_t g_entMaxRun = 0;
static uint16_t g_entCredit = 0;
static int8_t g_entropyReported = -1;
static unsigned long g_failBlinkAt = 0;

static uint8_t seedXor(const uint8_t s[32]) {
  uint8_t x = 0;
  for (uint8_t i = 0; i < 32; i++) x ^= s[i];
  return x;
}

static uint8_t seedSum(const uint8_t s[32]) {
  uint8_t x = 0;
  for (uint8_t i = 0; i < 32; i++) x += s[i];
  return x;
}

static bool loadSeed(uint8_t out[32]) {
  memset(out, 0, 32);
  if (EEPROM.read(SEED_FLAG_ADDR) != SEED_FLAG_OK) return false;
  for (uint8_t i = 0; i < 32; i++) out[i] = EEPROM.read(SEED_ADDR + i);
  if (EEPROM.read(SEED_XOR_ADDR) != seedXor(out)) return false;
  if (EEPROM.read(SEED_SUM_ADDR) != seedSum(out)) return false;
  uint8_t any = 0;
  for (uint8_t i = 0; i < 32; i++) any |= out[i];
  return any != 0;
}

static void storeSeed(const uint8_t s[32]) {
  EEPROM.update(SEED_FLAG_ADDR, 0x00);
  for (uint8_t i = 0; i < 32; i++) EEPROM.update(SEED_ADDR + i, s[i]);
  EEPROM.update(SEED_XOR_ADDR, seedXor(s));
  EEPROM.update(SEED_SUM_ADDR, seedSum(s));
  EEPROM.update(SEED_FLAG_ADDR, SEED_FLAG_OK);
}

static void drbgUpdate(const uint8_t *provided, uint8_t providedLen) {
  uint8_t sep = 0x00;
  sha256.resetHMAC(g_drbgK, 32);
  sha256.update(g_drbgV, 32);
  sha256.update(&sep, 1);
  if (providedLen) sha256.update(provided, providedLen);
  sha256.finalizeHMAC(g_drbgK, 32, g_drbgK, 32);

  sha256.resetHMAC(g_drbgK, 32);
  sha256.update(g_drbgV, 32);
  sha256.finalizeHMAC(g_drbgK, 32, g_drbgV, 32);

  if (provided && providedLen) {
    sep = 0x01;
    sha256.resetHMAC(g_drbgK, 32);
    sha256.update(g_drbgV, 32);
    sha256.update(&sep, 1);
    sha256.update(provided, providedLen);
    sha256.finalizeHMAC(g_drbgK, 32, g_drbgK, 32);

    sha256.resetHMAC(g_drbgK, 32);
    sha256.update(g_drbgV, 32);
    sha256.finalizeHMAC(g_drbgK, 32, g_drbgV, 32);
  }
  sha256.clear();
}

// Fills dest from the DRBG. Returns 0 when the DRBG has not been seeded.
static int drbgGenerate(uint8_t *dest, unsigned size) {
  if (!g_drbgReady) return 0;
  for (uint8_t i = 0; i < sizeof(g_drbgExtra); i++) {
    g_drbgExtra[i] = (uint8_t)(analogRead(A0 + (i % 6)) ^ TCNT0);
  }
  drbgUpdate(g_drbgExtra, sizeof(g_drbgExtra));
  while (size) {
    sha256.resetHMAC(g_drbgK, 32);
    sha256.update(g_drbgV, 32);
    sha256.finalizeHMAC(g_drbgK, 32, g_drbgV, 32);
    unsigned take = size > 32 ? 32 : size;
    memcpy(dest, g_drbgV, take);
    dest += take;
    size -= take;
  }
  drbgUpdate(g_drbgExtra, sizeof(g_drbgExtra));
  memset(g_drbgExtra, 0, sizeof(g_drbgExtra));
  sha256.clear();
  return 1;
}

static bool drbgStart(const uint8_t *persisted, const uint8_t pool[32]) {
  uint8_t material[64];
  if (persisted) memcpy(material, persisted, 32);
  else memset(material, 0, 32);
  memcpy(material + 32, pool, 32);

  memset(g_drbgK, 0x00, 32);
  memset(g_drbgV, 0x01, 32);
  drbgUpdate(material, 64);
  memset(material, 0, sizeof(material));

  g_drbgReady = 1;
  if (!drbgGenerate(material, 32) || !drbgGenerate(material + 32, 32)) {
    g_drbgReady = 0;
    memset(g_drbgK, 0, 32);
    memset(g_drbgV, 0, 32);
    memset(material, 0, sizeof(material));
    return false;
  }
  uint8_t diff = 0;
  uint8_t any = 0;
  for (uint8_t i = 0; i < 32; i++) {
    diff |= (uint8_t)(material[i] ^ material[32 + i]);
    any |= material[i];
  }
  if (!diff || !any || !drbgGenerate(material, 32)) {
    g_drbgReady = 0;
    memset(g_drbgK, 0, 32);
    memset(g_drbgV, 0, 32);
    memset(material, 0, sizeof(material));
    return false;
  }
  storeSeed(material);
  memset(material, 0, sizeof(material));
  return true;
}

static void entropyCollectUntil(unsigned long budgetMs) {
  (void)budgetMs;
  if (g_drbgReady || g_entFailed) return;
  uint8_t persisted[32];
  bool seeded = loadSeed(persisted);
  uint8_t pool[32];
  sha256.reset();
  for (uint16_t i = 0; i < 256; i++) {
    if ((i & 31) == 0) wdt_reset();
    uint8_t b = (uint8_t)(analogRead(A0 + (i % 6)) ^ TCNT0 ^ (uint8_t)micros());
    sha256.update(&b, 1);
  }
  char pers[16];
  memcpy_P(pers, PSTR("UNO-FIDO2-DRBG1"), 15);
  sha256.update(pers, 15);
  sha256.finalize(pool, 32);
  sha256.clear();
  if (!drbgStart(seeded ? persisted : 0, pool)) {
    g_entFailed = 1;
  }
  memset(pool, 0, 32);
  memset(persisted, 0, 32);
}

static int RNG(uint8_t *dest, unsigned size) {
  return drbgGenerate(dest, size);
}

int hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// Can safely decode in-place when dest == (uint8_t*)hexStr!
size_t parseHexBuf(const char *hexStr, uint8_t *dest, size_t maxLen) {
  size_t len = strlen(hexStr);
  if (len % 2 != 0) return 0;
  size_t byteLen = len / 2;
  if (byteLen > maxLen) byteLen = maxLen;
  for (size_t i = 0; i < byteLen; i++) {
    int hi = hexVal(hexStr[i * 2]);
    int lo = hexVal(hexStr[i * 2 + 1]);
    if (hi < 0 || lo < 0) return 0;
    dest[i] = (uint8_t)((hi << 4) | lo);
  }
  return byteLen;
}

void printHex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
}

size_t encodeDER(const uint8_t *sig, uint8_t *der) {
  const uint8_t *r = sig;
  const uint8_t *s = sig + 32;

  size_t r_offset = 0;
  while (r_offset < 31 && r[r_offset] == 0) r_offset++;
  size_t r_len = 32 - r_offset;
  bool r_pad = (r[r_offset] & 0x80) != 0;
  if (r_pad) r_len++;

  size_t s_offset = 0;
  while (s_offset < 31 && s[s_offset] == 0) s_offset++;
  size_t s_len = 32 - s_offset;
  bool s_pad = (s[s_offset] & 0x80) != 0;
  if (s_pad) s_len++;

  size_t total_len = 2 + r_len + 2 + s_len;
  size_t idx = 0;

  der[idx++] = 0x30;
  der[idx++] = (uint8_t)total_len;

  der[idx++] = 0x02;
  der[idx++] = (uint8_t)r_len;
  if (r_pad) der[idx++] = 0x00;
  memcpy(der + idx, r + r_offset, 32 - r_offset);
  idx += (32 - r_offset);

  der[idx++] = 0x02;
  der[idx++] = (uint8_t)s_len;
  if (s_pad) der[idx++] = 0x00;
  memcpy(der + idx, s + s_offset, 32 - s_offset);
  idx += (32 - s_offset);

  return idx;
}

// Build 77-byte COSE_Key (EC2, ES256, P-256) from 64-byte raw public key (X||Y)
size_t encodeCOSEKey(const uint8_t *pubKey64, uint8_t *out) {
  size_t idx = 0;
  out[idx++] = 0xA5; // CBOR map(5)
  out[idx++] = 0x01; out[idx++] = 0x02; // 1 (kty): 2 (EC2)
  out[idx++] = 0x03; out[idx++] = 0x26; // 3 (alg): -7 (ES256)
  out[idx++] = 0x20; out[idx++] = 0x01; // -1 (crv): 1 (P-256)
  out[idx++] = 0x21; out[idx++] = 0x58; out[idx++] = 0x20; // -2 (x): bstr(32)
  memcpy(out + idx, pubKey64, 32);
  idx += 32;
  out[idx++] = 0x22; out[idx++] = 0x58; out[idx++] = 0x20; // -3 (y): bstr(32)
  memcpy(out + idx, pubKey64 + 32, 32);
  idx += 32;
  return idx; // 77 bytes
}

void initStorage() {
  bool valid = EEPROM.read(0) == MAGIC_0 && EEPROM.read(1) == MAGIC_1 &&
               EEPROM.read(2) == MAGIC_2 && EEPROM.read(3) == MAGIC_3;
  if (!valid) {
    int n = EEPROM.length();
    for (int i = 0; i < n; i++) {
      EEPROM.update(i, 0x00);
      if ((i & 63) == 0) {
        wdt_reset();
        digitalWrite(LED_PIN, (i & 64) ? HIGH : LOW);
      }
    }
    digitalWrite(LED_PIN, LOW);
    EEPROM.update(0, MAGIC_0);
    EEPROM.update(1, MAGIC_1);
    EEPROM.update(2, MAGIC_2);
    EEPROM.update(3, MAGIC_3);
    g_counter = 1;
    EEPROM.put(4, g_counter);
    g_slotCount = 0;
    EEPROM.update(8, g_slotCount);
    g_storageWiped = 1;
  } else {
    EEPROM.get(4, g_counter);
    g_slotCount = EEPROM.read(8);
    if (g_slotCount > MAX_SLOTS) g_slotCount = 0;
  }
}

void incCounter() {
  g_counter++;
  EEPROM.put(4, g_counter);
}

static int slotAddr(uint8_t idx) {
  return SLOT_BASE_ADDR + (int)idx * (int)sizeof(Fido2Slot);
}

static void eeRead(int addr, uint8_t *dst, uint8_t n) {
  for (uint8_t i = 0; i < n; i++) dst[i] = EEPROM.read(addr + i);
}

static void eeWrite(int addr, const uint8_t *src, uint8_t n) {
  for (uint8_t i = 0; i < n; i++) EEPROM.update(addr + i, src[i]);
}

static bool slotUsed(uint8_t idx) {
  return EEPROM.read(slotAddr(idx) + (int)offsetof(Fido2Slot, valid)) == 0xA5;
}

static uint8_t slotsUsedCount(void) {
  uint8_t n = 0;
  for (uint8_t i = 0; i < MAX_SLOTS; i++) if (slotUsed(i)) n++;
  return n;
}

static void noteSlotCount(void) {
  g_slotCount = slotsUsedCount();
  EEPROM.update(8, g_slotCount);
}

static int allocSlot(void) {
  for (uint8_t i = 0; i < MAX_SLOTS; i++) {
    if (!slotUsed(i)) return i;
  }
  return -1;
}

int findSlotByCredId(const uint8_t *credId) {
  for (uint8_t i = 0; i < MAX_SLOTS; i++) {
    if (!slotUsed(i)) continue;
    uint8_t id[16];
    eeRead(slotAddr(i) + (int)offsetof(Fido2Slot, credId), id, 16);
    if (memcmp(id, credId, 16) == 0) return i;
  }
  return -1;
}

static bool pinIsSet(void) {
  return EEPROM.read(PIN_FLAG_ADDR) == 0xA5;
}

static void clearPinSession(void) {
  // Keep g_pinPriv / g_pinPub. They are the boot-time agreement key, not the
  // PIN. Wiping them forced getKeyAgreement to run P-256 while Windows waited.
  memset(g_pinToken, 0, 32);
  memset(g_blk, 0, 64);
  g_pinPerm = 0;
  g_pinProto = 0;
  g_pinRpBound = 0;
  g_pinConsec = 0;
  EEPROM.update(PIN_RP_FLAG_ADDR, 0x00);
}

static void wipeCredentialsAndPin(void) {
  // Only touch occupied slots — a full 5×179 EEPROM erase took ~3s and
  // made Windows Hello time out mid-reset.
  for (uint8_t i = 0; i < MAX_SLOTS; i++) {
    int base = slotAddr(i);
    if (EEPROM.read(base) != 0xA5) continue;
    for (uint8_t j = 0; j < (uint8_t)sizeof(Fido2Slot); j++)
      EEPROM.update(base + (int)j, 0x00);
  }
  for (uint8_t i = 0; i < 16; i++) EEPROM.update(PIN_HASH_ADDR + i, 0x00);
  EEPROM.update(PIN_FLAG_ADDR, 0x00);
  EEPROM.update(PIN_RETRIES_ADDR, PIN_MAX_RETRIES);
  clearPinSession();
  g_counter = 1;
  EEPROM.put(4, g_counter);
  g_slotCount = 0;
  EEPROM.update(8, 0);
}

int checkAnyButtonPinLow() {
  for (int i = 0; i < NUM_BUTTON_PINS; i++) {
    if (digitalRead(BUTTON_PINS[i]) == LOW) return BUTTON_PINS[i];
  }
  return -1;
}

// Passkey UI (Misskey / smb-chan.dev) drops a CTAP OK that arrives before
// STATUS_UPNEEDED. The 16U2 sends that keepalive for ~0.8s; hold past it.
static void holdBinaryPresence(void) {
  unsigned long start = millis();
  while ((unsigned long)(millis() - start) < 1500) {
    wdt_reset();
    digitalWrite(LED_PIN, ((millis() / 100) & 1) ? HIGH : LOW);
  }
  digitalWrite(LED_PIN, HIGH);
}

bool waitForUserPresence(bool binaryMode = false) {
  // Reset uses this and must return immediately. make/get/selection use
  // holdBinaryPresence instead; a delay here made Windows cancel Reset.
  if (binaryMode) {
    digitalWrite(LED_PIN, HIGH);
    return true;
  }

  unsigned long start = millis();
  bool ledState = false;
  unsigned long lastBlink = 0;
  unsigned long timeoutMs = 25000;

  while (Serial.available()) Serial.read();

  while (millis() - start < timeoutMs) {
    wdt_reset();
    if (millis() - lastBlink > 80) {
      ledState = !ledState;
      digitalWrite(LED_PIN, ledState ? HIGH : LOW);
      lastBlink = millis();
    }

    int triggeredPin = checkAnyButtonPinLow();
    if (triggeredPin >= 0) {
      delay(3);
      if (digitalRead(triggeredPin) == LOW) {
        digitalWrite(LED_PIN, HIGH);
        Serial.println(F("{\"status\":\"PROCESSING\"}"));
        return true;
      }
    }

    if (Serial.available()) {
      char c = Serial.read();
      if (c == 'T' || c == 't') {
        while (Serial.available()) Serial.read();
        digitalWrite(LED_PIN, HIGH);
        Serial.println(F("{\"status\":\"PROCESSING\"}"));
        return true;
      }
    }
    delay(1);
  }

  digitalWrite(LED_PIN, LOW);
  return false;
}

// ============================================================================
// Minimal Zero-Copy CBOR Parser for CTAP2 Commands
// ============================================================================
bool readCborHead(const uint8_t *buf, size_t len, size_t &pos, uint8_t &major, uint32_t &val) {
  if (pos >= len) return false;
  uint8_t b = buf[pos++];
  major = (b >> 5) & 0x07;
  uint8_t info = b & 0x1F;
  if (info < 24) {
    val = info;
  } else if (info == 24) {
    if (pos >= len) return false;
    val = buf[pos++];
  } else if (info == 25) {
    if (pos + 1 >= len) return false;
    val = ((uint32_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2;
  } else if (info == 26) {
    if (pos + 3 >= len) return false;
    val = ((uint32_t)buf[pos] << 24) | ((uint32_t)buf[pos + 1] << 16) |
          ((uint32_t)buf[pos + 2] << 8) | buf[pos + 3];
    pos += 4;
  } else {
    return false;
  }
  return true;
}

bool skipCborItem(const uint8_t *buf, size_t len, size_t &pos) {
  uint8_t major;
  uint32_t val;
  if (!readCborHead(buf, len, pos, major, val)) return false;
  if (major == 0 || major == 1 || major == 7) {
    return true;
  } else if (major == 2 || major == 3) {
    if (pos + val > len) return false;
    pos += val;
    return true;
  } else if (major == 4) {
    // A corrupt length must not spin forever while the 16U2 keepalives.
    if (val > len - pos) return false;
    for (uint32_t i = 0; i < val; i++) {
      if (!skipCborItem(buf, len, pos)) return false;
    }
    return true;
  } else if (major == 5) {
    if (val > len - pos) return false;
    for (uint32_t i = 0; i < val; i++) {
      if (!skipCborItem(buf, len, pos)) return false;
      if (!skipCborItem(buf, len, pos)) return false;
    }
    return true;
  }
  return false;
}

#include "ctap_hello.h"

// ============================================================================
// Binary CTAPHID Packet Handler (for ATmega16U2 Native USB HID Bridge!)
// Frame format between 16U2 and 328P: 0xAA 0x55 [64-byte HID Packet]
// ============================================================================
uint32_t g_cid = 0x01020304;
uint16_t g_hidExpectedLen = 0;
uint16_t g_hidReceivedLen = 0;
uint8_t g_hidActiveCmd = 0;
uint8_t g_hidActiveCid[4];
static uint8_t g_lastSeq = 0;
static bool g_haveSeq = false;
static bool g_beacon = true;
static unsigned long g_beaconAt = 0;
static unsigned long g_partialAt = 0;

void sendHidPacketTo16U2(const uint8_t *pkt64) {
  Serial.write(0xAA);
  Serial.write(0x55);
  Serial.write(pkt64, 64);
}

void sendCtapHidResponse(const uint8_t *cid, uint8_t cmd, const uint8_t *payload, uint16_t len) {
  uint8_t pkt[64];
  memset(pkt, 0, 64);
  memcpy(pkt, cid, 4);
  pkt[4] = cmd | 0x80;
  pkt[5] = (uint8_t)((len >> 8) & 0xFF);
  pkt[6] = (uint8_t)(len & 0xFF);

  uint16_t chunk = (len > 57) ? 57 : len;
  if (chunk > 0) memcpy(pkt + 7, payload, chunk);
  sendHidPacketTo16U2(pkt);

  uint16_t offset = chunk;
  uint8_t seq = 0;
  while (offset < len) {
    memset(pkt, 0, 64);
    memcpy(pkt, cid, 4);
    pkt[4] = seq++ & 0x7F;
    chunk = (len - offset > 59) ? 59 : (len - offset);
    memcpy(pkt + 5, payload + offset, chunk);
    sendHidPacketTo16U2(pkt);
    offset += chunk;
  }
}

void processCompletedCtapHidMessage() {
  if (g_hidActiveCmd == 0x90 && g_hidExpectedLen > CTAP_MAX_MSG) {
    uint8_t err = 0x39;
    sendCtapHidResponse(g_hidActiveCid, 0x90, &err, 1);
    return;
  }
  if (g_hidActiveCmd == 0x90) {
    size_t respLen = executeCtap2InPlace(g_hidReceivedLen, true);
    sendCtapHidResponse(g_hidActiveCid, 0x90, g_ioBuf, respLen);
  } else if (g_hidActiveCmd == 0x81) {
    sendCtapHidResponse(g_hidActiveCid, 0x81, g_ioBuf, g_hidReceivedLen);
  } else if (g_hidActiveCmd == 0x88) {
    for (int i = 0; i < 6; i++) {
      digitalWrite(LED_PIN, i % 2);
      delay(60);
    }
    sendCtapHidResponse(g_hidActiveCid, 0x88, NULL, 0);
  } else if (g_hidActiveCmd == 0x83) {
    // CTAPHID_MSG (U2F APDU): return SW_INS_NOT_SUPPORTED (0x6D00) so host uses CTAP2 CBOR
    uint8_t sw[2] = {0x6D, 0x00};
    sendCtapHidResponse(g_hidActiveCid, 0x83, sw, 2);
  }
}

void handleBinaryHidPacket(const uint8_t *pkt) {
  uint8_t cmdOrSeq = pkt[4];
  if (cmdOrSeq & 0x80) {
    memcpy(g_hidActiveCid, pkt, 4);
    g_hidActiveCmd = cmdOrSeq;
    g_hidExpectedLen = ((uint16_t)pkt[5] << 8) | pkt[6];

    if (cmdOrSeq == 0x86) {
      uint8_t initResp[17];
      memcpy(initResp, pkt + 7, 8);
      g_cid++;
      initResp[8]  = (uint8_t)((g_cid >> 24) & 0xFF);
      initResp[9]  = (uint8_t)((g_cid >> 16) & 0xFF);
      initResp[10] = (uint8_t)((g_cid >> 8) & 0xFF);
      initResp[11] = (uint8_t)(g_cid & 0xFF);
      initResp[12] = 2;
      initResp[13] = 2;
      initResp[14] = 0;
      initResp[15] = 0;
      initResp[16] = 0x05; // WINK(0x01) | CBOR/CTAP2(0x04)
      sendCtapHidResponse(g_hidActiveCid, 0x86, initResp, 17);
      return;
    }

    uint16_t take = (g_hidExpectedLen > 57) ? 57 : g_hidExpectedLen;
    bool store = !(cmdOrSeq == 0x90 && g_hidExpectedLen > CTAP_MAX_MSG);
    if (store) {
      uint16_t copyLen = take;
      if (copyLen > sizeof(g_ioBuf)) copyLen = sizeof(g_ioBuf);
      memcpy(g_ioBuf, pkt + 7, copyLen);
    }
    g_hidReceivedLen = take;
    if (g_hidReceivedLen >= g_hidExpectedLen) g_hidMsgReady = true;
  } else {
    if (g_hidExpectedLen == 0 || g_hidReceivedLen >= g_hidExpectedLen) return;
    uint16_t rem = (uint16_t)(g_hidExpectedLen - g_hidReceivedLen);
    uint16_t take = (rem > 59) ? 59 : rem;
    bool store = !(g_hidActiveCmd == 0x90 && g_hidExpectedLen > CTAP_MAX_MSG);
    if (store && (uint16_t)(g_hidReceivedLen + take) <= sizeof(g_ioBuf)) {
      memcpy(g_ioBuf + g_hidReceivedLen, pkt + 5, take);
    }
    g_hidReceivedLen = (uint16_t)(g_hidReceivedLen + take);
    if (g_hidReceivedLen >= g_hidExpectedLen) g_hidMsgReady = true;
  }
}

// After a watchdog reset the last CTAP command is blinked on the L LED:
// one 120ms flash per command byte, twice, with a 750ms gap (~10s total).
// 0x04 (GetInfo) blinking means the wedge was not command specific;
// 0x01 / 0x06 blinking points at makeCredential / clientPIN.
// The 16U2 waits up to 90s for the ready beacon, which covers this plus the
// boot keygen (one P-256 multiply).
static void reportLastCommand(uint8_t resetFlags) {
  if (!(resetFlags & (1 << WDRF))) return;
  uint8_t n = EEPROM.read(LAST_CMD_ADDR);
  if (n > 12) n = 12;
  for (uint8_t round = 0; round < 2; round++) {
    for (uint8_t i = 0; i < n; i++) {
      wdt_reset();
      digitalWrite(LED_PIN, HIGH); delay(120);
      wdt_reset();
      digitalWrite(LED_PIN, LOW); delay(200);
    }
    for (uint8_t i = 0; i < 3; i++) { wdt_reset(); delay(250); }
  }
}

// setup() is inlined into main otherwise, so its 64-byte HID frame stays
// on the stack through boot keygen and SHA256 overwrites its own state.
__attribute__((noinline))
void setup() {
  // The bootloader leaves the watchdog off. Read why we restarted before
  // clearing the flag: a WDRF here means a previous run was wedged.
  uint8_t resetFlags = MCUSR;
  MCUSR = 0;
  wdt_disable();

  pinMode(LED_PIN, OUTPUT);
  for (int i = 0; i < NUM_BUTTON_PINS; i++) {
    pinMode(BUTTON_PINS[i], INPUT_PULLUP);
  }
  digitalWrite(LED_PIN, LOW);

  if (resetFlags & (1 << WDRF)) {
    uint8_t c = EEPROM.read(WDT_COUNT_ADDR);
    if (c < 255) EEPROM.update(WDT_COUNT_ADDR, (uint8_t)(c + 1));
  }
  reportLastCommand(resetFlags);

  // Arm it after the blink report so a reboot loop still shows the pattern.
  // Every long path (boot keygen, EEPROM wipe, UP wait) feeds it explicitly.
  wdt_enable(WDTO_8S);
  wdt_reset();

  Serial.begin(115200);
  while (!Serial) { ; }

  uECC_set_rng(&RNG);
  initStorage();
  DIDR0 |= 0x3F;
  // Seed before the ready beacon. Collecting this in loop() blocked the UART
  // reader and the next HID frame was dropped.
  entropyCollectUntil(100);

  // One P-256 multiply is several seconds. Do it before the 0xA6 beacon so
  // Windows Hello's getKeyAgreement does not sit on KEEPALIVE until it cancels.
  if (g_drbgReady) {
    digitalWrite(LED_PIN, HIGH);
    if (gen_pin_key()) {
      memcpy(g_pinPub, g_blk, 64);
      memset(g_blk, 0, 64);
      g_havePinKey = 1;
    }
    digitalWrite(LED_PIN, LOW);
  }

  // No BOOT JSON on Serial: the same UART is the 16U2 HID bridge.
  g_entropyReported = g_drbgReady ? 1 : (g_entFailed ? 2 : 0);
}

static void flushHidRx(void) {
  while (Serial.available()) Serial.read();
}

// Gap of a few milliseconds means the 16U2 stopped. Drop the partial frame
// so the retry (same 0xAA 0x55 <seq>) is not glued onto the tail.
__attribute__((noinline))
static bool readExact(uint8_t *dst, uint8_t n) {
  unsigned long last = millis();
  uint8_t got = 0;
  while (got < n) {
    if (Serial.available()) {
      dst[got++] = (uint8_t)Serial.read();
      last = millis();
    } else if ((unsigned long)(millis() - last) > 6) {
      return false;
    }
  }
  return true;
}

static void ackFrame(uint8_t seq) {
  Serial.write((uint8_t)0xA5);
  Serial.write(seq);
}

// Returns true when a full CTAP message is sitting in g_ioBuf.
// The 64-byte frame lives only in this frame, so it is popped before uECC.
__attribute__((noinline))
static bool takeHidFrame(void) {
  if ((uint8_t)Serial.read() != 0xAA) return false;
  uint8_t mark = 0;
  uint8_t seq = 0;
  uint8_t pkt[64];
  if (!readExact(&mark, 1) || mark != 0x55 ||
      !readExact(&seq, 1) || !readExact(pkt, 64)) {
    flushHidRx();
    return false;
  }
  g_beacon = false;
  bool isInit = (pkt[4] & 0x80) != 0;
  if (!isInit && g_haveSeq && seq == g_lastSeq) {
    ackFrame(seq);
    return false;
  }
  g_lastSeq = seq;
  g_haveSeq = true;
  ackFrame(seq);
  g_partialAt = millis();
  handleBinaryHidPacket(pkt);
  if (!g_hidMsgReady) return false;
  g_hidMsgReady = false;
  return true;
}

__attribute__((noinline))
void loop() {
  wdt_reset();
  // Ready beacon. The 16U2 does not forward a host request until it sees 0xA6,
  // so a multi-frame CTAP message cannot arrive during initStorage.
  if (g_beacon && !Serial.available() &&
      (unsigned long)(millis() - g_beaconAt) >= 40) {
    Serial.write((uint8_t)0xA6);
    g_beaconAt = millis();
  }
  if (g_hidExpectedLen && g_hidReceivedLen < g_hidExpectedLen &&
      (unsigned long)(millis() - g_partialAt) > 50) {
    g_hidExpectedLen = 0;
    g_hidReceivedLen = 0;
    g_hidMsgReady = false;
  }

  bool runCtap = false;
  while (Serial.available()) {
    if (takeHidFrame()) {
      runCtap = true;
      break;
    }
  }
  if (runCtap) {
    processCompletedCtapHidMessage();
    g_hidExpectedLen = 0;
    g_hidReceivedLen = 0;
  }

  if (g_entFailed) {
    unsigned long now = millis();
    if ((unsigned long)(now - g_failBlinkAt) >= 500) {
      g_failBlinkAt = now;
      digitalWrite(LED_PIN, digitalRead(LED_PIN) == LOW ? HIGH : LOW);
    }
  }
  int8_t entState = g_drbgReady ? 1 : (g_entFailed ? 2 : 0);
  if (entState != g_entropyReported) {
    g_entropyReported = entState;
  }
}
