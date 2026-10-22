// CTAP clientPIN, discoverable credentials, hmac-secret, credProtect.
// Scratch at g_ioBuf[SCRATCH_OFF] is only used after the request bytes are parsed.
// ECC helpers are noinline so AES and CBOR frames are not live on the sign path.

enum {
  OFF_VALID = offsetof(Fido2Slot, valid),
  OFF_CP = offsetof(Fido2Slot, credProtect),
  OFF_ULEN = offsetof(Fido2Slot, userIdLen),
  OFF_UID = offsetof(Fido2Slot, userId),
  OFF_CRED = offsetof(Fido2Slot, credId),
  OFF_RP = offsetof(Fido2Slot, rpIdHash),
  OFF_PRIV = offsetof(Fido2Slot, privKey),
  OFF_RAND = offsetof(Fido2Slot, credRandom)
};

static uint16_t g_msgLen = 0;

static size_t ctapErr(uint8_t code) {
  g_ioBuf[0] = code;
  return 1;
}

// uECC reuses g_ioBuf[0..511]. Keep the parsed request and put it back after.
static bool eccSaveIo(void) {
  if (g_msgLen > sizeof(g_eccHold)) return false;
  if (g_msgLen) memcpy(g_eccHold, g_ioBuf, g_msgLen);
  return true;
}

static void eccRestoreIo(void) {
  if (g_msgLen && g_msgLen <= sizeof(g_eccHold))
    memcpy(g_ioBuf, g_eccHold, g_msgLen);
}

static void clearReq(void) {
  g_reqProto = 0;
  g_credProtect = 1;
  g_hmacProto = 1;
  g_reqFlags = 0;
  g_hasAllow = 0;
  g_hasHmacGet = 0;
  g_userLen = 0;
  g_pinSub = 0;
  g_reqPerm = 0;
  g_listN = 0;
  g_exclIdx = -1;
  g_chosen = -1;
  g_pinAuthOff = g_pinAuthLen = 0;
  g_hasPinAuth = 0;
  g_bOff = g_bLen = 0;
  g_cOff = g_cLen = 0;
  g_xOff = g_yOff = 0;
  g_rpOff = g_rpLen = 0;
  g_userOff = 0;
}

static bool cborInt(const uint8_t *b, size_t len, size_t &pos, int32_t &out) {
  uint8_t maj;
  uint32_t v;
  if (!readCborHead(b, len, pos, maj, v)) return false;
  if (maj == 0) { out = (int32_t)v; return true; }
  if (maj == 1) { out = -1 - (int32_t)v; return true; }
  return false;
}

static bool takeRaw(const uint8_t *b, size_t len, size_t &pos, uint8_t want,
                    uint16_t &off, uint16_t &rawLen) {
  uint8_t maj;
  uint32_t v;
  if (!readCborHead(b, len, pos, maj, v) || maj != want) return false;
  if ((size_t)pos + v > len || v > 0xFFFF) return false;
  off = (uint16_t)((b + pos) - g_ioBuf);
  rawLen = (uint16_t)v;
  pos += v;
  return true;
}

static bool ensureEntropy(void) {
  if (g_drbgReady) return true;
  if (g_entFailed) return false;
  entropyCollectUntil(8000);
  return g_drbgReady != 0;
}

__attribute__((noinline))
static bool mac_eq(const uint8_t *key, const uint8_t *m1, uint16_t n1,
                   const uint8_t *m2, uint16_t n2,
                   const uint8_t *expect, uint8_t elen) {
  uint8_t *mac = g_secTmp;
  sha256.resetHMAC(key, 32);
  if (n1) sha256.update(m1, n1);
  if (m2 && n2) sha256.update(m2, n2);
  sha256.finalizeHMAC(key, 32, mac, 32);
  sha256.clear();
  uint8_t diff = 0;
  for (uint8_t i = 0; i < elen; i++) diff |= (uint8_t)(mac[i] ^ expect[i]);
  memset(mac, 0, 32);
  return diff == 0;
}

__attribute__((noinline))
static void hkdf32(const uint8_t *ikm, uint8_t out64[64]) {
  // ECDH has returned, so g_secTmp is free. These used to sit under HMAC
  // and overwrite the SHA-256 object, which made setPIN return 0x33.
  uint8_t *salt = g_secTmp;
  uint8_t *prk = g_secTmp + 32;
  uint8_t *info = g_secTmp + 64;
  memset(salt, 0, 32);
  sha256.resetHMAC(salt, 32);
  sha256.update(ikm, 32);
  sha256.finalizeHMAC(salt, 32, prk, 32);
  memcpy_P(info, PSTR("CTAP2 HMAC key"), 14);
  info[14] = 0x01;
  sha256.resetHMAC(prk, 32);
  sha256.update(info, 15);
  sha256.finalizeHMAC(prk, 32, out64, 32);
  memcpy_P(info, PSTR("CTAP2 AES key"), 13);
  info[13] = 0x01;
  sha256.resetHMAC(prk, 32);
  sha256.update(info, 14);
  sha256.finalizeHMAC(prk, 32, out64 + 32, 32);
  sha256.clear();
  memset(prk, 0, 32);
  memset(salt, 0, 32);
  memset(info, 0, 16);
}

__attribute__((noinline))
static bool ecdh_keys(uint8_t proto) {
  if (!uECC_shared_secret(g_blk, g_pinPriv, g_ioBuf + SCRATCH_OFF, uECC_secp256r1()))
    return false;
  if (proto == 1) {
    sha256.reset();
    sha256.update(g_ioBuf + SCRATCH_OFF, 32);
    sha256.finalize(g_blk, 32);
    memcpy(g_blk + 32, g_blk, 32);
    sha256.clear();
  } else {
    hkdf32(g_ioBuf + SCRATCH_OFF, g_blk);
  }
  memset(g_ioBuf + SCRATCH_OFF, 0, 32);
  return true;
}

// aes_cbc provided by aes256_tiny.h

__attribute__((noinline))
static bool gen_pin_key(void) {
  // HMAC-DRBG then the multiply. A timer interrupt on that stack
  // lands inside the SHA256 object. Hold interrupts off until it returns.
  cli();
  bool ok = uECC_make_key(g_blk, g_pinPriv, uECC_secp256r1()) == 1;
  sei();
  return ok;
}

__attribute__((noinline))
static bool make_key_pub(void) {
  return uECC_make_key(g_blk, g_ioBuf + SCRATCH_OFF, uECC_secp256r1()) == 1;
}

__attribute__((noinline))
static bool sign_priv(const uint8_t *priv, const uint8_t *hash, uint8_t *sig) {
  return uECC_sign(priv, hash, 32, sig, uECC_secp256r1()) == 1;
}

static bool peerToBlk(void) {
  if (g_xOff == 0 || g_yOff == 0) return false;
  if ((uint32_t)g_xOff + 32 > g_msgLen || (uint32_t)g_yOff + 32 > g_msgLen) return false;
  memcpy(g_blk, g_ioBuf + g_xOff, 32);
  memcpy(g_blk + 32, g_ioBuf + g_yOff, 32);
  return true;
}

static uint8_t pinVerifyHash(const uint8_t got[16]) {
  if (!pinIsSet()) return 0x35;
  uint8_t retries = EEPROM.read(PIN_RETRIES_ADDR);
  if (retries == 0) return 0x32;
  if (g_pinConsec >= 3) return 0x34;
  uint8_t stored[16];
  eeRead(PIN_HASH_ADDR, stored, 16);
  uint8_t diff = 0;
  for (uint8_t i = 0; i < 16; i++) diff |= (uint8_t)(stored[i] ^ got[i]);
  memset(stored, 0, 16);
  if (diff) {
    if (retries) retries--;
    EEPROM.update(PIN_RETRIES_ADDR, retries);
    if (g_pinConsec < 255) g_pinConsec++;
    if (retries == 0) return 0x32;
    if (g_pinConsec >= 3) return 0x34;
    return 0x31;
  }
  EEPROM.update(PIN_RETRIES_ADDR, PIN_MAX_RETRIES);
  g_pinConsec = 0;
  return 0x00;
}

__attribute__((noinline))
static uint8_t pinPolicy(const uint8_t *p64, uint8_t out16[16]) {
  uint8_t n = 0;
  while (n < 64 && p64[n] != 0) n++;
  if (n < 4 || n > 63) return 0x37;
  for (uint8_t i = n; i < 64; i++) if (p64[i] != 0) return 0x37;
  sha256.reset();
  sha256.update(p64, n);
  uint8_t *full = g_secTmp;
  sha256.finalize(full, 32);
  memcpy(out16, full, 16);
  memset(full, 0, 32);
  sha256.clear();
  return 0x00;
}

static void storePinHash(const uint8_t h[16]) {
  eeWrite(PIN_HASH_ADDR, h, 16);
  EEPROM.update(PIN_RETRIES_ADDR, PIN_MAX_RETRIES);
  EEPROM.update(PIN_FLAG_ADDR, 0xA5);
  g_pinConsec = 0;
  memset(g_pinToken, 0, 32);
  g_pinPerm = 0;
  g_pinRpBound = 0;
  EEPROM.update(PIN_RP_FLAG_ADDR, 0x00);
}

__attribute__((noinline))
static uint8_t decryptPinHash(uint8_t proto) {
  uint8_t plain[16];
  uint8_t iv[16];
  uint16_t need = (proto == 1) ? 16 : 32;
  if (g_cLen != need || (uint32_t)g_cOff + g_cLen > g_msgLen) return 0x02;
  if (proto == 1) {
    memset(iv, 0, 16);
    memcpy(plain, g_ioBuf + g_cOff, 16);
  } else {
    memcpy(iv, g_ioBuf + g_cOff, 16);
    memcpy(plain, g_ioBuf + g_cOff + 16, 16);
  }
  if (!aes_cbc(0, g_blk + 32, iv, plain, 1)) {
    memset(plain, 0, 16);
    memset(iv, 0, 16);
    return 0x7F;
  }
  uint8_t st = pinVerifyHash(plain);
  memset(plain, 0, 16);
  memset(iv, 0, 16);
  return st;
}

__attribute__((noinline))
static uint8_t decryptNewPin(uint8_t proto, uint8_t outHash[16]) {
  uint16_t need = (proto == 1) ? 64 : 80;
  if (g_bLen != need || (uint32_t)g_bOff + g_bLen > g_msgLen) return 0x02;
  uint8_t iv[16];
  uint8_t *data;
  if (proto == 1) {
    memset(iv, 0, 16);
    data = g_ioBuf + g_bOff;
  } else {
    memcpy(iv, g_ioBuf + g_bOff, 16);
    data = g_ioBuf + g_bOff + 16;
  }
  if (!aes_cbc(0, g_blk + 32, iv, data, 4)) {
    memset(iv, 0, 16);
    return 0x7F;
  }
  uint8_t st = pinPolicy(data, outHash);
  memset(data, 0, 64);
  memset(iv, 0, 16);
  return st;
}

static size_t encodeCoseAgree(const uint8_t *pub, uint8_t *out) {
  size_t i = 0;
  out[i++] = 0xA5;
  out[i++] = 0x01; out[i++] = 0x02;
  out[i++] = 0x03; out[i++] = 0x38; out[i++] = 0x18;
  out[i++] = 0x20; out[i++] = 0x01;
  out[i++] = 0x21; out[i++] = 0x58; out[i++] = 0x20;
  memcpy(out + i, pub, 32); i += 32;
  out[i++] = 0x22; out[i++] = 0x58; out[i++] = 0x20;
  memcpy(out + i, pub + 32, 32); i += 32;
  return i;
}

static bool parseCose(const uint8_t *b, size_t len, size_t &pos) {
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return false;
  uint16_t x = 0, y = 0;
  for (uint32_t i = 0; i < pairs; i++) {
    int32_t k;
    if (!cborInt(b, len, pos, k)) return false;
    if (k == -2 || k == -3) {
      uint16_t off, bl;
      if (!takeRaw(b, len, pos, 2, off, bl) || bl != 32) return false;
      if (k == -2) x = off;
      else y = off;
    } else if (k == -1 || k == 1) {
      int32_t v;
      if (!cborInt(b, len, pos, v)) return false;
      if (k == -1 && v != 1) return false;
      if (k == 1 && v != 2) return false;
    } else if (!skipCborItem(b, len, pos)) {
      return false;
    }
  }
  if (!x || !y) return false;
  g_xOff = x;
  g_yOff = y;
  return true;
}

static bool hashToBlk(uint16_t off, uint16_t n) {
  if (n == 0) return false;
  sha256.reset();
  sha256.update(g_ioBuf + off, n);
  sha256.finalize(g_blk, 32);
  sha256.clear();
  g_reqFlags |= RF_RP;
  return true;
}

static bool parseRpMap(const uint8_t *b, size_t len, size_t &pos) {
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return false;
  for (uint32_t i = 0; i < pairs; i++) {
    uint16_t koff, klen;
    if (!takeRaw(b, len, pos, 3, koff, klen)) return false;
    if (klen == 2 && memcmp(g_ioBuf + koff, "id", 2) == 0) {
      uint16_t voff, vlen;
      if (!takeRaw(b, len, pos, 3, voff, vlen)) return false;
      if (!hashToBlk(voff, vlen)) return false;
    } else if (!skipCborItem(b, len, pos)) {
      return false;
    }
  }
  return true;
}

static bool parseUser(const uint8_t *b, size_t len, size_t &pos) {
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return false;
  for (uint32_t i = 0; i < pairs; i++) {
    uint16_t koff, klen;
    if (!takeRaw(b, len, pos, 3, koff, klen)) return false;
    if (klen == 2 && memcmp(g_ioBuf + koff, "id", 2) == 0) {
      uint16_t voff, vlen;
      if (!takeRaw(b, len, pos, 2, voff, vlen)) return false;
      if (vlen > USER_ID_MAX) g_userLen = 0xFF;
      else {
        g_userOff = voff;
        g_userLen = (uint8_t)vlen;
      }
    } else if (!skipCborItem(b, len, pos)) {
      return false;
    }
  }
  return true;
}

static bool parseParams(const uint8_t *b, size_t len, size_t &pos) {
  uint8_t maj;
  uint32_t n;
  if (!readCborHead(b, len, pos, maj, n) || maj != 4) return false;
  for (uint32_t a = 0; a < n; a++) {
    uint8_t dm;
    uint32_t pairs;
    if (!readCborHead(b, len, pos, dm, pairs) || dm != 5) return false;
    for (uint32_t j = 0; j < pairs; j++) {
      uint16_t koff, klen;
      if (!takeRaw(b, len, pos, 3, koff, klen)) return false;
      if (klen == 3 && memcmp(g_ioBuf + koff, "alg", 3) == 0) {
        int32_t alg;
        if (!cborInt(b, len, pos, alg)) return false;
        if (alg == -7) g_reqFlags |= RF_ES256;
      } else if (!skipCborItem(b, len, pos)) {
        return false;
      }
    }
  }
  return true;
}

static bool parseCredList(const uint8_t *b, size_t len, size_t &pos, bool allow) {
  uint8_t maj;
  uint32_t n;
  if (!readCborHead(b, len, pos, maj, n) || maj != 4) return false;
  if (allow) g_hasAllow = 1;
  for (uint32_t i = 0; i < n; i++) {
    uint8_t dm;
    uint32_t pairs;
    if (!readCborHead(b, len, pos, dm, pairs) || dm != 5) return false;
    for (uint32_t j = 0; j < pairs; j++) {
      uint16_t koff, klen;
      if (!takeRaw(b, len, pos, 3, koff, klen)) return false;
      if (klen == 2 && memcmp(g_ioBuf + koff, "id", 2) == 0) {
        uint16_t voff, vlen;
        if (!takeRaw(b, len, pos, 2, voff, vlen)) return false;
        if (vlen == 16 && g_listN < MAX_SLOTS) {
          int idx = findSlotByCredId(g_ioBuf + voff);
          if (idx >= 0) g_list[g_listN++] = (int8_t)idx;
        }
      } else if (!skipCborItem(b, len, pos)) {
        return false;
      }
    }
  }
  return true;
}

static bool parseOptions(const uint8_t *b, size_t len, size_t &pos) {
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return false;
  for (uint32_t i = 0; i < pairs; i++) {
    uint16_t koff, klen;
    if (!takeRaw(b, len, pos, 3, koff, klen)) return false;
    uint8_t vm;
    uint32_t vv;
    if (!readCborHead(b, len, pos, vm, vv) || vm != 7) return false;
    if (vv != 20 && vv != 21) return false;
    bool on = (vv == 21);
    if (klen == 2 && memcmp(g_ioBuf + koff, "rk", 2) == 0) {
      if (!on) g_reqFlags |= RF_RK_FALSE;
    } else if (klen == 2 && memcmp(g_ioBuf + koff, "uv", 2) == 0) {
      if (on) g_reqFlags |= RF_UV;
    } else if (klen == 2 && memcmp(g_ioBuf + koff, "up", 2) == 0) {
      if (!on) g_reqFlags |= RF_UP_FALSE;
    }
  }
  return true;
}

static bool parseHmacGet(const uint8_t *b, size_t len, size_t &pos) {
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return false;
  for (uint32_t i = 0; i < pairs; i++) {
    int32_t k;
    if (!cborInt(b, len, pos, k)) return false;
    if (k == 1) {
      if (!parseCose(b, len, pos)) return false;
    } else if (k == 2) {
      if (!takeRaw(b, len, pos, 2, g_bOff, g_bLen)) return false;
    } else if (k == 3) {
      if (!takeRaw(b, len, pos, 2, g_cOff, g_cLen)) return false;
    } else if (k == 4) {
      int32_t v;
      if (!cborInt(b, len, pos, v)) return false;
      g_hmacProto = (v == 1 || v == 2) ? (uint8_t)v : 0xFF;
    } else if (!skipCborItem(b, len, pos)) {
      return false;
    }
  }
  return true;
}

static bool parseExt(const uint8_t *b, size_t len, size_t &pos, bool make) {
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return false;
  for (uint32_t i = 0; i < pairs; i++) {
    uint16_t koff, klen;
    if (!takeRaw(b, len, pos, 3, koff, klen)) return false;
    bool hmac = (klen == 11 && memcmp(g_ioBuf + koff, "hmac-secret", 11) == 0);
    bool cp = (klen == 11 && memcmp(g_ioBuf + koff, "credProtect", 11) == 0);
    if (make && hmac) {
      uint8_t vm;
      uint32_t vv;
      if (!readCborHead(b, len, pos, vm, vv) || vm != 7) return false;
      if (vv == 21) g_reqFlags |= RF_HMAC;
    } else if (make && cp) {
      int32_t v;
      if (!cborInt(b, len, pos, v)) return false;
      if (v < 1 || v > 3) return false;
      g_credProtect = (uint8_t)v;
      g_reqFlags |= RF_CP;
    } else if (!make && hmac) {
      if (!parseHmacGet(b, len, pos)) return false;
      g_hasHmacGet = 1;
    } else if (!skipCborItem(b, len, pos)) {
      return false;
    }
  }
  return true;
}

static bool takeHash(const uint8_t *b, size_t len, size_t &pos) {
  uint16_t off, n;
  if (!takeRaw(b, len, pos, 2, off, n) || n != 32) return false;
  memcpy(g_clientHash, g_ioBuf + off, 32);
  g_reqFlags |= RF_HASH;
  return true;
}

static uint8_t parseMakeGet(uint8_t cmd, size_t reqLen) {
  clearReq();
  if (cmd == 0x01) g_reqFlags |= RF_ES256;
  if (reqLen < 2) return 0x14;
  const uint8_t *b = g_ioBuf + 1;
  size_t len = reqLen - 1;
  size_t pos = 0;
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return 0x12;
  for (uint32_t i = 0; i < pairs; i++) {
    int32_t k;
    if (!cborInt(b, len, pos, k)) return 0x12;
    bool ok = true;
    if (cmd == 0x01) {
      if (k == 1) ok = takeHash(b, len, pos);
      else if (k == 2) ok = parseRpMap(b, len, pos);
      else if (k == 3) ok = parseUser(b, len, pos);
      else if (k == 4) {
        g_reqFlags &= (uint8_t)~RF_ES256;
        ok = parseParams(b, len, pos);
      } else if (k == 5) ok = parseCredList(b, len, pos, false);
      else if (k == 6) ok = parseExt(b, len, pos, true);
      else if (k == 7) ok = parseOptions(b, len, pos);
      else if (k == 8) {
        ok = takeRaw(b, len, pos, 2, g_pinAuthOff, g_pinAuthLen);
        if (ok) g_hasPinAuth = 1;
      }
      else if (k == 9) {
        int32_t v;
        ok = cborInt(b, len, pos, v);
        if (ok) g_reqProto = (v == 1 || v == 2) ? (uint8_t)v : 0xFF;
      } else ok = skipCborItem(b, len, pos);
    } else {
      if (k == 1) {
        uint16_t off, n;
        ok = takeRaw(b, len, pos, 3, off, n) && hashToBlk(off, n);
      } else if (k == 2) ok = takeHash(b, len, pos);
      else if (k == 3) ok = parseCredList(b, len, pos, true);
      else if (k == 4) ok = parseExt(b, len, pos, false);
      else if (k == 5) ok = parseOptions(b, len, pos);
      else if (k == 6) {
        ok = takeRaw(b, len, pos, 2, g_pinAuthOff, g_pinAuthLen);
        if (ok) g_hasPinAuth = 1;
      }
      else if (k == 7) {
        int32_t v;
        ok = cborInt(b, len, pos, v);
        if (ok) g_reqProto = (v == 1 || v == 2) ? (uint8_t)v : 0xFF;
      } else ok = skipCborItem(b, len, pos);
    }
    if (!ok) return 0x12;
  }
  return 0x00;
}

static uint8_t parseClientPin(size_t reqLen) {
  clearReq();
  if (reqLen < 2) return 0x14;
  const uint8_t *b = g_ioBuf + 1;
  size_t len = reqLen - 1;
  size_t pos = 0;
  uint8_t maj;
  uint32_t pairs;
  if (!readCborHead(b, len, pos, maj, pairs) || maj != 5) return 0x12;
  bool sawSub = false;
  for (uint32_t i = 0; i < pairs; i++) {
    int32_t k;
    if (!cborInt(b, len, pos, k)) return 0x12;
    if (k == 1) {
      int32_t v;
      if (!cborInt(b, len, pos, v)) return 0x12;
      g_reqProto = (v == 1 || v == 2) ? (uint8_t)v : 0xFF;
    } else if (k == 2) {
      int32_t v;
      if (!cborInt(b, len, pos, v) || v < 0 || v > 255) return 0x12;
      g_pinSub = (uint8_t)v;
      sawSub = true;
    } else if (k == 3) {
      if (!parseCose(b, len, pos)) return 0x12;
    } else if (k == 4) {
      if (!takeRaw(b, len, pos, 2, g_pinAuthOff, g_pinAuthLen)) return 0x12;
      g_hasPinAuth = 1;
    } else if (k == 5) {
      if (!takeRaw(b, len, pos, 2, g_bOff, g_bLen)) return 0x12;
    } else if (k == 6) {
      if (!takeRaw(b, len, pos, 2, g_cOff, g_cLen)) return 0x12;
    } else if (k == 9) {
      int32_t v;
      if (!cborInt(b, len, pos, v) || v < 0 || v > 255) return 0x12;
      g_reqPerm = (uint8_t)v;
    } else if (k == 10) {
      if (!takeRaw(b, len, pos, 3, g_rpOff, g_rpLen)) return 0x12;
    } else if (!skipCborItem(b, len, pos)) {
      return 0x12;
    }
  }
  if (!sawSub) return 0x14;
  return 0x00;
}

// 0xFE = pinUvAuthParam omitted. 0xFD = present but zero-length (Windows Hello probe).
static uint8_t checkPinToken(uint8_t needPerm) {
  if (!g_hasPinAuth) return 0xFE;
  if (g_pinAuthLen == 0) return 0xFD;
  if (g_reqProto == 0) return 0x14;
  if (g_reqProto == 0xFF || (g_reqProto != 1 && g_reqProto != 2)) return 0x02;
  uint8_t expect = (g_reqProto == 1) ? 16 : 32;
  if (g_pinAuthLen != expect || g_pinProto != g_reqProto) return 0x33;
  if ((g_pinPerm & needPerm) != needPerm) return 0x33;
  if (g_pinRpBound) {
    uint8_t diff = 0;
    for (uint8_t i = 0; i < 32; i++) diff |= (uint8_t)(EEPROM.read(PIN_RP_ADDR + i) ^ g_blk[i]);
    if (diff) return 0x33;
  }
  if ((uint32_t)g_pinAuthOff + g_pinAuthLen > g_msgLen) return 0x33;
  if (!mac_eq(g_pinToken, g_clientHash, 32, 0, 0, g_ioBuf + g_pinAuthOff, expect))
    return 0x33;
  return 0x00;
}

static uint8_t doUp(bool binaryMode) {
  if (g_reqFlags & RF_UP_FALSE) return 0x00;
  if (!binaryMode) Serial.println(F("{\"status\":\"WAITING_USER_PRESENCE\",\"protocol\":\"CTAP2\"}"));
  if (binaryMode) {
    holdBinaryPresence();
    return 0x00;
  }
  if (!waitForUserPresence(false)) return 0x2D;
  return 0x00;
}

// CTAP2.1: an empty pinUvAuthParam is a UP probe, not a PIN attempt.
// Reply PIN_INVALID when a PIN exists and PIN_NOT_SET when it does not.
// Never touch the stored PIN here; Windows uses the reply to pick the device.
static size_t emptyPinAuthProbe(bool binaryMode) {
  uint8_t up = doUp(binaryMode);
  if (up) return ctapErr(up);
  digitalWrite(LED_PIN, LOW);
  return ctapErr(pinIsSet() ? 0x31 : 0x35);
}

static uint8_t upBit(void) {
  return (g_reqFlags & RF_UP_FALSE) ? 0 : 0x01;
}

static void resolveExclude(void) {
  g_exclIdx = -1;
  for (uint8_t i = 0; i < g_listN; i++) {
    uint8_t idx = (uint8_t)g_list[i];
    uint8_t diff = 0;
    int addr = slotAddr(idx) + OFF_RP;
    for (uint8_t k = 0; k < 32; k++) diff |= (uint8_t)(EEPROM.read(addr + k) ^ g_blk[k]);
    if (!diff) {
      g_exclIdx = (int8_t)idx;
      return;
    }
  }
}

static bool rpMatch(uint8_t idx) {
  uint8_t diff = 0;
  int addr = slotAddr(idx) + OFF_RP;
  for (uint8_t k = 0; k < 32; k++) diff |= (uint8_t)(EEPROM.read(addr + k) ^ g_blk[k]);
  return diff == 0;
}

static bool credUsable(uint8_t idx, bool haveUv, bool inAllow) {
  uint8_t cp = EEPROM.read(slotAddr(idx) + OFF_CP);
  if (cp < 1 || cp > 3) cp = 1;
  if (cp >= 3 && !haveUv) return false;
  if (cp == 2 && !haveUv && !inAllow) return false;
  return true;
}

static uint8_t selectCred(bool haveUv) {
  bool anyRp = false;
  g_chosen = -1;
  if (g_hasAllow) {
    for (uint8_t i = 0; i < g_listN; i++) {
      uint8_t idx = (uint8_t)g_list[i];
      if (!rpMatch(idx)) continue;
      anyRp = true;
      if (credUsable(idx, haveUv, true) && g_chosen < 0) g_chosen = (int8_t)idx;
    }
  } else {
    for (int i = MAX_SLOTS - 1; i >= 0; --i) {
      if (!slotUsed((uint8_t)i) || !rpMatch((uint8_t)i)) continue;
      anyRp = true;
      if (credUsable((uint8_t)i, haveUv, false)) {
        g_chosen = (int8_t)i;
        break;
      }
    }
  }
  if (g_chosen >= 0) return 0x00;
  if (!anyRp) return 0x2E;
  return 0x36;
}

static void putCounter(uint8_t *p, uint32_t cnt) {
  p[0] = (uint8_t)((cnt >> 24) & 0xFF);
  p[1] = (uint8_t)((cnt >> 16) & 0xFF);
  p[2] = (uint8_t)((cnt >> 8) & 0xFF);
  p[3] = (uint8_t)(cnt & 0xFF);
}

__attribute__((noinline))
static bool writeNewSlot(int slot) {
  int base = slotAddr((uint8_t)slot);
  eeWrite(base + OFF_RP, g_blk, 32);
  uint8_t ulen = (g_userLen == 0xFF) ? 0 : g_userLen;
  if (ulen) eeWrite(base + OFF_UID, g_ioBuf + g_userOff, ulen);
  EEPROM.update(base + OFF_ULEN, ulen);
  EEPROM.update(base + OFF_CP, g_credProtect);
  uint8_t tmp[32];
  if (!RNG(tmp, 16)) return false;
  eeWrite(base + OFF_CRED, tmp, 16);
  if (!RNG(tmp, 32)) return false;
  eeWrite(base + OFF_RAND, tmp, 32);
  memset(tmp, 0, 32);
  return true;
}

__attribute__((noinline))
static size_t finishMake(int slot, bool haveUv) {
  int base = slotAddr((uint8_t)slot);
  uint8_t *r = g_ioBuf;
  r[0] = 0x00;
  r[1] = 0xA3;
  r[2] = 0x01;
  r[3] = 0x66;
  memcpy_P(r + 4, PSTR("packed"), 6);
  r[10] = 0x02;
  r[11] = 0x58;
  uint8_t *ad = r + 13;
  eeRead(base + OFF_RP, ad, 32);
  bool wantH = (g_reqFlags & RF_HMAC) != 0;
  bool wantC = (g_reqFlags & RF_CP) != 0;
  uint8_t flags = (uint8_t)(0x40 | upBit());
  if (haveUv) flags |= 0x04;
  if (wantH || wantC) flags |= 0x80;
  ad[32] = flags;
  putCounter(ad + 33, g_counter);
  memcpy_P(ad + 37, AAGUID, 16);
  ad[53] = 0x00;
  ad[54] = 0x10;
  eeRead(base + OFF_CRED, ad + 55, 16);
  encodeCOSEKey(g_blk, ad + 71);
  memset(g_blk, 0, 64);
  size_t adLen = 148;
  if (wantH || wantC) {
    uint8_t *e = ad + 148;
    size_t ei = 1;
    e[0] = (wantH && wantC) ? 0xA2 : 0xA1;
    if (wantC) {
      e[ei++] = 0x6B;
      memcpy_P(e + ei, PSTR("credProtect"), 11);
      ei += 11;
      e[ei++] = g_credProtect;
    }
    if (wantH) {
      e[ei++] = 0x6B;
      memcpy_P(e + ei, PSTR("hmac-secret"), 11);
      ei += 11;
      e[ei++] = 0xF5;
    }
    adLen = 148 + ei;
  }
  r[12] = (uint8_t)adLen;
  sha256.reset();
  sha256.update(ad, adLen);
  sha256.update(g_clientHash, 32);
  sha256.finalize(g_clientHash, 32);
  sha256.clear();
  if (13 + adLen > SCRATCH_OFF || 13 + adLen > sizeof(g_eccHold)) {
    EEPROM.update(base + OFF_VALID, 0x00);
    noteSlotCount();
    return ctapErr(0x7F);
  }
  // sign reuses g_ioBuf[0..511] as ECC workspace. The authData prefix is rebuilt
  // from this copy; the private key sits at SCRATCH_OFF (512) and is not copied.
  memcpy(g_eccHold, g_ioBuf, 13 + adLen);
  eeRead(base + OFF_PRIV, g_ioBuf + SCRATCH_OFF, 32);
  if (!sign_priv(g_ioBuf + SCRATCH_OFF, g_clientHash, g_blk)) {
    memset(g_ioBuf + SCRATCH_OFF, 0, 32);
    EEPROM.update(base + OFF_VALID, 0x00);
    noteSlotCount();
    digitalWrite(LED_PIN, LOW);
    return ctapErr(0x7F);
  }
  memset(g_ioBuf + SCRATCH_OFF, 0, 32);
  memcpy(g_ioBuf, g_eccHold, 13 + adLen);
  size_t idx = 13 + adLen;
  r[idx++] = 0x03;
  r[idx++] = 0xA2;
  r[idx++] = 0x63; r[idx++] = 'a'; r[idx++] = 'l'; r[idx++] = 'g';
  r[idx++] = 0x26;
  r[idx++] = 0x63; r[idx++] = 's'; r[idx++] = 'i'; r[idx++] = 'g';
  r[idx++] = 0x58;
  size_t derLen = encodeDER(g_blk, r + idx + 1);
  r[idx++] = (uint8_t)derLen;
  idx += derLen;
  memset(g_blk, 0, 64);
  digitalWrite(LED_PIN, LOW);
  return idx;
}

__attribute__((noinline))
static void hmacCred(int slot, const uint8_t *salt, uint8_t out[32]) {
  uint8_t cr[32];
  eeRead(slotAddr((uint8_t)slot) + OFF_RAND, cr, 32);
  sha256.resetHMAC(cr, 32);
  sha256.update(salt, 32);
  sha256.finalizeHMAC(cr, 32, out, 32);
  sha256.clear();
  memset(cr, 0, 32);
}

__attribute__((noinline))
static bool fillHmacCt(int slot, uint8_t *dest, uint8_t *outLen) {
  uint8_t iv[16];
  uint8_t *cursor = dest;
  if (g_hmacProto == 2) {
    if (!RNG(cursor, 16)) return false;
    memcpy(iv, cursor, 16);
    cursor += 16;
  } else {
    memset(iv, 0, 16);
  }
  uint8_t nSalt = (uint8_t)(g_cLen / 32);
  for (uint8_t s = 0; s < nSalt; s++) {
    uint8_t mac[32];
    hmacCred(slot, g_ioBuf + 240 + (uint16_t)s * 32, mac);
    if (!aes_cbc(1, g_blk + 32, iv, mac, 2)) {
      memset(mac, 0, 32);
      return false;
    }
    memcpy(cursor, mac, 32);
    memcpy(iv, mac + 16, 16);
    memset(mac, 0, 32);
    cursor += 32;
  }
  *outLen = (uint8_t)(cursor - dest);
  memset(iv, 0, 16);
  return true;
}

__attribute__((noinline))
static uint8_t prepareHmac(void) {
  if (!g_havePinKey || !g_xOff || !g_bLen || !g_cLen) return 0x14;
  if (g_hmacProto != 1 && g_hmacProto != 2) return 0x02;
  uint8_t macLen = (g_hmacProto == 1) ? 16 : 32;
  if (g_cLen != macLen) return 0x33;
  uint16_t plain = 0;
  if (g_hmacProto == 1 && (g_bLen == 32 || g_bLen == 64)) plain = g_bLen;
  if (g_hmacProto == 2 && (g_bLen == 48 || g_bLen == 80)) plain = (uint16_t)(g_bLen - 16);
  if (!plain) return 0x02;
  if ((uint32_t)g_bOff + g_bLen > g_msgLen || (uint32_t)g_cOff + g_cLen > g_msgLen) return 0x02;
  if (!peerToBlk()) return 0x14;
  if (!eccSaveIo()) return 0x7F;
  if (!ecdh_keys(g_hmacProto)) return 0x33;
  eccRestoreIo();
  if (!mac_eq(g_blk, g_ioBuf + g_bOff, g_bLen, 0, 0, g_ioBuf + g_cOff, macLen))
    return 0x33;
  uint8_t iv[16];
  uint8_t *data;
  uint8_t blocks = (uint8_t)(plain / 16);
  if (g_hmacProto == 1) {
    memset(iv, 0, 16);
    data = g_ioBuf + g_bOff;
  } else {
    memcpy(iv, g_ioBuf + g_bOff, 16);
    data = g_ioBuf + g_bOff + 16;
  }
  if (!aes_cbc(0, g_blk + 32, iv, data, blocks)) {
    memset(iv, 0, 16);
    return 0x7F;
  }
  memset(iv, 0, 16);
  memmove(g_ioBuf + 240, data, plain);
  g_cLen = plain;
  return 0x00;
}

__attribute__((noinline))
static size_t finishGet(int slot, bool haveUv) {
  int base = slotAddr((uint8_t)slot);
  uint8_t *r = g_ioBuf;
  r[0] = 0x00;
  r[1] = 0xA4;
  r[2] = 0x01;
  r[3] = 0xA2;
  r[4] = 0x62; r[5] = 'i'; r[6] = 'd';
  r[7] = 0x50;
  eeRead(base + OFF_CRED, r + 8, 16);
  r[24] = 0x64;
  memcpy_P(r + 25, PSTR("type"), 4);
  r[29] = 0x6A;
  memcpy_P(r + 30, PSTR("public-key"), 10);
  r[40] = 0x02;
  r[41] = 0x58;
  uint8_t *ad = r + 43;
  eeRead(base + OFF_RP, ad, 32);
  uint8_t flags = upBit();
  if (haveUv) flags |= 0x04;
  if (g_hasHmacGet) flags |= 0x80;
  ad[32] = flags;
  putCounter(ad + 33, g_counter);
  size_t adLen = 37;
  if (g_hasHmacGet) {
    ad[37] = 0xA1;
    ad[38] = 0x6B;
    memcpy_P(ad + 39, PSTR("hmac-secret"), 11);
    uint8_t ctLen = 0;
    if (!fillHmacCt(slot, ad + 52, &ctLen)) {
      digitalWrite(LED_PIN, LOW);
      return ctapErr(0x7F);
    }
    ad[50] = 0x58;
    ad[51] = ctLen;
    adLen = 52 + ctLen;
  }
  r[42] = (uint8_t)adLen;
  sha256.reset();
  sha256.update(ad, adLen);
  sha256.update(g_clientHash, 32);
  sha256.finalize(g_clientHash, 32);
  sha256.clear();
  if (43 + adLen > SCRATCH_OFF || 43 + adLen > sizeof(g_eccHold)) return ctapErr(0x7F);
  memcpy(g_eccHold, g_ioBuf, 43 + adLen);
  eeRead(base + OFF_PRIV, g_ioBuf + SCRATCH_OFF, 32);
  if (!sign_priv(g_ioBuf + SCRATCH_OFF, g_clientHash, g_blk)) {
    memset(g_ioBuf + SCRATCH_OFF, 0, 32);
    digitalWrite(LED_PIN, LOW);
    return ctapErr(0x7F);
  }
  memset(g_ioBuf + SCRATCH_OFF, 0, 32);
  memcpy(g_ioBuf, g_eccHold, 43 + adLen);
  size_t idx = 43 + adLen;
  r[idx++] = 0x03;
  r[idx++] = 0x58;
  size_t derLen = encodeDER(g_blk, r + idx + 1);
  r[idx++] = (uint8_t)derLen;
  idx += derLen;
  memset(g_blk, 0, 64);
  uint8_t ulen = EEPROM.read(base + OFF_ULEN);
  if (ulen > USER_ID_MAX) ulen = 0;
  r[idx++] = 0x04;
  r[idx++] = 0xA1;
  r[idx++] = 0x62; r[idx++] = 'i'; r[idx++] = 'd';
  if (ulen < 24) r[idx++] = (uint8_t)(0x40 | ulen);
  else { r[idx++] = 0x58; r[idx++] = ulen; }
  if (ulen) {
    eeRead(base + OFF_UID, r + idx, ulen);
    idx += ulen;
  }
  digitalWrite(LED_PIN, LOW);
  if (idx > sizeof(g_ioBuf)) return ctapErr(0x7F);
  return idx;
}

static size_t ctapMake(bool binaryMode, size_t reqLen) {
  if (!ensureEntropy()) return ctapErr(0x7F);
  uint8_t pe = parseMakeGet(0x01, reqLen);
  if (pe) return ctapErr(pe);
  if (!(g_reqFlags & RF_HASH) || !(g_reqFlags & RF_RP)) return ctapErr(0x14);
  if (g_userLen == 0xFF) return ctapErr(0x15);
  if (!(g_reqFlags & RF_ES256)) return ctapErr(0x26);
  uint8_t uv = checkPinToken(0x01);
  // Empty pinUvAuthParam is only a UP probe (CTAP). Never start ECC here —
  // a 5–15s keygen makes Windows re-INIT mid-flight and then show 0x52E.
  if (uv == 0xFD) return emptyPinAuthProbe(binaryMode);
  if (uv != 0x00 && uv != 0xFE) return ctapErr(uv);
  bool haveUv = (uv == 0x00);
  if ((g_reqFlags & RF_UV) && !haveUv) return ctapErr(pinIsSet() ? 0x36 : 0x35);
  // Without makeCredUvNotRqd, Windows must supply pinAuth once a PIN exists.
  if (pinIsSet() && !haveUv) return ctapErr(0x36);
  resolveExclude();
  uint8_t up = doUp(binaryMode);
  if (up) return ctapErr(up);
  if (g_exclIdx >= 0) {
    digitalWrite(LED_PIN, LOW);
    return ctapErr(0x19);
  }
  int slot = allocSlot();
  if (slot < 0) {
    digitalWrite(LED_PIN, LOW);
    return ctapErr(0x28);
  }
  if (!writeNewSlot(slot) || !make_key_pub()) {
    digitalWrite(LED_PIN, LOW);
    return ctapErr(0x7F);
  }
  int base = slotAddr((uint8_t)slot);
  eeWrite(base + OFF_PRIV, g_ioBuf + SCRATCH_OFF, 32);
  memset(g_ioBuf + SCRATCH_OFF, 0, 32);
  EEPROM.update(base + OFF_VALID, 0xA5);
  noteSlotCount();
  incCounter();
  return finishMake(slot, haveUv);
}

static size_t ctapGet(bool binaryMode, size_t reqLen) {
  if (!ensureEntropy()) return ctapErr(0x7F);
  uint8_t pe = parseMakeGet(0x02, reqLen);
  if (pe) return ctapErr(pe);
  if (!(g_reqFlags & RF_HASH) || !(g_reqFlags & RF_RP)) return ctapErr(0x14);
  uint8_t uv = checkPinToken(0x02);
  if (uv == 0xFD) return emptyPinAuthProbe(binaryMode);
  if (uv != 0x00 && uv != 0xFE) return ctapErr(uv);
  bool haveUv = (uv == 0x00);
  if ((g_reqFlags & RF_UV) && !haveUv) return ctapErr(pinIsSet() ? 0x36 : 0x35);
  uint8_t sel = selectCred(haveUv);
  if (sel) return ctapErr(sel);
  if (g_hasHmacGet) {
    uint8_t hs = prepareHmac();
    if (hs) return ctapErr(hs);
  }
  uint8_t up = doUp(binaryMode);
  if (up) return ctapErr(up);
  incCounter();
  return finishGet(g_chosen, haveUv);
}

static size_t buildCtap2GetInfo(uint8_t *out) {
  size_t i = 0;
  out[i++] = 0x00; // CTAP2_OK
  out[i++] = 0xAA; // map(10)
  // 1. versions — FIDO_2_1 first so Windows uses authenticatorSelection
  // instead of makeCredential + empty pinUvAuthParam for device pick.
  out[i++] = 0x01; out[i++] = 0x83;
  out[i++] = 0x68; memcpy_P(out + i, PSTR("FIDO_2_1"), 8); i += 8;
  out[i++] = 0x68; memcpy_P(out + i, PSTR("FIDO_2_0"), 8); i += 8;
  out[i++] = 0x66; memcpy_P(out + i, PSTR("U2F_V2"), 6); i += 6;
  // 2. extensions
  out[i++] = 0x02; out[i++] = 0x82;
  out[i++] = 0x6B; memcpy_P(out + i, PSTR("hmac-secret"), 11); i += 11;
  out[i++] = 0x6B; memcpy_P(out + i, PSTR("credProtect"), 11); i += 11;
  // 3. aaguid
  out[i++] = 0x03; out[i++] = 0x50;
  memcpy_P(out + i, AAGUID, 16); i += 16;
  // 4. options (map(5): rk, up, plat, clientPin, pinUvAuthToken)
  // Do NOT advertise makeCredUvNotRqd — Windows then sends empty pinAuth while
  // clientPin=true and BioEnrollment aborts with 0x52E (FIDO-dev known issue).
  out[i++] = 0x04; out[i++] = 0xA5;
  out[i++] = 0x62; out[i++] = 'r'; out[i++] = 'k'; out[i++] = 0xF5;
  out[i++] = 0x62; out[i++] = 'u'; out[i++] = 'p'; out[i++] = 0xF5;
  out[i++] = 0x64; memcpy_P(out + i, PSTR("plat"), 4); i += 4; out[i++] = 0xF4;
  out[i++] = 0x69; memcpy_P(out + i, PSTR("clientPin"), 9); i += 9;
  out[i++] = pinIsSet() ? 0xF5 : 0xF4;
  out[i++] = 0x6E; memcpy_P(out + i, PSTR("pinUvAuthToken"), 14); i += 14;
  out[i++] = 0xF5;
  // 5. maxMsgSize (512 bytes) — Windows Hello makeCredential often exceeds 288
  out[i++] = 0x05; out[i++] = 0x19; out[i++] = 0x02; out[i++] = 0x00;
  // 6. pinUvAuthProtocols ([1, 2])
  out[i++] = 0x06; out[i++] = 0x82; out[i++] = 0x01; out[i++] = 0x02;
  // 7. maxCredentialCountInList (4)
  out[i++] = 0x07; out[i++] = 0x04;
  // 8. maxCredentialIdLength (16)
  out[i++] = 0x08; out[i++] = 0x10;
  // 9. minPINLength (0x0D, 4) — matches pinPolicy's minimum of 4 code points
  out[i++] = 0x0D; out[i++] = 0x04;
  // 10 (0x0A). algorithms ([{"alg": -7, "type": "public-key"}])
  out[i++] = 0x0A; out[i++] = 0x81; out[i++] = 0xA2;
  out[i++] = 0x63; out[i++] = 'a'; out[i++] = 'l'; out[i++] = 'g'; out[i++] = 0x26;
  out[i++] = 0x64; memcpy_P(out + i, PSTR("type"), 4); i += 4;
  out[i++] = 0x6A; memcpy_P(out + i, PSTR("public-key"), 10); i += 10;
  return i;
}

static size_t ctapReset(bool binaryMode) {
  if (!binaryMode) Serial.println(F("{\"status\":\"WAITING_USER_PRESENCE\",\"protocol\":\"CTAP2\"}"));
  // HID: approve immediately. A long wait + UPNEEDED let Windows CANCEL
  // before the OK arrived ("リセットを完了できませんでした").
  if (!waitForUserPresence(binaryMode)) return ctapErr(0x2D);
  wipeCredentialsAndPin();
  digitalWrite(LED_PIN, LOW);
  g_ioBuf[0] = 0x00;
  return 1;
}

static size_t ctapSelection(bool binaryMode) {
  if (!binaryMode) Serial.println(F("{\"status\":\"WAITING_USER_PRESENCE\",\"protocol\":\"CTAP2\"}"));
  if (binaryMode) holdBinaryPresence();
  else if (!waitForUserPresence(false)) return ctapErr(0x2D);
  digitalWrite(LED_PIN, LOW);
  g_ioBuf[0] = 0x00;
  return 1;
}

__attribute__((noinline))
static size_t doGetKey(void) {
  if (g_reqProto == 0) return ctapErr(0x14);
  if (g_reqProto == 0xFF) return ctapErr(0x02);
  if (!g_havePinKey) return ctapErr(0x7F);
  size_t n = encodeCoseAgree(g_pinPub, g_ioBuf + 3);
  g_ioBuf[0] = 0x00;
  g_ioBuf[1] = 0xA1;
  g_ioBuf[2] = 0x01;
  return 3 + n;
}

__attribute__((noinline))
static size_t doSetPin(void) {
  if (g_reqProto == 0) return ctapErr(0x14);
  if (g_reqProto == 0xFF) return ctapErr(0x02);
  if (pinIsSet()) return ctapErr(0x33);
  if (!g_havePinKey || !g_xOff || !g_pinAuthLen || !g_bLen) return ctapErr(g_havePinKey ? 0x14 : 0x33);
  uint8_t expect = (g_reqProto == 1) ? 16 : 32;
  uint16_t need = (g_reqProto == 1) ? 64 : 80;
  if (g_pinAuthLen != expect || g_bLen != need) return ctapErr(0x02);
  if (!peerToBlk()) return ctapErr(0x33);
  if (!eccSaveIo()) return ctapErr(0x7F);
  if (!ecdh_keys(g_reqProto)) return ctapErr(0x33);
  eccRestoreIo();
  if (!mac_eq(g_blk, g_ioBuf + g_bOff, g_bLen, 0, 0, g_ioBuf + g_pinAuthOff, expect)) {
    memset(g_blk, 0, 64);
    return ctapErr(0x33);
  }
  uint8_t hash[16];
  uint8_t st = decryptNewPin(g_reqProto, hash);
  if (st) {
    memset(hash, 0, 16);
    memset(g_blk, 0, 64);
    return ctapErr(st);
  }
  storePinHash(hash);
  memset(hash, 0, 16);
  memset(g_blk, 0, 64);
  g_ioBuf[0] = 0x00;
  g_ioBuf[1] = 0xA0;
  return 2;
}

__attribute__((noinline))
static size_t doChangePin(void) {
  if (g_reqProto == 0) return ctapErr(0x14);
  if (g_reqProto == 0xFF) return ctapErr(0x02);
  if (!pinIsSet()) return ctapErr(0x35);
  if (EEPROM.read(PIN_RETRIES_ADDR) == 0) return ctapErr(0x32);
  if (g_pinConsec >= 3) return ctapErr(0x34);
  if (!g_havePinKey || !g_xOff || !g_pinAuthLen || !g_bLen || !g_cLen) return ctapErr(0x14);
  uint8_t expect = (g_reqProto == 1) ? 16 : 32;
  uint16_t need = (g_reqProto == 1) ? 64 : 80;
  uint16_t hashNeed = (g_reqProto == 1) ? 16 : 32;
  if (g_pinAuthLen != expect || g_bLen != need || g_cLen != hashNeed) return ctapErr(0x02);
  if (!peerToBlk()) return ctapErr(0x33);
  if (!eccSaveIo()) return ctapErr(0x7F);
  if (!ecdh_keys(g_reqProto)) return ctapErr(0x33);
  eccRestoreIo();
  if (!mac_eq(g_blk, g_ioBuf + g_bOff, g_bLen, g_ioBuf + g_cOff, g_cLen,
              g_ioBuf + g_pinAuthOff, expect)) {
    memset(g_blk, 0, 64);
    return ctapErr(0x33);
  }
  uint8_t st = decryptPinHash(g_reqProto);
  if (st) {
    memset(g_blk, 0, 64);
    return ctapErr(st);
  }
  uint8_t hash[16];
  st = decryptNewPin(g_reqProto, hash);
  if (st) {
    memset(hash, 0, 16);
    memset(g_blk, 0, 64);
    return ctapErr(st);
  }
  storePinHash(hash);
  memset(hash, 0, 16);
  memset(g_blk, 0, 64);
  g_ioBuf[0] = 0x00;
  g_ioBuf[1] = 0xA0;
  return 2;
}

__attribute__((noinline))
static void hashRpToEeprom(void) {
  uint8_t rp[32];
  sha256.reset();
  sha256.update(g_ioBuf + g_rpOff, g_rpLen);
  sha256.finalize(rp, 32);
  sha256.clear();
  EEPROM.update(PIN_RP_FLAG_ADDR, 0x00);
  eeWrite(PIN_RP_ADDR, rp, 32);
  EEPROM.update(PIN_RP_FLAG_ADDR, 0xA5);
  memset(rp, 0, 32);
  g_pinRpBound = 1;
}

__attribute__((noinline))
static size_t emitToken(uint8_t proto) {
  uint8_t tmp[32];
  memcpy(tmp, g_pinToken, 32);
  g_ioBuf[0] = 0x00;
  g_ioBuf[1] = 0xA1;
  g_ioBuf[2] = 0x02;
  g_ioBuf[3] = 0x58;
  if (proto == 1) {
    uint8_t z[16];
    memset(z, 0, 16);
    g_ioBuf[4] = 32;
    bool ok = aes_cbc(1, g_blk + 32, z, tmp, 2);
    memcpy(g_ioBuf + 5, tmp, 32);
    memset(z, 0, 16);
    memset(tmp, 0, 32);
    memset(g_blk, 0, 64);
    if (!ok) return ctapErr(0x7F);
    return 37;
  }
  g_ioBuf[4] = 48;
  if (!RNG(g_ioBuf + 5, 16)) {
    memset(tmp, 0, 32);
    memset(g_blk, 0, 64);
    return ctapErr(0x7F);
  }
  bool ok = aes_cbc(1, g_blk + 32, g_ioBuf + 5, tmp, 2);
  memcpy(g_ioBuf + 21, tmp, 32);
  memset(tmp, 0, 32);
  memset(g_blk, 0, 64);
  if (!ok) return ctapErr(0x7F);
  return 53;
}

__attribute__((noinline))
static size_t doGetToken(bool withPerm) {
  if (g_reqProto == 0) return ctapErr(0x14);
  if (g_reqProto == 0xFF) return ctapErr(0x02);
  if (!pinIsSet()) return ctapErr(0x35);
  if (EEPROM.read(PIN_RETRIES_ADDR) == 0) return ctapErr(0x32);
  if (g_pinConsec >= 3) return ctapErr(0x34);
  if (!g_havePinKey || !g_xOff || !g_cLen) return ctapErr(0x14);
  if (!peerToBlk()) return ctapErr(0x33);
  if (!eccSaveIo()) return ctapErr(0x7F);
  if (!ecdh_keys(g_reqProto)) return ctapErr(0x33);
  eccRestoreIo();
  uint8_t st = decryptPinHash(g_reqProto);
  if (st) {
    memset(g_blk, 0, 64);
    return ctapErr(st);
  }
  uint8_t perm = 0x03;
  if (withPerm) {
    perm = (uint8_t)(g_reqPerm & 0x03);
    if (!perm) {
      memset(g_blk, 0, 64);
      return ctapErr(0x02);
    }
    if (!g_rpLen || (uint32_t)g_rpOff + g_rpLen > g_msgLen) {
      memset(g_blk, 0, 64);
      return ctapErr(0x14);
    }
  }
  if (!ensureEntropy() || !RNG(g_pinToken, 32)) {
    memset(g_blk, 0, 64);
    return ctapErr(0x7F);
  }
  g_pinPerm = perm;
  g_pinProto = g_reqProto;
  if (withPerm) hashRpToEeprom();
  else {
    g_pinRpBound = 0;
    EEPROM.update(PIN_RP_FLAG_ADDR, 0x00);
  }
  return emitToken(g_reqProto);
}

static size_t doGetRetries(void) {
  uint8_t r = EEPROM.read(PIN_RETRIES_ADDR);
  if (r > PIN_MAX_RETRIES) r = PIN_MAX_RETRIES;
  g_ioBuf[0] = 0x00; // CTAP2_OK
  g_ioBuf[1] = 0xA1; // map(1)
  g_ioBuf[2] = 0x03; // key: 3 (pinRetries)
  g_ioBuf[3] = r;    // value: r (8)
  return 4;
}

static size_t ctapClientPin(size_t reqLen) {
  uint8_t pe = parseClientPin(reqLen);
  if (pe) return ctapErr(pe);
  if (g_pinSub == 0x01) return doGetRetries();
  if (g_pinSub == 0x02) return doGetKey();
  if (g_pinSub == 0x03) return doSetPin();
  if (g_pinSub == 0x04) return doChangePin();
  if (g_pinSub == 0x05) return doGetToken(false);
  if (g_pinSub == 0x09) return doGetToken(true);
  return ctapErr(0x01);
}

size_t executeCtap2InPlace(size_t reqLen, bool binaryMode) {
  if (reqLen == 0) return ctapErr(0x01);
  if (reqLen > CTAP_MAX_MSG) return ctapErr(0x39);
  g_msgLen = (uint16_t)reqLen;
  uint8_t cmd = g_ioBuf[0];
  if (cmd == 0x04) return buildCtap2GetInfo(g_ioBuf);
  if (cmd == 0x07) return ctapReset(binaryMode);
  if (cmd == 0x0B) return ctapSelection(binaryMode);
  if (cmd == 0x06) return ctapClientPin(reqLen);
  if (cmd == 0x01) return ctapMake(binaryMode, reqLen);
  if (cmd == 0x02) return ctapGet(binaryMode, reqLen);
  if (cmd == 0x08) return ctapErr(0x2A);
  return ctapErr(0x01);
}


