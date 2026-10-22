#ifndef COMPACT_SHA256_H
#define COMPACT_SHA256_H

#include <stdint.h>
#include <string.h>
#include <avr/pgmspace.h>

static const uint32_t sha256_k[64] PROGMEM = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// The message schedule is built in place over buffer[64]. HMAC pads also use
// buffer, and the inner digest lives at g_secTmp + 96. No SHA workspace sits in
// g_ioBuf any more: a long makeCredential could overwrite pinUvAuthParam.
extern uint8_t g_secTmp[];

static inline uint8_t *shaInnerDigest(void) { return g_secTmp + 96; }

class CompactSHA256 {
private:
  uint32_t state[8];
  uint32_t totalBytes;
  uint8_t buffer[64] __attribute__((aligned(4)));
  uint8_t bufLen;

  __attribute__((noinline))
  static uint32_t rotr(uint32_t x, uint8_t n) {
    return (x >> n) | (x << (32 - n));
  }

  __attribute__((noinline))
  static uint32_t sigma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
  }

  __attribute__((noinline))
  static uint32_t sigma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
  }

  __attribute__((noinline))
  static uint32_t Sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
  }

  __attribute__((noinline))
  static uint32_t Sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
  }

  __attribute__((noinline))
  static uint32_t Ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ ((~x) & z);
  }

  __attribute__((noinline))
  static uint32_t Maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
  }

  // buffer is the only caller: expand the schedule in place over the block.
  void processBlock() {
    uint32_t *w = (uint32_t *)buffer;
    for (uint8_t i = 0; i < 16; i++) {
      w[i] = ((uint32_t)buffer[i * 4] << 24) |
             ((uint32_t)buffer[i * 4 + 1] << 16) |
             ((uint32_t)buffer[i * 4 + 2] << 8) |
             ((uint32_t)buffer[i * 4 + 3]);
    }

    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

    for (uint8_t i = 0; i < 64; i++) {
      uint32_t wi;
      if (i < 16) {
        wi = w[i];
      } else {
        wi = w[i & 15] = w[i & 15] + sigma0(w[(i + 1) & 15]) + w[(i + 9) & 15] + sigma1(w[(i + 14) & 15]);
      }

      uint32_t temp1 = h + Sigma1(e) + Ch(e, f, g) + pgm_read_dword(sha256_k + i) + wi;
      uint32_t temp2 = Sigma0(a) + Maj(a, b, c);

      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
  }

public:
  CompactSHA256() { reset(); }

  void reset() {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
    totalBytes = 0;
    bufLen = 0;
  }

  void update(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    totalBytes += (uint32_t)len;
    while (len > 0) {
      uint8_t take = 64 - bufLen;
      if (take > len) take = (uint8_t)len;
      memcpy(buffer + bufLen, p, take);
      bufLen += take;
      p += take;
      len -= take;
      if (bufLen == 64) {
        processBlock();
        bufLen = 0;
      }
    }
  }

  void finalize(void *hash, size_t len) {
    buffer[bufLen++] = 0x80;
    if (bufLen > 56) {
      memset(buffer + bufLen, 0, 64 - bufLen);
      processBlock();
      bufLen = 0;
    }
    memset(buffer + bufLen, 0, 56 - bufLen);
    uint32_t bits = totalBytes * 8;
    buffer[56] = 0; buffer[57] = 0; buffer[58] = 0; buffer[59] = 0;
    buffer[60] = (uint8_t)(bits >> 24);
    buffer[61] = (uint8_t)(bits >> 16);
    buffer[62] = (uint8_t)(bits >> 8);
    buffer[63] = (uint8_t)(bits);
    processBlock();

    // Write the digest straight into the caller buffer. A 32-byte
    // temporary here sat under processBlock and crossed into BSS.
    uint8_t *o = (uint8_t *)hash;
    uint8_t n = len > 32 ? 32 : (uint8_t)len;
    for (uint8_t i = 0; i < n; i++) {
      uint32_t word = state[i >> 2];
      uint8_t shift = (uint8_t)(24 - ((i & 3) << 3));
      o[i] = (uint8_t)(word >> shift);
    }
  }

  void clear() {
    memset(buffer, 0, sizeof(buffer));
    reset();
  }

  // Build an HMAC pad in buffer and absorb it. A key longer than the block is
  // hashed first; the 32-byte digest fits at the front of buffer.
  void startPad(uint8_t pad, const void *key, size_t keyLen) {
    uint8_t *k = buffer;
    if (keyLen > 64) {
      reset();
      update(key, keyLen);
      finalize(k, 32);
      memset(k + 32, 0, 32);
    } else {
      memset(k, 0, 64);
      memcpy(k, key, keyLen);
    }
    for (uint8_t i = 0; i < 64; i++) k[i] ^= pad;
    reset();
    totalBytes = 64;
    processBlock();
    memset(k, 0, 64);
  }

  void resetHMAC(const void *key, size_t keyLen) {
    startPad(0x36, key, keyLen);
  }

  void finalizeHMAC(const void *key, size_t keyLen, void *hash, size_t hashLen) {
    uint8_t *inner = shaInnerDigest();
    finalize(inner, 32);
    startPad(0x5C, key, keyLen);
    update(inner, 32);
    finalize(hash, hashLen);
    memset(inner, 0, 32);
  }
};

typedef CompactSHA256 SHA256;

#endif // COMPACT_SHA256_H
