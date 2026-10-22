#include <Arduino.h>
#include <uECC.h>
#include <SHA256.h>

const int LED_PIN = 13;
SHA256 sha256;

// PRNG for micro-ecc using ADC noise and micros()
static int RNG(uint8_t *dest, unsigned size) {
  while (size--) {
    uint8_t val = 0;
    for (int i = 0; i < 8; ++i) {
      // Read low bit of unconnected analog pins A0-A3
      val = (val << 1) | (analogRead(A0) & 0x01) ^ ((micros() & 0x01));
      delayMicroseconds(50);
    }
    *dest++ = val;
  }
  return 1;
}

// Convert byte array to hex string
void printHex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print("0");
    Serial.print(data[i], HEX);
  }
}

// Encode ECDSA signature (r, s) into ASN.1 DER format
// sig is 64 bytes: 32 bytes r followed by 32 bytes s
size_t encodeDER(const uint8_t *sig, uint8_t *der) {
  const uint8_t *r = sig;
  const uint8_t *s = sig + 32;

  // Trim leading zeros, but keep at least 1 byte
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

  der[idx++] = 0x30; // SEQUENCE
  der[idx++] = (uint8_t)total_len;

  // Integer r
  der[idx++] = 0x02;
  der[idx++] = (uint8_t)r_len;
  if (r_pad) der[idx++] = 0x00;
  memcpy(der + idx, r + r_offset, 32 - r_offset);
  idx += (32 - r_offset);

  // Integer s
  der[idx++] = 0x02;
  der[idx++] = (uint8_t)s_len;
  if (s_pad) der[idx++] = 0x00;
  memcpy(der + idx, s + s_offset, 32 - s_offset);
  idx += (32 - s_offset);

  return idx;
}

void setup() {
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  Serial.begin(115200);
  while (!Serial) { ; }

  Serial.println("\n=== Elegoo Uno R3 ECDSA P-256 Benchmark & Test ===");

  uECC_set_rng(&RNG);
  const struct uECC_Curve_t *curve = uECC_secp256r1();

  uint8_t pubKey[64];
  uint8_t privKey[32];

  // 1. Key Generation
  Serial.print("Generating P-256 Key Pair... ");
  digitalWrite(LED_PIN, HIGH);
  unsigned long start = millis();
  int res = uECC_make_key(pubKey, privKey, curve);
  unsigned long keygen_time = millis() - start;
  digitalWrite(LED_PIN, LOW);

  if (res == 1) {
    Serial.print("SUCCESS in ");
    Serial.print(keygen_time);
    Serial.println(" ms");
  } else {
    Serial.println("FAILED!");
    return;
  }

  Serial.print("Public Key (X, Y 64 bytes): ");
  printHex(pubKey, 64);
  Serial.println();

  // 2. Hash message
  const char *msg = "FIDO2/WebAuthn Challenge Test on Uno R3";
  uint8_t hash[32];
  sha256.reset();
  sha256.update(msg, strlen(msg));
  sha256.finalize(hash, sizeof(hash));

  Serial.print("SHA-256 of test msg: ");
  printHex(hash, 32);
  Serial.println();

  // 3. ECDSA Sign
  uint8_t sig[64];
  Serial.print("Signing hash... ");
  digitalWrite(LED_PIN, HIGH);
  start = millis();
  res = uECC_sign(privKey, hash, sizeof(hash), sig, curve);
  unsigned long sign_time = millis() - start;
  digitalWrite(LED_PIN, LOW);

  if (res == 1) {
    Serial.print("SUCCESS in ");
    Serial.print(sign_time);
    Serial.println(" ms");
  } else {
    Serial.println("FAILED!");
    return;
  }

  Serial.print("Raw Signature (r+s 64 bytes): ");
  printHex(sig, 64);
  Serial.println();

  // 4. Verify Signature
  Serial.print("Verifying signature... ");
  digitalWrite(LED_PIN, HIGH);
  start = millis();
  res = uECC_verify(pubKey, hash, sizeof(hash), sig, curve);
  unsigned long verify_time = millis() - start;
  digitalWrite(LED_PIN, LOW);

  if (res == 1) {
    Serial.print("VALID! Verified in ");
    Serial.print(verify_time);
    Serial.println(" ms");
  } else {
    Serial.println("INVALID!");
  }

  // 5. ASN.1 DER Encoding
  uint8_t der[72];
  size_t der_len = encodeDER(sig, der);
  Serial.print("ASN.1 DER Signature (");
  Serial.print(der_len);
  Serial.print(" bytes): ");
  printHex(der, der_len);
  Serial.println();

  Serial.println("=== Test Completed Successfully ===");
}

void loop() {
  // Idle blink
  digitalWrite(LED_PIN, HIGH);
  delay(100);
  digitalWrite(LED_PIN, LOW);
  delay(900);
}
