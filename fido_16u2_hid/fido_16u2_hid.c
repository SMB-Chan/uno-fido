// ============================================================================
// Bare-Metal USB HID FIDO2 / U2F Bridge Firmware v7 for ATmega16U2 (Uno R3)
// - Each UART frame is 0xAA 0x55 <seq> + 64-byte HID packet, and the 328P
//   must answer 0xA5 <seq> before the next frame is sent. A dropped frame
//   is retried. The bridge does not sit in KEEPALIVE unless the 328P ACKed
//   the whole request.
// - The 328P announces ready with 0xA6 after initStorage. Until that byte
//   (or a 5s fallback) one host request is buffered and no KEEPALIVE is sent.
// - INIT / WINK / PING / CANCEL are answered here. CBOR, including GetInfo,
//   runs on the 328P so clientPin matches EEPROM.
// - make/get/selection: UPNEEDED for the first ~0.8s, then PROCESSING.
//   UPNEEDED for the whole ECC made Windows cancel; never sending it made
//   the passkey dialog sit on "セキュリティキーの操作が必要です" after it
//   missed the immediate OK. INIT is answered from a static buffer — a
//   64-byte stack frame here overflowed the 512-byte SRAM and wedged USB.
// ============================================================================
#define F_CPU 16000000UL
#include <avr/io.h>
#include <avr/pgmspace.h>
#include <avr/interrupt.h>
#include <avr/wdt.h>
#include <util/delay.h>
#include <string.h>
#include <stdbool.h>

#define EP0_SIZE        32
#define FIDO_IN_EP      1
#define FIDO_OUT_EP     2
#define FIDO_EP_SIZE    64

// Standard FIDO Alliance HID Report Descriptor (34 bytes)
const uint8_t PROGMEM fido_hid_report_desc[34] = {
  0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance 0xF1D0)
  0x09, 0x01,       // Usage (U2F/FIDO Authenticator Device)
  0xA1, 0x01,       // Collection (Application)
  0x09, 0x20,       //   Usage (Input Report Data)
  0x15, 0x00,       //   Logical Minimum (0)
  0x26, 0xFF, 0x00, //   Logical Maximum (255)
  0x75, 0x08,       //   Report Size (8)
  0x95, 0x40,       //   Report Count (64)
  0x81, 0x02,       //   Input (Data, Var, Abs)
  0x09, 0x21,       //   Usage (Output Report Data)
  0x15, 0x00,       //   Logical Minimum (0)
  0x26, 0xFF, 0x00, //   Logical Maximum (255)
  0x75, 0x08,       //   Report Size (8)
  0x95, 0x40,       //   Report Count (64)
  0x91, 0x02,       //   Output (Data, Var, Abs)
  0xC0              // End Collection
};

const uint8_t PROGMEM device_desc[18] = {
  18, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, EP0_SIZE,
  0x09, 0x12,       // idVendor: 0x1209
  0xD0, 0xF1,       // idProduct: 0xF1D0
  0x31, 0x02,       // bcdDevice: 2.31
  1, 2, 3, 1
};

const uint8_t PROGMEM config_desc[41] = {
  9, 0x02, 41, 0x00, 1, 1, 0, 0x80, 50,
  9, 0x04, 0, 0, 2, 0x03, 0x00, 0x00, 0,
  9, 0x21, 0x11, 0x01, 0x00, 1, 0x22, sizeof(fido_hid_report_desc), 0x00,
  7, 0x05, 0x80 | FIDO_IN_EP, 0x03, FIDO_EP_SIZE, 0x00, 1, // bInterval = 1ms
  7, 0x05, FIDO_OUT_EP, 0x03, FIDO_EP_SIZE, 0x00, 1        // bInterval = 1ms
};

const uint8_t PROGMEM str_lang[4] = { 4, 0x03, 0x09, 0x04 };
const uint8_t PROGMEM str_mfg[14] = {
  14, 0x03, 'E',0, 'l',0, 'e',0, 'g',0, 'o',0, 'o',0
};
const uint8_t PROGMEM str_prod[38] = {
  38, 0x03,
  'U',0,'n',0,'o',0,' ',0,'R',0,'3',0,' ',0,
  'F',0,'I',0,'D',0,'O',0,'2',0,' ',0,'K',0,'e',0,'y',0,' ',0,'2',0
};
const uint8_t PROGMEM str_ser[18] = {
  18, 0x03, 'F',0,'I',0,'D',0,'O',0,'2',0,'0',0,'2',0,'6',0
};

volatile bool usb_configured = false;

// ============================================================================
// Shared 336-byte Buffer:
// - Phase 1 (USB OUT): buffers up to 5 x 64B (320B) request packets from Host
// - Phase 2 (UART RX): 336B interrupt ring buffer for 5 x 66B (330B) responses
// ============================================================================
// 3 boot packets (192) plus one UART frame. 336 left 140 bytes of stack;
// INIT's 64-byte reply frame crossed into this buffer and wedged the chip.
#define UART_RX_BUF_SIZE 240
volatile uint8_t uart_rx_buf[UART_RX_BUF_SIZE];
// Shared HID TX scratch. Nested 64-byte frames in main + send overflowed SRAM.
static uint8_t hid_tx[64];
volatile uint16_t uart_rx_head = 0;
volatile uint16_t uart_rx_tail = 0;

ISR(USART1_RX_vect) {
  uint8_t c = UDR1;
  uint16_t next = uart_rx_head + 1;
  if (next >= UART_RX_BUF_SIZE) next = 0;
  if (next != uart_rx_tail) {
    uart_rx_buf[uart_rx_head] = c;
    uart_rx_head = next;
  }
}

void uart_init(void) {
  UCSR1A = (1 << U2X1);
  UBRR1H = 0;
  UBRR1L = 16; // 115200 bps
  UCSR1B = (1 << RXEN1) | (1 << TXEN1); // RXCIE1 enabled only when waiting_328p is true!
  UCSR1C = (1 << UCSZ11) | (1 << UCSZ10);
}

void uart_putc(uint8_t c) {
  while (!(UCSR1A & (1 << UDRE1))) ;
  UDR1 = c;
}

bool uart_available(void) {
  uint8_t sreg = SREG;
  cli();
  bool avail = (uart_rx_head != uart_rx_tail);
  SREG = sreg;
  return avail;
}

uint8_t uart_getc(void) {
  while (!uart_available()) ;
  uint8_t sreg = SREG;
  cli();
  uint8_t c = uart_rx_buf[uart_rx_tail];
  uint16_t next = uart_rx_tail + 1;
  if (next >= UART_RX_BUF_SIZE) next = 0;
  uart_rx_tail = next;
  SREG = sreg;
  return c;
}

void uart_flush_rx(void) {
  uint8_t sreg = SREG;
  cli();
  while (UCSR1A & (1 << RXC1)) { (void)UDR1; }
  uart_rx_head = 0;
  uart_rx_tail = 0;
  SREG = sreg;
}

// ============================================================================
// USB Endpoint Configuration & Proven Register Logic
// ============================================================================
// Endpoint memory is a stack. Free the highest endpoint first, then retry
// until CFGOK. A single ALLOC write often fails after USB reset, which left
// the HID pipes dead: Windows enumerated the key and then timed out INIT.
static void ep_free(uint8_t ep) {
  UENUM = ep;
  UECONX &= ~(1 << EPEN);
  UECFG1X = 0;
}

static bool ep_enable(uint8_t ep, uint8_t cfg0, uint8_t cfg1) {
  UENUM = ep;
  UECONX = (1 << EPEN);
  for (uint8_t n = 0; n < 16; n++) {
    UECFG0X = cfg0;
    UECFG1X = cfg1;
    if (UESTA0X & (1 << CFGOK)) return true;
  }
  return false;
}

void configure_endpoints(void) {
  ep_free(FIDO_OUT_EP);
  ep_free(FIDO_IN_EP);
  uint8_t cfg1 = (uint8_t)((0b011 << EPSIZE0) | (1 << ALLOC));
  ep_enable(FIDO_IN_EP, (uint8_t)((0b11 << EPTYPE0) | (1 << EPDIR)), cfg1);
  ep_enable(FIDO_OUT_EP, (uint8_t)(0b11 << EPTYPE0), cfg1);
}

void usb_init(void) {
  REGCR = 0;
  USBCON = (1 << USBE) | (1 << FRZCLK);
  PLLCSR = (1 << PLLP0) | (1 << PLLE);
  while (!(PLLCSR & (1 << PLOCK))) ;
  USBCON = (1 << USBE);
  UDCON = 0;
  UDIEN = (1 << EORSTE);
  sei();
}

void ep0_send_progmem(const uint8_t *data, uint16_t len, uint16_t wLength) {
  if (len > wLength) len = wLength;
  while (len > 0) {
    while (!(UEINTX & (1 << TXINI))) ;
    uint8_t chunk = (len > EP0_SIZE) ? EP0_SIZE : len;
    for (uint8_t i = 0; i < chunk; i++) {
      UEDATX = pgm_read_byte(data++);
    }
    len -= chunk;
    UEINTX &= ~(1 << TXINI);
  }
  while (!(UEINTX & (1 << RXOUTI))) ;
  UEINTX &= ~(1 << RXOUTI);
}

static bool in_bank_free(void) {
  UENUM = FIDO_IN_EP;
  return (UEINTX & (1 << TXINI)) && (UEINTX & (1 << RWAL));
}

void send_usb_hid_report(const uint8_t *pkt64) {
  if (!usb_configured) return;
  for (uint8_t attempt = 0; attempt < 2; attempt++) {
    uint16_t timeout = 20000; // 200ms, host polls IN every 1ms
    while (!in_bank_free() && --timeout) {
      wdt_reset();
      _delay_us(10);
    }
    if (!timeout) {
      // Bank owned by nobody: a previous IN was filled and never armed.
      // Windows then sees every INIT as 0x5B4 and stays on the touch prompt.
      configure_endpoints();
      continue;
    }
    UENUM = FIDO_IN_EP;
    for (uint8_t i = 0; i < 64; i++) UEDATX = pkt64[i];
    UEINTX &= ~((1 << FIFOCON) | (1 << TXINI));
    return;
  }
}

#define CTAP_MAX_MSG 512
#define BOOT_MAX_PKTS 3
#define BOOT_MAX_MSG 175

uint32_t g_cid_counter = 0x01020300;
uint8_t active_cid[4] = {0, 0, 0, 0};
bool waiting_328p = false;
uint16_t keepalive_ticks = 0;
uint16_t keepalive_count = 0;
bool boot_ready = false;
// Only make/get/reset/selection actually wait for UP on the 328P.
// ClientPin ECC used to advertise UPNEEDED and Windows blocked on "touch".
bool keepalive_up_needed = false;
bool discard_328p_response = false;
bool pending_getinfo = false;
// HID continuation packets still owed by the in-flight 328P reply.
static uint8_t resp_follow = 0;
uint8_t pending_getinfo_cid[4];

// Multi-packet USB OUT state (boot buffer uses uart_rx_buf[0..319])
uint8_t req_pkt_count = 0;
uint16_t req_expected_bytes = 0;
uint16_t req_received_bytes = 0;
bool req_ready = false;
bool req_streaming = false;

// ---------------------------------------------------------------------------
// 328P recovery
// The 328P stopped answering the UART once (10/23 03:49:40, the last good
// GetInfo) while the 16U2 kept serving CTAPHID_INIT. Every CBOR command then
// came back as a 1-byte 0x7F from this chip, and only a USB replug cleared it.
//
// PD7 drives ATmega328P RESET through the Uno's 0.1uF auto-reset cap, so the
// bridge can reboot a wedged 328P itself. If the RESET-EN solder jumper is
// open this pulse does nothing and the old behaviour (0x7F until replug) stays.
// ---------------------------------------------------------------------------
#define P328_RST_BIT 7
static bool p328_recovering = false;
static uint16_t boot_wait_ms = 0;

static void p328_reset_pulse(void) {
  // Already waiting for the ready beacon: do not reset again mid-boot, or a
  // slow boot keygen (one P-256 multiply) would be restarted forever.
  if (p328_recovering) return;
  p328_recovering = true;

  DDRD |= (1 << P328_RST_BIT);
  PORTD &= ~(1 << P328_RST_BIT);      // falling edge into the coupling cap
  for (uint8_t i = 0; i < 2; i++) { wdt_reset(); _delay_ms(1); }
  DDRD &= ~(1 << P328_RST_BIT);       // high-Z: the cap pulls RESET back up

  boot_ready = false;
  boot_wait_ms = 0;
  waiting_328p = false;
  discard_328p_response = false;
  pending_getinfo = false;
  resp_follow = 0;
  keepalive_ticks = 0;
  keepalive_count = 0;
  req_streaming = false;
  req_pkt_count = 0;
  req_ready = false;
  uart_flush_rx();
}

static bool ctap_cmd_needs_up(uint8_t ctap_cmd) {
  // Reset (0x07) stays PROCESSING-only: UPNEEDED made Windows Hello show a
  // touch prompt, then CANCEL the transaction before our auto-UP OK arrived.
  return ctap_cmd == 0x01 || ctap_cmd == 0x02 || ctap_cmd == 0x0B;
}

static void send_hid_error(const uint8_t *cid, uint8_t err) {
  memset(hid_tx, 0, 64);
  memcpy(hid_tx, cid, 4);
  hid_tx[4] = 0xBF; // CTAPHID_ERROR
  hid_tx[5] = 0x00;
  hid_tx[6] = 0x01;
  hid_tx[7] = err;
  send_usb_hid_report(hid_tx);
}

// Complete the CTAP transaction. A HID-level error makes Windows Hello
// report the key as unusable; a one-byte CTAP status lets the UI move on.
static void send_ctap_status(const uint8_t *cid, uint8_t status) {
  memset(hid_tx, 0, 64);
  memcpy(hid_tx, cid, 4);
  hid_tx[4] = 0x90;
  hid_tx[5] = 0x00;
  hid_tx[6] = 0x01;
  hid_tx[7] = status;
  send_usb_hid_report(hid_tx);
}

static bool stream_to_328p(const uint8_t *pkt64, bool is_first, bool is_last);
static void start_pending_getinfo(void);

#define UART_ACK   0xA5
#define UART_READY 0xA6

static uint8_t frame_seq = 0;

static void uart_send_frame(const uint8_t *pkt64, uint8_t seq) {
  uart_putc(0xAA);
  uart_putc(0x55);
  uart_putc(seq);
  for (uint8_t i = 0; i < 64; i++) uart_putc(pkt64[i]);
}

// 328P ACKs only after the whole frame is in its buffer. No ACK means it was
// not in the read loop (the 64-byte Arduino RX buffer would have dropped the
// tail). Retry the same seq; the 328P ignores a duplicate continuation.
static bool wait_frame_ack(uint8_t seq) {
  for (uint16_t n = 0; n < 4000; n++) {
    if (uart_available()) {
      uint8_t b = uart_getc();
      if (b == UART_ACK) {
        uint16_t t = 2000;
        while (!uart_available() && --t) _delay_us(5);
        if (uart_available() && uart_getc() == seq) return true;
      }
    } else {
      _delay_us(5);
    }
  }
  return false;
}

static bool send_frame_acked(const uint8_t *pkt64, uint8_t seq) {
  for (uint8_t attempt = 0; attempt < 4; attempt++) {
    UCSR1B |= (1 << RXCIE1);
    uart_send_frame(pkt64, seq);
    if (wait_frame_ack(seq)) return true;
  }
  uart_flush_rx();
  return false;
}

static bool stream_to_328p(const uint8_t *pkt64, bool is_first, bool is_last) {
  if (is_first) {
    frame_seq = 0;
    // Drop leftover ready beacons. The request image is not the ring cursor.
    uart_flush_rx();
  }
  if (!send_frame_acked(pkt64, frame_seq)) {
    waiting_328p = false;
    req_streaming = false;
    req_pkt_count = 0;
    req_ready = false;
    discard_328p_response = true;
    resp_follow = 0;
    // No ACK on all four attempts: the 328P is not reading its UART at all.
    // Reboot it so the next request works instead of every request returning
    // 0x7F until the key is unplugged.
    p328_reset_pulse();
    return false;
  }
  frame_seq++;
  if (is_last) {
    waiting_328p = true;
    keepalive_ticks = 0;
    keepalive_count = 0;
    req_pkt_count = 0;
    req_streaming = false;
    req_ready = false;
  }
  return true;
}

// Run queued GetInfo after the in-flight CBOR finishes.
// BUSY(0x06) on GetInfo made Windows show "このセキュリティ キーは使用できません".
static void start_pending_getinfo(void) {
  memset(hid_tx, 0, 64);
  memcpy(hid_tx, pending_getinfo_cid, 4);
  hid_tx[4] = 0x90;
  hid_tx[5] = 0x00;
  hid_tx[6] = 0x01;
  hid_tx[7] = 0x04;
  pending_getinfo = false;
  memcpy(active_cid, pending_getinfo_cid, 4);
  keepalive_up_needed = false;
  discard_328p_response = false;
  req_expected_bytes = 1;
  req_received_bytes = 1;
  req_pkt_count = 1;
  if (!stream_to_328p(hid_tx, true, true)) send_ctap_status(active_cid, 0x7F);
}

void forward_buffered_request_to_328p(void) {
  uint8_t n = req_pkt_count;
  req_ready = false;
  // Copy each packet out before RXCIE runs. The ring and this boot image
  // share uart_rx_buf; an ACK must not overwrite a packet still to be sent.
  for (uint8_t p = 0; p < n; p++) {
    memcpy(hid_tx, (const uint8_t *)&uart_rx_buf[(uint16_t)p * 64], 64);
    if (!stream_to_328p(hid_tx, p == 0, (uint8_t)(p + 1) == n)) {
      send_ctap_status(active_cid, 0x7F);
      return;
    }
  }
}

static void send_too_large(const uint8_t *pkt) {
  memset(hid_tx, 0, 64);
  memcpy(hid_tx, pkt, 4);
  hid_tx[4] = 0x90;
  hid_tx[5] = 0x00;
  hid_tx[6] = 0x01;
  hid_tx[7] = 0x39; // CTAP2_ERR_REQUEST_TOO_LARGE
  send_usb_hid_report(hid_tx);
}

// Single-packet UP (authenticatorSelection) returns before the main loop can
// send a keepalive. Windows then keeps the passkey dialog on the touch prompt.
static void hold_short_up(bool single_packet) {
  if (!single_packet || !keepalive_up_needed) return;
  for (uint8_t n = 0; n < 4; n++) {
    memset(hid_tx, 0, 64);
    memcpy(hid_tx, active_cid, 4);
    hid_tx[4] = 0xBB;
    hid_tx[5] = 0x00;
    hid_tx[6] = 0x01;
    hid_tx[7] = 0x02; // STATUS_UPNEEDED
    send_usb_hid_report(hid_tx);
    for (uint16_t ms = 0; ms < 200; ms++) {
      wdt_reset();
      _delay_ms(1);
    }
  }
}

void process_host_hid_packet(const uint8_t *pkt) {
  uint8_t cmd = pkt[4];
  uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];

  if (cmd & 0x80) {
    // 1. Directly answer CTAPHID_INIT (0x86)
    if (cmd == 0x86) {
      // INIT only allocates a new CID. Do NOT discard an in-flight CBOR
      // (e.g. authenticatorReset) — Windows Hello still expects that response
      // on the old channel. Dropping it caused "リセットを完了できませんでした".
      req_pkt_count = 0;
      req_streaming = false;
      req_ready = false;
      memset(hid_tx, 0, 64);
      memcpy(hid_tx, pkt, 4);
      hid_tx[4] = 0x86;
      hid_tx[5] = 0x00;
      hid_tx[6] = 17;
      memcpy(hid_tx + 7, pkt + 7, 8);
      g_cid_counter++;
      hid_tx[15] = (uint8_t)((g_cid_counter >> 24) & 0xFF);
      hid_tx[16] = (uint8_t)((g_cid_counter >> 16) & 0xFF);
      hid_tx[17] = (uint8_t)((g_cid_counter >> 8) & 0xFF);
      hid_tx[18] = (uint8_t)(g_cid_counter & 0xFF);
      hid_tx[19] = 2;    // CTAPHID protocol version 2
      hid_tx[20] = 2;    // Major version
      hid_tx[21] = 0;    // Minor version
      hid_tx[22] = 0;    // Build version
      hid_tx[23] = 0x05; // Capabilities: WINK(0x01) | CBOR(0x04)
      send_usb_hid_report(hid_tx);
      return;
    }

    // 2. Directly handle CTAPHID_CANCEL (0x91)
    if (cmd == 0x91) {
      // Do NOT discard an in-flight 328P response. Windows Hello often sends
      // CANCEL during authenticatorReset while still expecting the CBOR OK;
      // dropping it produced "リセットを完了できませんでした".
      req_pkt_count = 0;
      req_streaming = false;
      req_ready = false;
      return;
    }

    // 3. Directly answer CTAPHID_WINK (0x88)
    if (cmd == 0x88) {
      memset(hid_tx, 0, 64);
      memcpy(hid_tx, pkt, 4);
      hid_tx[4] = 0x88;
      send_usb_hid_report(hid_tx);
      return;
    }

    // 4. Directly answer single-packet CTAPHID_PING (0x81)
    if (cmd == 0x81 && bcnt <= 57) {
      send_usb_hid_report(pkt);
      return;
    }

    // GetInfo while a command is in flight used to return CHANNEL_BUSY, which
    // Windows Hello shows as "このセキュリティキーは使用できません".
    // Hold it and run it when the 328P is free, so clientPin stays truthful.
    if (cmd == 0x90 && bcnt == 1 && pkt[7] == 0x04 && waiting_328p) {
      memcpy(pending_getinfo_cid, pkt, 4);
      pending_getinfo = true;
      return;
    }

    // 5b. Reject CBOR larger than the 328P window.
    uint16_t limit = boot_ready ? CTAP_MAX_MSG : BOOT_MAX_MSG;
    if (cmd == 0x90 && bcnt > limit) {
      send_too_large(pkt);
      return;
    }

    // 5c. While 328P is busy, reject other CBOR with BUSY.
    if (waiting_328p && cmd == 0x90) {
      send_hid_error(pkt, 0x06); // CTAPHID_ERR_CHANNEL_BUSY
      return;
    }

    waiting_328p = false;
    discard_328p_response = false;
    memcpy(active_cid, pkt, 4);
    req_expected_bytes = bcnt;
    req_received_bytes = (bcnt > 57) ? 57 : bcnt;
    req_pkt_count = 1;
    // CTAP command is the first CBOR payload byte (offset 7 on an init packet).
    keepalive_up_needed = (cmd == 0x90 && bcnt >= 1 && ctap_cmd_needs_up(pkt[7]));

    if (boot_ready) {
      // Stream each HID packet to the 328P immediately (supports 512B CBOR).
      req_streaming = true;
      req_ready = false;
      bool last = (req_received_bytes >= req_expected_bytes);
      hold_short_up(last);
      if (!stream_to_328p(pkt, true, last)) send_ctap_status(active_cid, 0x7F);
    } else {
      // Optiboot window: buffer in uart_rx_buf (max 5 packets).
      req_streaming = false;
      for (uint8_t i = 0; i < 64; i++) uart_rx_buf[i] = pkt[i];
      req_ready = (req_received_bytes >= req_expected_bytes);
    }
  } else {
    // Continuation packet
    if (req_streaming) {
      uint16_t rem = req_expected_bytes - req_received_bytes;
      uint16_t copy_len = (rem > 59) ? 59 : rem;
      req_received_bytes += copy_len;
      req_pkt_count++;
      bool last = (req_received_bytes >= req_expected_bytes);
      if (!stream_to_328p(pkt, false, last)) send_ctap_status(active_cid, 0x7F);
    } else if (req_pkt_count > 0 && req_pkt_count < BOOT_MAX_PKTS) {
      uint16_t base = (uint16_t)req_pkt_count * 64;
      for (uint8_t i = 0; i < 64; i++) uart_rx_buf[base + i] = pkt[i];
      req_pkt_count++;
      uint16_t rem = req_expected_bytes - req_received_bytes;
      uint16_t copy_len = (rem > 59) ? 59 : rem;
      req_received_bytes += copy_len;
      if (req_received_bytes >= req_expected_bytes) req_ready = true;
    }
  }
}

ISR(USB_GEN_vect) {
  uint8_t saved_uenum = UENUM;
  uint8_t udint = UDINT;
  UDINT = 0;
  if (udint & (1 << EORSTI)) {
    UENUM = 0;
    UECONX = (1 << EPEN);
    UECFG1X = 0;
    for (uint8_t n = 0; n < 16; n++) {
      UECFG0X = 0;
      UECFG1X = (0b010 << EPSIZE0) | (1 << ALLOC);
      if (UESTA0X & (1 << CFGOK)) break;
    }
    UEIENX = (1 << RXSTPE);
    usb_configured = false;
  }
  UENUM = saved_uenum;
}

ISR(USB_COM_vect) {
  uint8_t saved_uenum = UENUM;
  UENUM = 0;
  if (UEINTX & (1 << RXSTPI)) {
    uint8_t bmRequestType = UEDATX;
    uint8_t bRequest = UEDATX;
    uint16_t wValue = UEDATX | ((uint16_t)UEDATX << 8);
    uint16_t wIndex = UEDATX | ((uint16_t)UEDATX << 8);
    uint16_t wLength = UEDATX | ((uint16_t)UEDATX << 8);
    (void)wIndex;

    UEINTX &= ~((1 << RXSTPI) | (1 << RXOUTI) | (1 << TXINI));

    if (bRequest == 0x06) {
      uint8_t descType = (wValue >> 8) & 0xFF;
      uint8_t descIdx = wValue & 0xFF;
      if (descType == 0x01) { ep0_send_progmem(device_desc, sizeof(device_desc), wLength); UENUM = saved_uenum; return; }
      if (descType == 0x02) { ep0_send_progmem(config_desc, sizeof(config_desc), wLength); UENUM = saved_uenum; return; }
      if (descType == 0x21) { ep0_send_progmem(config_desc + 18, 9, wLength); UENUM = saved_uenum; return; }
      if (descType == 0x22) { ep0_send_progmem(fido_hid_report_desc, sizeof(fido_hid_report_desc), wLength); UENUM = saved_uenum; return; }
      if (descType == 0x03) {
        if (descIdx == 0) { ep0_send_progmem(str_lang, sizeof(str_lang), wLength); UENUM = saved_uenum; return; }
        if (descIdx == 1) { ep0_send_progmem(str_mfg, sizeof(str_mfg), wLength); UENUM = saved_uenum; return; }
        if (descIdx == 2) { ep0_send_progmem(str_prod, sizeof(str_prod), wLength); UENUM = saved_uenum; return; }
        if (descIdx == 3) { ep0_send_progmem(str_ser, sizeof(str_ser), wLength); UENUM = saved_uenum; return; }
      }
    } else if (bRequest == 0x05 && bmRequestType == 0x00) {
      uint8_t addr = wValue & 0x7F;
      UDADDR = addr;
      UEINTX &= ~(1 << TXINI);
      while (!(UEINTX & (1 << TXINI))) ;
      UDADDR = addr | (1 << ADDEN);
      UENUM = saved_uenum;
      return;
    } else if (bRequest == 0x09 && bmRequestType == 0x00) {
      usb_configured = (wValue != 0);
      if (usb_configured) configure_endpoints();
      UENUM = 0;
      UEINTX &= ~(1 << TXINI);
      UENUM = saved_uenum;
      return;
    } else if (bRequest == 0x0A && bmRequestType == 0x21) {
      UEINTX &= ~(1 << TXINI);
      UENUM = saved_uenum;
      return;
    } else if (bRequest == 0x09 && bmRequestType == 0x21 && wLength == 64) {
      uint8_t pkt[64];
      uint8_t idx = 0;
      bool short_read = false;
      while (idx < 64 && !short_read) {
        uint16_t spin = 4000;
        while (!(UEINTX & (1 << RXOUTI)) && --spin) ;
        if (!spin) { short_read = true; break; }
        uint8_t chunk = (64 - idx > EP0_SIZE) ? EP0_SIZE : (64 - idx);
        for (uint8_t i = 0; i < chunk; i++) pkt[idx++] = UEDATX;
        UEINTX &= ~(1 << RXOUTI);
      }
      if (!short_read) process_host_hid_packet(pkt);
      // Status stage is EP0. process_host_hid_packet leaves UENUM on the IN ep.
      UENUM = 0;
      UEINTX &= ~(1 << TXINI);
      UENUM = saved_uenum;
      return;
    }

    UECONX |= (1 << STALLRQ) | (1 << EPEN);
  }
  UENUM = saved_uenum;
}

// waiting_328p stays set until resp_follow hits 0 so the next host command
// cannot walk onto the UART while the 328P is still shifting the reply out.
static void note_response_header(const uint8_t *resp) {
  if (resp[4] & 0x80) {
    uint16_t blen = ((uint16_t)resp[5] << 8) | resp[6];
    if (blen > 57) {
      uint16_t rest = (uint16_t)(blen - 57);
      resp_follow = (uint8_t)((rest + 58) / 59);
    } else {
      resp_follow = 0;
    }
  } else if (resp_follow) {
    resp_follow--;
  }
}

static void service_uart_response(void) {
  if (req_streaming || req_pkt_count != 0 || req_ready) return;
  while (uart_available()) {
    uint8_t b = uart_getc();
    if (b != 0xAA) continue;
    uint16_t t = 30000;
    while (!uart_available() && --t) _delay_us(2);
    if (!(uart_available() && uart_getc() == 0x55)) continue;
    uint8_t *resp = hid_tx;
    uint8_t got = 0;
    t = 60000;
    while (got < 64 && --t) {
      wdt_reset();
      if (uart_available()) {
        resp[got++] = uart_getc();
        t = 60000;
      } else {
        _delay_us(2);
      }
    }
    if (got != 64) continue;
    note_response_header(resp);
    if (discard_328p_response) {
      discard_328p_response = false;
      resp_follow = 0;
      waiting_328p = false;
    } else {
      send_usb_hid_report(resp);
      if (resp_follow == 0) waiting_328p = false;
    }
    if (pending_getinfo && !waiting_328p) start_pending_getinfo();
  }
}

int main(void) {
  MCUSR = 0;
  wdt_disable();
  uart_init();
  usb_init();
  wdt_enable(WDTO_8S);

  while (1) {
    wdt_reset();
    if (!usb_configured) continue;

    // Deliver a finished 328P reply before accepting another host packet.
    // Doing this second let the next makeCredential hit the UART while the
    // 328P was still inside Serial.write, so the frame was dropped and
    // Windows Hello stayed on KEEPALIVE ("準備しています").
    service_uart_response();

    // 1. Check USB HID OUT Endpoint
    UENUM = FIDO_OUT_EP;
    if (UEINTX & (1 << RWAL)) {
      uint8_t pkt[64];
      for (uint8_t i = 0; i < 64; i++) {
        pkt[i] = UEDATX;
      }
      UEINTX &= ~((1 << FIFOCON) | (1 << RXOUTI));
      process_host_hid_packet(pkt);
    }

    // 328P sends 0xA6 once initStorage has finished. RXCIE stays off until
    // then so the beacon cannot overwrite a request buffered in uart_rx_buf.
    // No KEEPALIVE here: that is what Windows Hello shows as "準備しています".
    if (!boot_ready) {
      _delay_ms(1);
      boot_wait_ms++;
      if (UCSR1A & (1 << RXC1)) {
        uint8_t b = UDR1;
        if (b == UART_READY) {
          boot_ready = true;
          // A fresh 328P (first boot or after a recovery reset) has no reply
          // in flight, so never drop the first response it sends.
          p328_recovering = false;
          discard_328p_response = false;
        }
      }
      // 328P builds the PIN agreement key before 0xA6. That is one P-256
      // multiply (up to ~20s). Forwarding earlier hits a deaf UART.
      // A buffered GetInfo still needs KEEPALIVE or Windows drops the key.
      if (req_ready && ++keepalive_ticks >= 200) {
        keepalive_ticks = 0;
        memset(hid_tx, 0, 64);
        hid_tx[0] = uart_rx_buf[0];
        hid_tx[1] = uart_rx_buf[1];
        hid_tx[2] = uart_rx_buf[2];
        hid_tx[3] = uart_rx_buf[3];
        hid_tx[4] = 0xBB;
        hid_tx[5] = 0x00;
        hid_tx[6] = 0x01;
        hid_tx[7] = 0x01;
        send_usb_hid_report(hid_tx);
      }
      // The 328P blinks its last-command report (~10s) and then builds the
      // PIN key before 0xA6, so allow more than the old 40s.
      if (boot_wait_ms >= 90000) boot_ready = true;
    }
    if (boot_ready && req_ready && !req_streaming && !waiting_328p) {
      forward_buffered_request_to_328p();
    }

    service_uart_response();

    // 3. Automatic CTAPHID_KEEPALIVE (0xBB) every ~200ms while ATmega328P is computing ECC
    if (waiting_328p) {
      _delay_ms(1);
      if (++keepalive_ticks >= 200) {
        keepalive_ticks = 0;
        if (keepalive_count < 500) keepalive_count++;
        memset(hid_tx, 0, 64);
        memcpy(hid_tx, active_cid, 4);
        hid_tx[4] = 0xBB;
        hid_tx[5] = 0x00;
        hid_tx[6] = 0x01;
        // Touch window, then PROCESSING while the 328P does ECC.
        // UPNEEDED for the whole command made Windows cancel; never sending
        // it left the passkey UI on the security-key prompt.
        hid_tx[7] = (keepalive_up_needed && keepalive_count <= 4) ? 0x02 : 0x01;
        send_usb_hid_report(hid_tx);
        // The 328P already ACKed, so this is a hung authenticator, not a
        // lost frame. make/get used to skip this path and Windows sat on
        // "準備しています" until its own 90s timeout.
        // Level-2 multiply needs ~20-40s for one P-256 op. 16s was cut off
        // and Windows showed "問題が発生しました". make/get may run it twice.
        if (keepalive_count >= (keepalive_up_needed ? 450 : 250)) {
          waiting_328p = false;
          discard_328p_response = true;
          send_ctap_status(active_cid, 0x7F);
          // It ACKed the frame but never produced a reply, so it is stuck
          // mid-command (the modInv loop or a stack overflow). Reboot it now;
          // the next request is served by a clean 328P.
          p328_reset_pulse();
        }
      }
    }
  }
}
