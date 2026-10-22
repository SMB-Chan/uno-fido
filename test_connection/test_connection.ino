// Test Sketch for Elegoo Uno R3
const int LED_PIN = 13;
const int BUTTON_PIN = 2; // User presence pin (with internal pullup)

void setup() {
  pinMode(LED_PIN, OUTPUT);
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  Serial.begin(115200);
  while (!Serial) {
    ; // wait for serial port to connect
  }
  Serial.println("{\"status\":\"READY\",\"msg\":\"Elegoo Uno R3 FIDO Key PoC initialized\"}");
}

void loop() {
  // Read button (active LOW because of internal pull-up)
  int buttonState = digitalRead(BUTTON_PIN);
  
  if (buttonState == LOW) {
    digitalWrite(LED_PIN, HIGH);
    Serial.println("{\"event\":\"BUTTON_PRESSED\"}");
    delay(300); // Debounce
  } else {
    // Heartbeat blink
    digitalWrite(LED_PIN, HIGH);
    delay(50);
    digitalWrite(LED_PIN, LOW);
    delay(950);
  }
}
