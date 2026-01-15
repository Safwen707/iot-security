#include <WiFi.h>
#include <PubSubClient.h>

// ===============================
// SMART GUARDIAN - ASCON-128 AEAD + DEBUG MQTT
// ===============================

// ===============================
// PINS & CONFIG
// ===============================
#define SOUND_PIN 34
#define REED_PIN  25
#define SHOCK_PIN 26
#define LED_PIN   27

#define SOUND_THRESHOLD 1000
const int ledMaxDuty = 50;
const int minInterval = 200;
unsigned long lastShock = 0;

// ===============================
// ASCON-128 CONSTANTS
// ===============================
#define ASCON_RATE 8
#define ASCON_KEY_SIZE 16
#define ASCON_NONCE_SIZE 16
#define ASCON_TAG_SIZE 16

const uint64_t ASCON_IV = 0x80400c0600000000ULL;

uint8_t ascon_key[16] = {
  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

// ===============================
// WIFI & MQTT - AVEC PARAMÈTRES OPTIMISÉS
// ===============================
const char* ssid = "ooredoo-5EB433";
const char* password = "ABB0CDFFWn@40";
const char* mqtt_server = "192.168.100.230";
const int mqtt_port = 1883;

WiFiClient espClient;
PubSubClient client(espClient);

// ===============================
// ASCON STATE
// ===============================
uint64_t state[5];

// ===============================
// UTILITAIRES ASCON
// ===============================

uint64_t rotr64(uint64_t x, int n) {
  return (x >> n) | (x << (64 - n));
}

uint64_t bytes_to_uint64(const uint8_t* bytes, int offset) {
  uint64_t result = 0;
  for (int i = 0; i < 8; i++) {
    result = (result << 8) | bytes[offset + i];
  }
  return result;
}

void uint64_to_bytes(uint64_t value, uint8_t* bytes, int offset) {
  for (int i = 7; i >= 0; i--) {
    bytes[offset + i] = value & 0xFF;
    value >>= 8;
  }
}

void ascon_permutation(int rounds) {
  for (int r = 12 - rounds; r < 12; r++) {
    state[2] ^= ((0xfULL - r) << 4) | r;
    
    state[0] ^= state[4];
    state[4] ^= state[3];
    state[2] ^= state[1];
    
    uint64_t temp[5];
    for (int i = 0; i < 5; i++) {
      temp[i] = state[i] ^ (~state[(i + 1) % 5] & state[(i + 2) % 5]);
    }
    
    for (int i = 0; i < 5; i++) {
      state[i] = temp[i];
    }
    
    state[1] ^= state[0];
    state[0] ^= state[4];
    state[3] ^= state[2];
    state[2] = ~state[2];
    
    state[0] ^= rotr64(state[0], 19) ^ rotr64(state[0], 28);
    state[1] ^= rotr64(state[1], 61) ^ rotr64(state[1], 39);
    state[2] ^= rotr64(state[2], 1)  ^ rotr64(state[2], 6);
    state[3] ^= rotr64(state[3], 10) ^ rotr64(state[3], 17);
    state[4] ^= rotr64(state[4], 7)  ^ rotr64(state[4], 41);
  }
}

void ascon_init(const uint8_t* key, const uint8_t* nonce) {
  state[0] = ASCON_IV;
  state[1] = bytes_to_uint64(key, 0);
  state[2] = bytes_to_uint64(key, 8);
  state[3] = bytes_to_uint64(nonce, 0);
  state[4] = bytes_to_uint64(nonce, 8);
  
  ascon_permutation(12);
  
  state[3] ^= bytes_to_uint64(key, 0);
  state[4] ^= bytes_to_uint64(key, 8);
}

void ascon_process_ad(const uint8_t* ad, int ad_len) {
  if (ad_len == 0) {
    state[4] ^= 1ULL;
    return;
  }
  
  int offset = 0;
  while (offset < ad_len) {
    int block_size = (ad_len - offset >= ASCON_RATE) ? ASCON_RATE : (ad_len - offset);
    
    uint8_t ad_block[8] = {0};
    memcpy(ad_block, ad + offset, block_size);
    
    if (block_size < ASCON_RATE) {
      ad_block[block_size] = 0x80;
    }
    
    uint64_t ad_word = bytes_to_uint64(ad_block, 0);
    state[0] ^= ad_word;
    
    offset += block_size;
    
    if (offset < ad_len) {
      ascon_permutation(6);
    }
  }
  
  state[4] ^= 1ULL;
}

void ascon_encrypt_plaintext(const uint8_t* plaintext, int pt_len, uint8_t* ciphertext) {
  int offset = 0;
  while (offset < pt_len) {
    int block_size = (pt_len - offset >= ASCON_RATE) ? ASCON_RATE : (pt_len - offset);
    
    uint8_t keystream[8];
    uint64_to_bytes(state[0], keystream, 0);
    
    for (int i = 0; i < block_size; i++) {
      ciphertext[offset + i] = plaintext[offset + i] ^ keystream[i];
    }
    
    uint8_t ct_block[8] = {0};
    memcpy(ct_block, ciphertext + offset, block_size);
    if (block_size < ASCON_RATE) {
      ct_block[block_size] = 0x80;
    }
    
    state[0] = bytes_to_uint64(ct_block, 0);
    
    offset += block_size;
    
    if (offset < pt_len) {
      ascon_permutation(6);
    }
  }
}

void ascon_finalize(const uint8_t* key, uint8_t* tag) {
  state[1] ^= bytes_to_uint64(key, 0);
  state[2] ^= bytes_to_uint64(key, 8);
  
  ascon_permutation(12);
  
  state[3] ^= bytes_to_uint64(key, 0);
  state[4] ^= bytes_to_uint64(key, 8);
  
  uint64_to_bytes(state[3], tag, 0);
  uint64_to_bytes(state[4], tag, 8);
}

void ascon_aead_encrypt(
  const uint8_t* plaintext, int pt_len,
  const uint8_t* ad, int ad_len,
  const uint8_t* key,
  const uint8_t* nonce,
  uint8_t* ciphertext,
  uint8_t* tag
) {
  ascon_init(key, nonce);
  ascon_process_ad(ad, ad_len);
  ascon_encrypt_plaintext(plaintext, pt_len, ciphertext);
  ascon_finalize(key, tag);
}

// ===============================
// UTILITAIRES
// ===============================

bool detectShock() {
  int count = 0;
  for (int i = 0; i < 5; i++) {
    if (digitalRead(SHOCK_PIN) == HIGH) count++;
    delay(1);
  }
  return count >= 4;
}

String toHex(const uint8_t* data, int len) {
  String s = "";
  for (int i = 0; i < len; i++) {
    if (data[i] < 16) s += "0";
    s += String(data[i], HEX);
  }
  return s;
}

// ===============================
// WIFI / MQTT AVEC DEBUG COMPLET
// ===============================

void setup_wifi() {
  Serial.println("\n╔════════════════════════════════════╗");
  Serial.println("║     WIFI CONNECTION DEBUG         ║");
  Serial.println("╚════════════════════════════════════╝");
  
  Serial.printf("SSID: %s\n", ssid);
  Serial.printf("Password: %s\n", password);
  
  WiFi.disconnect(true);
  delay(1000);
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  
  int attempt = 0;
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    attempt++;
    
    if (attempt % 10 == 0) {
      Serial.printf("\n[Attempt %d] Status: %d\n", attempt, WiFi.status());
    }
    
    if (attempt > 40) {
      Serial.println("\n❌ WiFi Connection FAILED!");
      Serial.println("Possible issues:");
      Serial.println("  - Wrong SSID/Password");
      Serial.println("  - Router too far");
      Serial.println("  - 5GHz network (ESP32 needs 2.4GHz)");
      return;
    }
  }
  
  Serial.println("\n✅ WiFi Connected!");
  Serial.printf("IP Address: %s\n", WiFi.localIP().toString().c_str());
  Serial.printf("Gateway: %s\n", WiFi.gatewayIP().toString().c_str());
  Serial.printf("Signal Strength: %d dBm\n", WiFi.RSSI());
}

void reconnect() {
  Serial.println("\n╔════════════════════════════════════╗");
  Serial.println("║     MQTT CONNECTION DEBUG         ║");
  Serial.println("╚════════════════════════════════════╝");
  
  int attempt = 0;
  while (!client.connected() && attempt < 5) {
    attempt++;
    
    Serial.printf("\n[Attempt %d/5]\n", attempt);
    Serial.printf("Broker: %s:%d\n", mqtt_server, mqtt_port);
    Serial.printf("Client ID: ESP32_Guardian\n");
    
    // Test de connexion réseau au broker
    WiFiClient testClient;
    Serial.print("Testing TCP connection to broker... ");
    if (testClient.connect(mqtt_server, mqtt_port)) {
      Serial.println("✅ TCP reachable");
      testClient.stop();
    } else {
      Serial.println("❌ TCP unreachable!");
      Serial.println("Possible issues:");
      Serial.println("  - Broker offline");
      Serial.println("  - Wrong IP address");
      Serial.println("  - Firewall blocking port 1883");
      delay(2000);
      continue;
    }
    
    // Tentative de connexion MQTT
    Serial.print("Connecting to MQTT broker... ");
    
    if (client.connect("ESP32_Guardian")) {
      Serial.println("✅ MQTT Connected!");
      Serial.printf("Max packet size: %d bytes\n", client.getBufferSize());
      return;
    } else {
      Serial.println("❌ MQTT Connection Failed!");
      Serial.printf("Error code: %d\n", client.state());
      
      // Décodage des erreurs MQTT
      switch(client.state()) {
        case -4:
          Serial.println("  → Connection timeout");
          break;
        case -3:
          Serial.println("  → Connection lost");
          break;
        case -2:
          Serial.println("  → Connect failed");
          break;
        case -1:
          Serial.println("  → Disconnected");
          break;
        case 1:
          Serial.println("  → Bad protocol");
          break;
        case 2:
          Serial.println("  → Bad client ID");
          break;
        case 3:
          Serial.println("  → Unavailable");
          break;
        case 4:
          Serial.println("  → Bad credentials");
          break;
        case 5:
          Serial.println("  → Unauthorized");
          break;
        default:
          Serial.println("  → Unknown error");
      }
      
      delay(2000);
    }
  }
  
  if (!client.connected()) {
    Serial.println("\n❌ Could not connect to MQTT after 5 attempts");
  }
}

// ===============================
// SETUP
// ===============================

void setup() {
  Serial.begin(115200);
  delay(2000);
  
  Serial.println("\n╔════════════════════════════════════════╗");
  Serial.println("║  SMART GUARDIAN - ASCON-128 AEAD      ║");
  Serial.println("║  Complete 4-Phase + MQTT Debug        ║");
  Serial.println("╚════════════════════════════════════════╝\n");

  pinMode(SOUND_PIN, INPUT);
  pinMode(REED_PIN, INPUT_PULLUP);
  pinMode(SHOCK_PIN, INPUT_PULLDOWN);
  pinMode(LED_PIN, OUTPUT);

  setup_wifi();
  
  // AUGMENTER LE BUFFER MQTT (par défaut 256 bytes peut être insuffisant)
  client.setBufferSize(1024);  // 1KB pour messages longs
  Serial.printf("MQTT Buffer size set to: %d bytes\n", client.getBufferSize());
  
  client.setServer(mqtt_server, mqtt_port);
  client.setKeepAlive(15);  // Keepalive 15 secondes
  
  reconnect();

  Serial.println("\n✅ SMART GUARDIAN READY\n");
}

// ===============================
// LOOP AVEC DEBUG MQTT
// ===============================

void loop() {
  // Vérifier connexion WiFi
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("❌ WiFi disconnected! Reconnecting...");
    setup_wifi();
  }
  
  // Vérifier connexion MQTT
  if (!client.connected()) {
    Serial.println("❌ MQTT disconnected! Reconnecting...");
    reconnect();
  }
  
  client.loop();
  
  // --- Lecture capteurs ---
  bool soundDetected = analogRead(SOUND_PIN) > SOUND_THRESHOLD;
  bool doorOpen = digitalRead(REED_PIN) == HIGH;

  bool shockDetected = false;
  if (detectShock() && millis() - lastShock > minInterval) {
    shockDetected = true;
    lastShock = millis();
    analogWrite(LED_PIN, ledMaxDuty);
  } else {
    analogWrite(LED_PIN, 0);
  }

  int threat = soundDetected * 25 + doorOpen * 40 + shockDetected * 35;
  uint32_t timestamp = millis() / 1000;

  // --- Construction JSON plaintext ---
  String json =
    "{"
    "\"ts\":" + String(timestamp) + ","
    "\"sound\":" + String(soundDetected) + ","
    "\"door\":" + String(doorOpen) + ","
    "\"shock\":" + String(shockDetected) + ","
    "\"threat\":" + String(threat) +
    "}";

  Serial.println("\n─────────────────────────────────────");
  Serial.println("📊 SENSOR DATA:");
  Serial.println("─────────────────────────────────────");
  Serial.printf("Sound: %s\n", soundDetected ? "DETECTED" : "Normal");
  Serial.printf("Door:  %s\n", doorOpen ? "OPEN" : "Closed");
  Serial.printf("Shock: %s\n", shockDetected ? "DETECTED" : "Normal");
  Serial.printf("Threat Score: %d/100\n", threat);
  Serial.printf("Plaintext: %s\n", json.c_str());
  Serial.printf("Plaintext size: %d bytes\n", json.length());
  Serial.println("─────────────────────────────────────");

  // --- Génération nonce ---
  uint8_t nonce[ASCON_NONCE_SIZE];
  for (int i = 0; i < ASCON_NONCE_SIZE; i++) {
    nonce[i] = esp_random() & 0xFF;
  }

  // --- Associated Data ---
  String ad_str = "ESP32-GUARDIAN|FW:v1.0|MSG#" + String(millis());
  uint8_t ad[64];
  int ad_len = ad_str.length();
  memcpy(ad, ad_str.c_str(), ad_len);

  // --- Plaintext ---
  uint8_t plaintext[256];
  int pt_len = json.length();
  memcpy(plaintext, json.c_str(), pt_len);

  // --- Chiffrement ASCON ---
  uint8_t ciphertext[256];
  uint8_t tag[ASCON_TAG_SIZE];

  Serial.println("\n🔐 Starting ASCON-128 encryption...");
  ascon_aead_encrypt(
    plaintext, pt_len,
    ad, ad_len,
    ascon_key,
    nonce,
    ciphertext,
    tag
  );
  Serial.println("✅ Encryption complete");

  // --- Construction message MQTT ---
  String message = "{";
  message += "\"nonce\":\"" + toHex(nonce, ASCON_NONCE_SIZE) + "\",";
  message += "\"ad\":\"" + ad_str + "\",";
  message += "\"cipher\":\"" + toHex(ciphertext, pt_len) + "\",";
  message += "\"tag\":\"" + toHex(tag, ASCON_TAG_SIZE) + "\"";
  message += "}";

  Serial.println("\n╔═══════════════════════════════════════╗");
  Serial.println("║         MQTT PUBLISH DEBUG            ║");
  Serial.println("╚═══════════════════════════════════════╝");
  Serial.printf("Topic: smartguardian/alert\n");
  Serial.printf("Message size: %d bytes\n", message.length());
  Serial.printf("Buffer size: %d bytes\n", client.getBufferSize());
  
  if (message.length() > client.getBufferSize()) {
    Serial.println("❌ ERROR: Message too large for buffer!");
    Serial.println("Solution: Increase buffer size in setup()");
  }
  
  Serial.println("\nMessage preview ");
  Serial.println(message);

  // --- Publication MQTT avec vérifications ---
  if (!client.connected()) {
    Serial.println("❌ Client not connected!");
    reconnect();
  }

  if (client.connected()) {
    Serial.print("\n📤 Publishing... ");
    
    bool success = client.publish("smartguardian/alert", message.c_str());
    
    if (success) {
      Serial.println("✅ PUBLISH SUCCESS!");
    } else {
      Serial.println("❌ PUBLISH FAILED!");
      Serial.println("\nDebug info:");
      Serial.printf("  - Client state: %d\n", client.state());
      Serial.printf("  - WiFi RSSI: %d dBm\n", WiFi.RSSI());
      Serial.printf("  - Free heap: %d bytes\n", ESP.getFreeHeap());
      Serial.printf("  - Message length: %d bytes\n", message.length());
      Serial.printf("  - Buffer size: %d bytes\n", client.getBufferSize());
      
      Serial.println("\nPossible causes:");
      Serial.println("  1. Message too large for buffer");
      Serial.println("  2. Network congestion");
      Serial.println("  3. Broker overloaded");
      Serial.println("  4. QoS issue");
      Serial.println("\nRetrying in 5 seconds...");
      delay(5000);
      
      // Tentative de republication
      Serial.print("Retry... ");
      if (client.publish("smartguardian/alert", message.c_str())) {
        Serial.println("✅ SUCCESS on retry!");
      } else {
        Serial.println("❌ Failed again");
      }
    }
  } else {
    Serial.println("❌ Cannot publish - not connected to broker");
  }

  Serial.println("\n═══════════════════════════════════════\n");

  delay(2000);
}

/*
 * ═══════════════════════════════════════════════════════════════
 * DIAGNOSTIC DES ERREURS "PUBLISH FAILED" COMMUNES
 * ═══════════════════════════════════════════════════════════════
 * 
 * 1. BUFFER TROP PETIT (Cause #1 la plus fréquente)
 *    Solution: client.setBufferSize(1024) dans setup()
 * 
 * 2. BROKER INACCESSIBLE
 *    - Vérifier IP broker avec ping 192.168.100.230
 *    - Vérifier broker actif: mosquitto -v
 * 
 * 3. FIREWALL
 *    - Port 1883 bloqué sur broker
 *    Solution: sudo ufw allow 1883
 * 
 * 4. CONNEXION MQTT PERDUE
 *    - Vérifier keepalive
 *    - Augmenter setKeepAlive() à 60 secondes
 * 
 * 5. WIFI INSTABLE
 *    - Signal faible (< -80 dBm)
 *    - Rapprocher ESP32 du routeur
 * 
 * 6. MÉMOIRE INSUFFISANTE
 *    - Vérifier getFreeHeap()
 *    - Réduire taille buffers si < 50KB
 * 
 * ═══════════════════════════════════════════════════════════════
 */
