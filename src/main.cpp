#include <Arduino.h>
#include <EspMQTTClient.h>

#include <Crypto.h>
#include <AES.h>
#include <string.h>

#include <LiquidCrystal_I2C.h>

#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#include "Secrets.h"
#include "Utils.h"

#include "display.h"
#include "card.h"
#include "config.h"
#include "mqtt_protocol.h"
#include "mqtt_types.h"

struct
{
  String url;
  String usr;
  String pw;
  String id;
  String SSID;
  String KEY;
  int port;
} mqtt_data;

String clientID = "TestClient";

Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

EspMQTTClient client;

// set the LCD number of columns and rows
int lcdColumns = 16;
int lcdRows = 2;

// set LCD address, number of columns and rows
// if you don't know your display address, run an I2C scanner sketch
LiquidCrystal_I2C lcd(0x27, lcdColumns, lcdRows);

enum state
{
  WAITING_FOR_USER_ID,
  WAITING_FOR_USER_BUFFER,
} current_state;

int last_state_change;

char last_will[200] = {}; // to fix wierd pointer issure with the last will message
const char *last_msg = last_will;

enum mode
{
  NONE,
  AUTHENTICATE,
  REGISTER,
  READ,
} current_mode;

AES128 aes128;

// MQTT Protocol objects
MQTTMessageBuilder mqttBuilder;
MQTTMessageParser mqttParser;
MQTTTopicBuilder mqttTopics;

// Read mode state
char read_request_id[MAX_UUID_LENGTH + 1] = {0};

// Register mode state
struct {
  char request_id[MAX_UUID_LENGTH + 1];
  char tag_uid[MAX_TAG_UID_LENGTH + 1];
  unsigned char tag_uid_binary[8];
  char key[MAX_HEX_KEY_LENGTH + 1];
  unsigned char key_binary[16];
  unsigned char user_data[USER_BUFFER_LENGTH + 1];
} register_state;

// Auth mode state
struct {
  char request_id[MAX_UUID_LENGTH + 1];
  unsigned char tag_uid_binary[8];
  char key[MAX_HEX_KEY_LENGTH + 1];
  unsigned char key_binary[16];
  unsigned char encryption_data[16];
  // Store user_data to echo back in response
  char username[64];
  char context[64];
} auth_state;

// Utility functions for hex/binary conversion
void hexStringToBinary(const char* hexStr, unsigned char* binary, size_t binaryLen) {
  for (size_t i = 0; i < binaryLen; i++) {
    sscanf(&hexStr[i * 2], "%2hhx", &binary[i]);
  }
}

void clearAuthState() {
  memset(&auth_state, 0, sizeof(auth_state));
}

void clearRegisterState() {
  memset(&register_state, 0, sizeof(register_state));
}

void onConnectionEstablished();
void handleCommand(const String &command);
void handleDisplay(const String &payload);
void handleData(const String &payload);
bool containsOnlyZeroes(const String &str);
void load_flash();

void setup()
{ // Open USB serial port
  Serial.begin(115200);

  // initialize LCD
  lcd.init();
  // turn on LCD backlight
  lcd.backlight();

  display_clear();

  display.begin(SSD1306_SWITCHCAPVCC, 0x3C);
  display.clearDisplay();
  display.display();

  pinMode(WM_TRIGGER_PIN, INPUT_PULLUP);
  Serial.println(wm.getWiFiSSID());
  Serial.println(wm.getWiFiPass());

  preferences.begin("my-app", false);

  if (digitalRead(WM_TRIGGER_PIN) == LOW)
  {
    WiFi.mode(WIFI_STA); // explicitly set mode, esp defaults to STA+AP
    display_settings_mode();
    run_config_portal();
  }
  load_flash();
  preferences.end();

  client.setWifiCredentials(mqtt_data.SSID.c_str(), mqtt_data.KEY.c_str());
  client.setMqttServer(mqtt_data.url.c_str(), mqtt_data.usr.c_str(), mqtt_data.pw.c_str(), mqtt_data.port);
  client.setMqttClientName(mqtt_data.id.c_str());
  
  // Initialize MQTT protocol objects with device ID
  mqttBuilder.setDeviceId(clientID.c_str());
  mqttTopics.setDeviceId(clientID.c_str());

  // Software SPI is configured to run a slow clock of 10 kHz which can be transmitted over longer cables.
  gi_PN532.InitSoftwareSPI(SPI_CLK_PIN, SPI_MISO_PIN, SPI_MOSI_PIN, SPI_CS_PIN, RESET_PIN);

  pinMode(learn, INPUT_PULLUP);

  InitReader(false);

#if USE_DESFIRE
  gi_PiccMasterKey.SetKeyData(SECRET_PICC_MASTER_KEY, sizeof(SECRET_PICC_MASTER_KEY), CARD_KEY_VERSION);
#endif

  // -------------------------------------------------------------------------------------------------------
  // -------------------------------------------------------------------------------------------------------

  current_state = WAITING_FOR_USER_ID;
  last_state_change = millis();
  current_mode = NONE;

  client.setMaxPacketSize(500);
  // Optional functionalities of EspMQTTClient
  client.enableDebuggingMessages(); // Enable debugging messages sent to serial output
  // client.enableHTTPWebUpdater(); // Enable the web updater. User and password default to values of MQTTUsername and MQTTPassword. These can be overridded with enableHTTPWebUpdater("user", "password").
  //  client.enableOTA(); // Enable OTA (Over The Air) updates. Password defaults to MQTTPassword. Port is the default OTA port. Can be overridden with enableOTA("password", port).
  client.enableDrasticResetOnConnectionFailures();

  /*char buffer[100]; // Make sure the buffer is large enough
  char concatenatedString[100]; // Make sure this buffer is large enough too

  char disconnect[20];
  strcpy(disconnect,"disconnect");


  strcpy(buffer, "device/");
  strcat(buffer, clientID.c_str());
  strcat(buffer, "/register");

  strcpy(concatenatedString, buffer); // Copy the concatenated string*/

  String message3 = "device/" + String(clientID) + "/register";
  message3.toCharArray(last_will, message3.length() + 1);
  client.enableLastWillMessage(last_msg, "disconnect", true); // You can activate the retain flag by setting the third parameter to true
}

void loop()
{
  client.loop();

  if (!(client.isMqttConnected() && client.isWifiConnected()))
  {
    display_connectionloss();
    return;
  }

  // Handle waiting_for_user_buffer timeout
  if (current_state == WAITING_FOR_USER_BUFFER && millis() - last_state_change > 20000)
  {
    Serial.println("Timeout while waiting for user buffer");
    current_state = WAITING_FOR_USER_ID;
    display_fail();
    delay(1000);
  }

  if (current_mode == NONE)
  {
    display_mode_standby();
    return;
  }

  if (current_state == WAITING_FOR_USER_ID && current_mode == AUTHENTICATE)
  {

    display_place_card();

    unsigned char ID[8] = {0};

    clear_kCard(&last_card);
    if (ReadCard(ID, &last_card))
    {
      // Card present in the RF field
      if (last_card.u8_UidLength > 0)
      {
        // Store binary UID in auth state
        memcpy(auth_state.tag_uid_binary, ID, 8);
        
        // Convert tag UID to colon-separated hex string
        char tagUidHex[MAX_TAG_UID_LENGTH + 1];
        snprintf(tagUidHex, sizeof(tagUidHex), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 ID[0], ID[1], ID[2], ID[3], ID[4], ID[5], ID[6], ID[7]);
        
        // Build and publish TAG_DETECTED event
        TagDetectedPayload tagPayload;
        strlcpy(tagPayload.tag_uid, tagUidHex, sizeof(tagPayload.tag_uid));
        strlcpy(tagPayload.message, "Tag detected. Awaiting verification.", sizeof(tagPayload.message));
        
        const char* tagMsg = mqttBuilder.buildTagDetected(auth_state.request_id, tagPayload);
        client.publish(mqttTopics.authTagDetected(), tagMsg);
        
        current_state = WAITING_FOR_USER_BUFFER;
        printUnsignedCharArrayAsHex(ID, 8);
        last_state_change = millis();
        display_processing();
      }

      else
      {
        gu64_LastID = 0;
      }
    }

    else
    {
      // Handle NFC errors
      if (IsDesfireTimeout())
      {
        // Send error event
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "NFC timeout", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_TIMEOUT;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildAuthError(auth_state.request_id, errorPayload);
        client.publish(mqttTopics.authError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
      }
      else if (last_card.b_PN532_Error) // Another error from PN532 -> reset the chip
      {
        // Send error event
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "PN532 communication error", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_DEVICE_ERROR;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildAuthError(auth_state.request_id, errorPayload);
        client.publish(mqttTopics.authError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
        InitReader(true); // flash red LED for 2.4 seconds
      }
      else // e.g. Error while authenticating with master key
      {
        // Send error event
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "Authentication error", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_AUTH_FAILED;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildAuthError(auth_state.request_id, errorPayload);
        client.publish(mqttTopics.authError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
      }

      Utils::Print("> ");
    }
  }
  
  // READ mode handling
  if (current_state == WAITING_FOR_USER_ID && current_mode == READ)
  {
    display_place_card();

    unsigned char ID[8] = {0};

    clear_kCard(&last_card);
    if (ReadCard(ID, &last_card))
    {
      // Card present in the RF field
      if (last_card.u8_UidLength > 0)
      {
        // Convert tag UID to hex string
        char tagUidHex[MAX_TAG_UID_LENGTH + 1];
        snprintf(tagUidHex, sizeof(tagUidHex), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 ID[0], ID[1], ID[2], ID[3], ID[4], ID[5], ID[6], ID[7]);
        
        Serial.print("Card detected for reading: ");
        Serial.println(tagUidHex);
        
        // Build READ_SUCCESS event
        ReadSuccessPayload readPayload;
        strlcpy(readPayload.tag_uid, tagUidHex, sizeof(readPayload.tag_uid));
        strlcpy(readPayload.message, "Tag read successfully", sizeof(readPayload.message));
        
        // Publish the read success event
        const char* readMsg = mqttBuilder.buildReadSuccess(read_request_id, readPayload);
        client.publish(mqttTopics.readSuccess(), readMsg);
        
        Serial.println("Read success published");
        
        display_success();
        delay(1000);
        
        // Reset to idle mode
        ModeChangePayload modePayload;
        modePayload.mode = DeviceMode::IDLE;
        modePayload.previous_mode = DeviceMode::READ;
        const char* modeMsg = mqttBuilder.buildModeChange(read_request_id, modePayload);
        client.publish(mqttTopics.mode(), modeMsg, true);
        
        current_mode = NONE;
        current_state = WAITING_FOR_USER_ID;
        memset(read_request_id, 0, sizeof(read_request_id));
        
        clear_kCard(&last_card);
      }
      else
      {
        gu64_LastID = 0;
      }
    }
    else
    {
      // Handle NFC errors
      if (IsDesfireTimeout())
      {
        // Send error event
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "NFC timeout", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_TIMEOUT;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildReadError(read_request_id, errorPayload);
        client.publish(mqttTopics.readError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
      }
      else if (last_card.b_PN532_Error)
      {
        // Send error event
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "PN532 communication error", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_DEVICE_ERROR;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildReadError(read_request_id, errorPayload);
        client.publish(mqttTopics.readError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
        InitReader(true);
      }
      else
      {
        // Send error event
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "NFC read error", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_READ_ERROR;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildReadError(read_request_id, errorPayload);
        client.publish(mqttTopics.readError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
      }

      Utils::Print("> ");
    }
  }
  
  // REGISTER mode handling
  if (current_state == WAITING_FOR_USER_ID && current_mode == REGISTER)
  {
    display_place_card();

    unsigned char ID[8] = {0};

    clear_kCard(&last_card);
    if (ReadCard(ID, &last_card))
    {
      // Card present in the RF field
      if (last_card.u8_UidLength > 0)
      {
        // Convert detected tag UID to hex string for comparison
        char detectedUidHex[MAX_TAG_UID_LENGTH + 1];
        snprintf(detectedUidHex, sizeof(detectedUidHex), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
                 ID[0], ID[1], ID[2], ID[3], ID[4], ID[5], ID[6], ID[7]);
        
        Serial.print("Card detected for registration: ");
        Serial.println(detectedUidHex);
        Serial.print("Expected UID: ");
        Serial.println(register_state.tag_uid);
        
        // Check if this is the correct card
        if (strcmp(detectedUidHex, register_state.tag_uid) == 0)
        {
          Serial.println("UID matches - proceeding with registration");
          
          // Store the binary UID
          memcpy(register_state.tag_uid_binary, ID, 8);
          
          unsigned char outID[8] = {0};
          
          // Customize the card with the key (key_binary was already converted in REGISTER_START)
          // Use the tag_uid as the user_buff parameter (for deriving application keys)
          // Pass the already-read card data to avoid waiting for card again
          if (customize_card(register_state.tag_uid, register_state.key_binary, outID, &last_card))
          {
            Serial.println("Card registration successful");
            
            // Build REGISTER_SUCCESS event
            RegisterSuccessPayload registerPayload;
            strlcpy(registerPayload.tag_uid, register_state.tag_uid, sizeof(registerPayload.tag_uid));
            strlcpy(registerPayload.message, "Tag registered successfully", sizeof(registerPayload.message));
            registerPayload.blocks_written = 1;
            
            const char* registerMsg = mqttBuilder.buildRegisterSuccess(register_state.request_id, registerPayload);
            client.publish(mqttTopics.registerSuccess(), registerMsg);
            
            display_success();
            delay(1000);
            
            // Reset to idle mode
            ModeChangePayload modePayload;
            modePayload.mode = DeviceMode::IDLE;
            modePayload.previous_mode = DeviceMode::REGISTER;
            const char* modeMsg = mqttBuilder.buildModeChange(register_state.request_id, modePayload);
            client.publish(mqttTopics.mode(), modeMsg, true);
            
            current_mode = NONE;
            current_state = WAITING_FOR_USER_ID;
            clearRegisterState();
            
            clear_kCard(&last_card);
          }
          else
          {
            Serial.println("Card registration failed");
            
            // Registration failed
            ErrorPayload errorPayload;
            strlcpy(errorPayload.error, "Failed to write to card", sizeof(errorPayload.error));
            errorPayload.error_code = ErrorCode::NFC_WRITE_ERROR;
            errorPayload.retry_possible = true;
            errorPayload.component = ErrorComponent::NFC;
            
            const char* errorMsg = mqttBuilder.buildRegisterError(register_state.request_id, errorPayload);
            client.publish(mqttTopics.registerError(), errorMsg);
            
            display_fail();
            delay(1000);
            display_place_card();
          }
        }
        else
        {
          Serial.println("UID does not match - wrong card");
          
          // Wrong card detected
          ErrorPayload errorPayload;
          strlcpy(errorPayload.error, "Wrong card - UID mismatch", sizeof(errorPayload.error));
          errorPayload.error_code = ErrorCode::NFC_UNSUPPORTED_TAG;
          errorPayload.retry_possible = true;
          errorPayload.component = ErrorComponent::NFC;
          
          const char* errorMsg = mqttBuilder.buildRegisterError(register_state.request_id, errorPayload);
          client.publish(mqttTopics.registerError(), errorMsg);
          
          display_fail();
          delay(1000);
          display_place_card();
        }
      }
      else
      {
        gu64_LastID = 0;
      }
    }
    else
    {
      // Handle NFC errors
      if (IsDesfireTimeout())
      {
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "NFC timeout", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_TIMEOUT;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildRegisterError(register_state.request_id, errorPayload);
        client.publish(mqttTopics.registerError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
      }
      else if (last_card.b_PN532_Error)
      {
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "PN532 communication error", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_DEVICE_ERROR;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildRegisterError(register_state.request_id, errorPayload);
        client.publish(mqttTopics.registerError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
        InitReader(true);
      }
      else
      {
        ErrorPayload errorPayload;
        strlcpy(errorPayload.error, "NFC read error", sizeof(errorPayload.error));
        errorPayload.error_code = ErrorCode::NFC_READ_ERROR;
        errorPayload.retry_possible = true;
        errorPayload.component = ErrorComponent::NFC;
        
        const char* errorMsg = mqttBuilder.buildRegisterError(register_state.request_id, errorPayload);
        client.publish(mqttTopics.registerError(), errorMsg);
        
        display_fail();
        delay(1000);
        display_place_card();
      }

      Utils::Print("> ");
    }
  }
}

void onConnectionEstablished()
{
  // Subscribe to specific command topics (not using wildcard to avoid receiving our own events)
  client.subscribe(mqttTopics.registerStart(), [](const String &payload)
                   { handleCommand(payload); }, qos);
  client.subscribe(mqttTopics.registerCancel(), [](const String &payload)
                   { handleCommand(payload); }, qos);
  client.subscribe(mqttTopics.authStart(), [](const String &payload)
                   { handleCommand(payload); }, qos);
  client.subscribe(mqttTopics.authVerify(), [](const String &payload)
                   { handleCommand(payload); }, qos);
  client.subscribe(mqttTopics.authCancel(), [](const String &payload)
                   { handleCommand(payload); }, qos);
  client.subscribe(mqttTopics.readStart(), [](const String &payload)
                   { handleCommand(payload); }, qos);
  client.subscribe(mqttTopics.readCancel(), [](const String &payload)
                   { handleCommand(payload); }, qos);
  client.subscribe(mqttTopics.reset(), [](const String &payload)
                   { handleCommand(payload); }, qos);

  // Also keep backward compatibility with display commands for now
  client.subscribe("device/" + clientID + "/receive/display", [](const String &payload)
                   {
        Serial.println("Remote Display Command");
        handleDisplay(payload); }, qos);

  // Send status_change event (ONLINE)
  StatusChangePayload statusPayload;
  statusPayload.status = DeviceStatus::ONLINE;
  strlcpy(statusPayload.firmware_version, "1.0.0", sizeof(statusPayload.firmware_version));
  strlcpy(statusPayload.ip_address, WiFi.localIP().toString().c_str(), sizeof(statusPayload.ip_address));
  
  char requestId[MAX_UUID_LENGTH + 1];
  generateUUID(requestId, sizeof(requestId));
  
  const char* statusMessage = mqttBuilder.buildStatusChange(requestId, statusPayload);
  client.publish(mqttTopics.status(), statusMessage, true); // retained
  
  Serial.println("MQTT Connected - Published status change (ONLINE)");
}

void handleCommand(const String &payload)
{  
  // Parse the incoming MQTT message
  if (!mqttParser.parse(payload.c_str())) {
    Serial.println("Failed to parse MQTT command message");
    return;
  }
  
  // Get command type
  CommandType cmdType = mqttParser.getCommandType();
  const char* requestId = mqttParser.getRequestId();
  
  Serial.print("Parsed command type: ");
  Serial.println(commandTypeToString(cmdType));
  
  switch (cmdType) {
    case CommandType::AUTH_START: {
      Serial.println("Handling AUTH_START command");
      AuthStartPayload authPayload;
      if (mqttParser.parseAuthStart(authPayload)) {
        Serial.println("Enable Authenticate Mode");
        Serial.print("Timeout: ");
        Serial.println(authPayload.timeout_seconds);
        
        // Clear and initialize auth state
        clearAuthState();
        strlcpy(auth_state.request_id, requestId, sizeof(auth_state.request_id));
        
        display_authenticate_mode();
        current_mode = AUTHENTICATE;
        current_state = WAITING_FOR_USER_ID;
        
        // Send mode change event
        ModeChangePayload modePayload;
        modePayload.mode = DeviceMode::AUTH;
        modePayload.previous_mode = DeviceMode::IDLE;
        const char* modeMsg = mqttBuilder.buildModeChange(requestId, modePayload);
        client.publish(mqttTopics.mode(), modeMsg, true);
        Serial.println("Mode change published");
      } else {
        Serial.println("Failed to parse AuthStart payload");
      }
      break;
    }
    
    case CommandType::REGISTER_START: {
      Serial.println("Handling REGISTER_START command");
      RegisterStartPayload registerPayload;
      if (mqttParser.parseRegisterStart(registerPayload)) {
        Serial.println("Enable Register Mode");
        Serial.print("Tag UID: ");
        Serial.println(registerPayload.tag_uid);
        Serial.print("Key: ");
        Serial.println(registerPayload.key);
        Serial.print("Timeout: ");
        Serial.println(registerPayload.timeout_seconds);
        
        // Clear and initialize register state
        clearRegisterState();
        strlcpy(register_state.request_id, requestId, sizeof(register_state.request_id));
        strlcpy(register_state.tag_uid, registerPayload.tag_uid, sizeof(register_state.tag_uid));
        strlcpy(register_state.key, registerPayload.key, sizeof(register_state.key));
        
        // Convert hex key to binary
        hexStringToBinary(registerPayload.key, register_state.key_binary, 16);
        
        display_register_mode();
        current_mode = REGISTER;
        current_state = WAITING_FOR_USER_ID;
        
        // Send mode change event
        ModeChangePayload modePayload;
        modePayload.mode = DeviceMode::REGISTER;
        modePayload.previous_mode = DeviceMode::IDLE;
        const char* modeMsg = mqttBuilder.buildModeChange(requestId, modePayload);
        client.publish(mqttTopics.mode(), modeMsg, true);
        Serial.println("Mode change published - waiting for card");
      } else {
        Serial.println("Failed to parse RegisterStart payload");
      }
      break;
    }
    
    case CommandType::AUTH_CANCEL:
    case CommandType::REGISTER_CANCEL: {
      Serial.println("Cancel Mode");
      display_mode_standby();
      
      // Send mode change event - use the appropriate stored request_id
      ModeChangePayload modePayload;
      modePayload.mode = DeviceMode::IDLE;
      DeviceMode prevMode = DeviceMode::IDLE;
      const char* cancelRequestId = requestId; // default to incoming command's request_id
      
      if (current_mode == AUTHENTICATE) {
        prevMode = DeviceMode::AUTH;
        cancelRequestId = auth_state.request_id;
      }
      else if (current_mode == REGISTER) {
        prevMode = DeviceMode::REGISTER;
        cancelRequestId = register_state.request_id;
      }
      else if (current_mode == READ) {
        prevMode = DeviceMode::READ;
        cancelRequestId = read_request_id;
      }
      
      modePayload.previous_mode = prevMode;
      const char* modeMsg = mqttBuilder.buildModeChange(cancelRequestId, modePayload);
      client.publish(mqttTopics.mode(), modeMsg, true);
      
      // Clear state based on mode
      if (current_mode == AUTHENTICATE) {
        clearAuthState();
      }
      else if (current_mode == REGISTER) {
        clearRegisterState();
      }
      
      current_mode = NONE;
      current_state = WAITING_FOR_USER_ID;
      break;
    }
    
    case CommandType::RESET: {
      Serial.println("Resetting device");
      
      // Send mode change to IDLE (mode is retained, so we must always update it before reset)
      ModeChangePayload modePayload;
      modePayload.mode = DeviceMode::IDLE;
      
      // Determine previous mode
      if (current_mode == AUTHENTICATE) {
        modePayload.previous_mode = DeviceMode::AUTH;
      } else if (current_mode == REGISTER) {
        modePayload.previous_mode = DeviceMode::REGISTER;
      } else if (current_mode == READ) {
        modePayload.previous_mode = DeviceMode::READ;
      } else {
        // current_mode == NONE means we're in an unknown/idle state
        modePayload.previous_mode = DeviceMode::UNKNOWN;
      }
      
      const char* modeMsg = mqttBuilder.buildModeChange(requestId, modePayload);
      client.publish(mqttTopics.mode(), modeMsg, true); // retained
      delay(100); // Give time for message to be sent
      
      // Clear all state variables (will be in IDLE after reboot)
      current_mode = NONE;
      current_state = WAITING_FOR_USER_ID;
      memset(read_request_id, 0, sizeof(read_request_id));
      clearAuthState();
      clearRegisterState();

      // Send status change (OFFLINE) before resetting
      StatusChangePayload statusPayload;
      statusPayload.status = DeviceStatus::OFFLINE;
      strlcpy(statusPayload.firmware_version, "1.0.0", sizeof(statusPayload.firmware_version));
      strlcpy(statusPayload.ip_address, WiFi.localIP().toString().c_str(), sizeof(statusPayload.ip_address));
      const char* statusMsg = mqttBuilder.buildStatusChange(requestId, statusPayload);
      client.publish(mqttTopics.status(), statusMsg, true);
      
      delay(500); // Give time for message to be sent
      ESP.restart();
      break;
    }
    
    case CommandType::AUTH_VERIFY: {
      // Handle AUTH_VERIFY - use the tag UID already stored from tag detection
      AuthVerifyPayload verifyPayload;
      if (mqttParser.parseAuthVerify(verifyPayload)) {
        Serial.println("Received AUTH_VERIFY command");
        
        // Store key and convert to binary
        strlcpy(auth_state.key, verifyPayload.key, sizeof(auth_state.key));
        hexStringToBinary(verifyPayload.key, auth_state.key_binary, 16);
        
        // Store user_data to echo back in the response
        strlcpy(auth_state.username, verifyPayload.user_data.username, sizeof(auth_state.username));
        strlcpy(auth_state.context, verifyPayload.user_data.context, sizeof(auth_state.context));
        
        // encryption_data should remain as-is (can be used for challenge-response if needed)
        // For now, just clear it - the authenticate_user function may populate it
        memset(auth_state.encryption_data, 0, sizeof(auth_state.encryption_data));
        
        // Trigger authentication
        current_state = WAITING_FOR_USER_BUFFER;
        handleData(""); // Process authentication
      }
      break;
    }
    
    case CommandType::READ_START: {
      Serial.println("Handling READ_START command");
      ReadStartPayload readPayload;
      if (mqttParser.parseReadStart(readPayload)) {
        Serial.println("Enable Read Mode");
        Serial.print("Timeout: ");
        Serial.println(readPayload.timeout_seconds);
        
        // Store read parameters for later use
        strlcpy(read_request_id, requestId, sizeof(read_request_id));
        
        current_mode = READ;
        current_state = WAITING_FOR_USER_ID;
        
        // Send mode change event
        ModeChangePayload modePayload;
        modePayload.mode = DeviceMode::READ;
        modePayload.previous_mode = DeviceMode::IDLE;
        const char* modeMsg = mqttBuilder.buildModeChange(requestId, modePayload);
        client.publish(mqttTopics.mode(), modeMsg, true);
        Serial.println("Mode change published - waiting for tag to read");
      } else {
        Serial.println("Failed to parse ReadStart payload");
      }
      break;
    }
    
    case CommandType::READ_CANCEL: {
      Serial.println("Cancel Read Mode");
      display_mode_standby();
      
      // Send mode change event
      ModeChangePayload modePayload;
      modePayload.mode = DeviceMode::IDLE;
      modePayload.previous_mode = DeviceMode::READ;
      const char* modeMsg = mqttBuilder.buildModeChange(requestId, modePayload);
      client.publish(mqttTopics.mode(), modeMsg, true);
      
      current_mode = NONE;
      current_state = WAITING_FOR_USER_ID;
      memset(read_request_id, 0, sizeof(read_request_id));
      break;
    }
    
    default:
      Serial.println("Unknown or unhandled command type");
      break;
  }
}

void handleDisplay(const String &payload)
{
  // Legacy display handler - kept for backward compatibility
  // In the new protocol, display updates are handled internally based on device state
  Serial.println("Display command received (legacy):");
  Serial.println(payload);
  
  // For now, just log it - can be extended if needed for debugging
}

void handleData(const String &payload)
{
  // This function is now only called from AUTH_VERIFY to trigger authentication
  // The payload parameter is ignored - we use auth_state which was populated by AUTH_VERIFY handler

  switch (current_mode)
  {
  case NONE:
    Serial.println("No Mode");
    break;
    
  case AUTHENTICATE:
    Serial.println("Authenticate Mode");
    
    if (current_state == WAITING_FOR_USER_BUFFER)
    {
      unsigned char key[enc_key_length] = {0};

      // Convert tag UID to colon-separated hex string
      char tagUidHex[MAX_TAG_UID_LENGTH + 1];
      snprintf(tagUidHex, sizeof(tagUidHex), "%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X",
               auth_state.tag_uid_binary[0], auth_state.tag_uid_binary[1], 
               auth_state.tag_uid_binary[2], auth_state.tag_uid_binary[3],
               auth_state.tag_uid_binary[4], auth_state.tag_uid_binary[5], 
               auth_state.tag_uid_binary[6], auth_state.tag_uid_binary[7]);

      // Pass the tag UID string as user_buffer (to match what was used during registration)
      if (authenticate_user(auth_state.tag_uid_binary, tagUidHex, &last_card, key))
      {
        // Authentication successful
        aes128.setKey(key, enc_key_length);
        unsigned char encr_data[16] = {0};
        aes128.encryptBlock(encr_data, auth_state.encryption_data);
        
        // Build AUTH_SUCCESS event
        AuthSuccessPayload authPayload;
        strlcpy(authPayload.tag_uid, tagUidHex, sizeof(authPayload.tag_uid));
        authPayload.authenticated = true;
        strlcpy(authPayload.message, "Authentication successful", sizeof(authPayload.message));
        
        // Echo back the user_data from the verify request
        strlcpy(authPayload.user_data.username, auth_state.username, sizeof(authPayload.user_data.username));
        strlcpy(authPayload.user_data.context, auth_state.context, sizeof(authPayload.user_data.context));
        
        const char* authMsg = mqttBuilder.buildAuthSuccess(auth_state.request_id, authPayload);
        client.publish(mqttTopics.authSuccess(), authMsg);
        
        display_success();
        delay(1000);
      }
      else
      {
        // Authentication failed
        AuthFailedPayload failedPayload;
        strlcpy(failedPayload.tag_uid, tagUidHex, sizeof(failedPayload.tag_uid));
        failedPayload.authenticated = false;
        strlcpy(failedPayload.reason, "Invalid credentials or key mismatch", sizeof(failedPayload.reason));
        
        const char* failedMsg = mqttBuilder.buildAuthFailed(auth_state.request_id, failedPayload);
        client.publish(mqttTopics.authFailed(), failedMsg);
        
        display_fail();
        delay(1000);
      }

      // Send mode change back to idle
      ModeChangePayload modePayload;
      modePayload.mode = DeviceMode::IDLE;
      modePayload.previous_mode = DeviceMode::AUTH;
      const char* modeMsg = mqttBuilder.buildModeChange(auth_state.request_id, modePayload);
      client.publish(mqttTopics.mode(), modeMsg, true);

      clear_kCard(&last_card);
      current_state = WAITING_FOR_USER_ID;
      current_mode = NONE;
      
      // Clear auth state for next operation
      clearAuthState();
    }
    break;

  case REGISTER:
    // Registration is handled directly in loop() when card is detected
    Serial.println("Register Mode - waiting for card");
    break;
    
  default:
    Serial.println("Unknown mode");
  }
}

bool containsOnlyZeroes(const String &str)
{
  for (size_t i = 0; i < str.length(); ++i)
  {
    if (str[i] != '0')
    {
      return false;
    }
  }
  return true;
}

void load_flash()
{
  mqtt_data.url = preferences.getString("mqtturl", "");
  mqtt_data.usr = preferences.getString("mqttusr", "");
  mqtt_data.pw = preferences.getString("mqttpw", "");
  mqtt_data.id = preferences.getString("mqttid", "");
  clientID = preferences.getString("mqttid", "");
  mqtt_data.SSID = preferences.getString("mqttssid", "");
  mqtt_data.KEY = preferences.getString("mqttkey", "");
  mqtt_data.port = preferences.getString("mqttport", "1883").toInt();

  Serial.println(mqtt_data.url);
  Serial.println(mqtt_data.usr);
  Serial.println(mqtt_data.pw);
  Serial.println(mqtt_data.id);
  Serial.println(mqtt_data.KEY);
  Serial.println(mqtt_data.SSID);
  Serial.println(mqtt_data.port);
}