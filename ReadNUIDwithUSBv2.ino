/* Typical pin layout used:
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 */

#include <SPI.h>
#include <MFRC522.h>
#include <SoftwareSerial.h>
#include <Wire.h>
#include "RTClib.h"

SoftwareSerial USB(5, 6);
byte computerByte;  //used to store data coming from the computer
byte USB_Byte;      //used to store data coming from the USB stick
int timeOut = 2000; //wait 2sec for response from the CH376S

#define SS_PIN 10
#define RST_PIN 9
const int redLED = 3;
const int greenLED = 4;
const int buzzerPin = 2;

MFRC522 rfid(SS_PIN, RST_PIN); // Instance of the class

MFRC522::MIFARE_Key key;

// Init array that will store new NUID
byte nuidPICC[4];

RTC_DS1307 rtc;
DateTime now;

String fileName;
String cDate;
String cTime;

void setup()
{

  Serial.begin(9600);

  pinMode(greenLED, OUTPUT);  // Define digital pin 13 for LED
  pinMode(redLED, OUTPUT);    // Define digital pin 13 for LED
  pinMode(buzzerPin, OUTPUT); // Define digital pin 13 for LED

  digitalWrite(greenLED, LOW);  // Turn off the LED
  digitalWrite(redLED, LOW);    // Turn off the LED
  digitalWrite(buzzerPin, LOW); // Turn off the Buzzer

  while (!rtc.begin())
  {
    errorSignal();
  }

  while (!rtc.isrunning())
  {
    errorSignal();
    Serial.println("RTC is NOT running!");
    // following line sets the RTC to the date & time this sketch was compiled
    //     rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    // This line sets the RTC with an explicit date & time, for example to set
    // January 21, 2014 at 3am you would call:
    //     rtc.adjust(DateTime(2018, 11, 11, 22, 27, 0));
  }

  now = rtc.now();
  fileName = String(now.year()) + String(now.month()) + String(now.day()) + ".CSV";

  SPI.begin();     // Init SPI bus
  rfid.PCD_Init(); // Init MFRC522

  USB.begin(9600); // Setup communication with the CH376S module
  for (byte i = 0; i < 6; i++)
  {
    key.keyByte[i] = 0xFF;
  }

  while (!checkConnection(0x01))
  {
    errorSignal();
    Serial.println("USB is NOT CONNECTED!");
  }

  Serial.println(F("This code scan the MIFARE Classsic NUID."));
  Serial.print(F("Using the following key:"));
  printHex(key.keyByte, MFRC522::MF_KEY_SIZE);

  pinMode(redLED, OUTPUT);
  pinMode(greenLED, OUTPUT);
  set_USB_Mode(0x06);
  if (checkConnection(0x01) && !isFileExists())
  {
    Serial.println(">Connection to CH376S was successful.");
    Serial.println("rfid_tag,date_time_stamp");
    writeFile(fileName, "rfid_tag,date_time_stamp");
  }

  blinkLED();
}

void loop()
{
  while (!checkConnection(0x01))
  {
    errorSignal();
    Serial.println("USB is NOT CONNECTED!");
  }

  while (!rtc.isrunning())
  {
    errorSignal();
    Serial.println("RTC is NOT running!");
    // following line sets the RTC to the date & time this sketch was compiled
    //     rtc.adjust(DateTime(F(__DATE__), F(__TIME__)));
    // This line sets the RTC with an explicit date & time, for example to set
    // January 21, 2014 at 3am you would call:
    //     rtc.adjust(DateTime(2018, 11, 11, 22, 27, 0));
  }

  now = rtc.now();
  fileName = String(now.year()) + String(now.month()) + String(now.day()) + ".CSV";
  cDate = String(now.year()) + "-" + String(now.month()) + "-" + String(now.day());
  cTime = String(now.hour()) + ":" + String(now.minute()) + ":" + String(now.second());

  // Look for new cards
  if (!rfid.PICC_IsNewCardPresent())
    return;

  // Verify if the NUID has been readed
  if (!rfid.PICC_ReadCardSerial())
    return;

  Serial.print(F("PICC type: "));
  MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
  Serial.println(rfid.PICC_GetTypeName(piccType));

  // Check is the PICC of Classic MIFARE type
  if (piccType != MFRC522::PICC_TYPE_MIFARE_MINI &&
      piccType != MFRC522::PICC_TYPE_MIFARE_1K &&
      piccType != MFRC522::PICC_TYPE_MIFARE_4K)
  {
    Serial.println(F("Your tag is not of type MIFARE Classic."));
    return;
  }

  if (rfid.uid.uidByte[0] != nuidPICC[0] ||
      rfid.uid.uidByte[1] != nuidPICC[1] ||
      rfid.uid.uidByte[2] != nuidPICC[2] ||
      rfid.uid.uidByte[3] != nuidPICC[3])
  {
    Serial.println(F("A new card has been detected."));

    // Store NUID into nuidPICC array
    for (byte i = 0; i < 4; i++)
    {
      nuidPICC[i] = rfid.uid.uidByte[i];
    }

    Serial.println(F("The NUID tag is:"));
    Serial.print(F("In hex: "));
    printHex(rfid.uid.uidByte, rfid.uid.size);
    Serial.println();
    Serial.print(F("In dec: "));
    blinkLED();
    printDec(rfid.uid.uidByte, rfid.uid.size);
    Serial.println();
  }
  else
  {
    Serial.println(F("Card read previously."));
    errorSignal();
  }

  // Halt PICC
  rfid.PICC_HaltA();

  // Stop encryption on PCD
  rfid.PCD_StopCrypto1();
}

/**
 * Helper routine to dump a byte array as hex values to Serial. 
 */
void printHex(byte *buffer, byte bufferSize)
{
  for (byte i = 0; i < bufferSize; i++)
  {
    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    Serial.print(buffer[i], HEX);
  }
}

/**
 * Helper routine to dump a byte array as dec values to Serial.
 */
void printDec(byte *buffer, byte bufferSize)
{

  String rfidTag = "";
  for (byte i = 0; i < bufferSize; i++)
  {
    //    Serial.print(buffer[i] < 0x10 ? " 0" : " ");
    rfidTag += buffer[i];
  }
  Serial.print(rfidTag + "," + cDate + " " + cTime);
  appendFile(fileName,"\n" +  rfidTag + "," + cDate + " " + cTime  );
  
}

//checkConnection==================================================================================
//This function is used to check for successful communication with the CH376S module. This is not dependant of the presence of a USB stick.
//Send any value between 0 to 255, and the CH376S module will return a number = 255 - value.
boolean checkConnection(byte value)
{
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x06);
  USB.write(value);

  if (waitForResponse("checking connection"))
  { //wait for a response from the CH376S. If CH376S responds, it will be true. If it times out, it will be false.
    if (getResponseFromUSB() == (255 - value))
    {
      // blinkLED(); //blink the LED for 1 second if the connection was successful
      return true;
    }
    else
    {
      Serial.print(">Connection to CH376S - FAILED.");
      return false;
    }
  }
}

//set_USB_Mode=====================================================================================
//Make sure that the USB is inserted when using 0x06 as the value in this specific code sequence
void set_USB_Mode(byte value)
{
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x15);
  USB.write(value);

  delay(20);

  if (USB.available())
  {
    USB_Byte = USB.read();
    //Check to see if the command has been successfully transmitted and acknowledged.
    if (USB_Byte == 0x51)
    {                                                      // If true - the CH376S has acknowledged the command.
      Serial.println("set_USB_Mode command acknowledged"); //The CH376S will now check and monitor the USB port
      USB_Byte = USB.read();

      //Check to see if the USB stick is connected or not.
      if (USB_Byte == 0x15)
      { // If true - there is a USB stick connected
        Serial.println("USB is present");
        // blinkLED(); // If the process was successful, then turn the LED on for 1 second
      }
      else
      {
        Serial.print("USB Not present. Error code:"); // If the USB is not connected - it should return an Error code = FFH
        Serial.print(USB_Byte, HEX);
        Serial.println("H");
      }
    }
    else
    {
      Serial.print("CH3765 error!   Error code:");
      Serial.print(USB_Byte, HEX);
      Serial.println("H");
    }
  }
  delay(20);
}

//resetALL=========================================================================================
//This will perform a hardware reset of the CH376S module - which usually takes about 35 msecs =====
void resetALL()
{
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x05);
  Serial.println("The CH376S module has been reset !");
  delay(200);
}

//setFileName======================================================================================
//This sets the name of the file to work with
void setFileName(String fileName)
{
  Serial.print("Setting filename to:");
  Serial.println(fileName);
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x2F);
  USB.write(0x2F);       // Every filename must have this byte to indicate the start of the file name.
  USB.print(fileName);   // "fileName" is a variable that holds the name of the file.  eg. TEST.TXT
  USB.write((byte)0x00); // you need to cast as a byte - otherwise it will not compile.  The null byte indicates the end of the file name.
  delay(20);
}

//diskConnectionStatus================================================================================
//Check the disk connection status
void diskConnectionStatus()
{
  Serial.println("Checking USB disk connection status");
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x30);

  if (waitForResponse("Connecting to USB disk"))
  { //wait for a response from the CH376S. If CH376S responds, it will be true. If it times out, it will be false.
    if (getResponseFromUSB() == 0x14)
    { //CH376S will send 0x14 if this command was successful
      Serial.println(">Connection to USB OK");
    }
    else
    {
      Serial.print(">Connection to USB - FAILED.");
    }
  }
}

//USBdiskMount========================================================================================
//initialise the USB disk and check that it is ready - this process is required if you want to find the manufacturing information of the USB disk
void USBdiskMount()
{
  Serial.println("Mounting USB disk");
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x31);

  if (waitForResponse("mounting USB disk"))
  { //wait for a response from the CH376S. If CH376S responds, it will be true. If it times out, it will be false.
    if (getResponseFromUSB() == 0x14)
    { //CH376S will send 0x14 if this command was successful
      Serial.println(">USB Mounted - OK");
    }
    else
    {
      Serial.print(">Failed to Mount USB disk.");
    }
  }
}

boolean isFileExists()
{
  setFileName(fileName);
  Serial.println("Opening file.");
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x32);
  if (waitForResponse("file Open"))
  { //wait for a response from the CH376S. If CH376S responds, it will be true. If it times out, it will be false.
    if (getResponseFromUSB() == 0x14)
    { //CH376S will send 0x14 if this command was successful
      return true;
    }
    else
    {
      return false;
    }
  }
}

//fileOpen========================================================================================
//opens the file for reading or writing
void fileOpen()
{
  Serial.println("Opening file.");
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x32);
  if (waitForResponse("file Open"))
  { //wait for a response from the CH376S. If CH376S responds, it will be true. If it times out, it will be false.
    if (getResponseFromUSB() == 0x14)
    { //CH376S will send 0x14 if this command was successful
      Serial.println(">File opened successfully.");
    }
    else
    {
      Serial.print(">Failed to open file.");
    }
  }
}

//writeFile========================================================================================
//is used to create a new file and then write data to that file. "fileName" is a variable used to hold the name of the file (e.g TEST.TXT). "data" should not be greater than 255 bytes long.
void writeFile(String fileName, String data)
{
  resetALL();             //Reset the module
  set_USB_Mode(0x06);     //Set to USB Mode
  diskConnectionStatus(); //Check that communication with the USB device is possible
  USBdiskMount();         //Prepare the USB for reading/writing - you need to mount the USB disk for proper read/write operations.
  setFileName(fileName);  //Set File name
  if (fileCreate())
  {                  //Try to create a new file. If file creation is successful
    fileWrite(data); //write data to the file.
  }
  else
  {
    Serial.println("File could not be created, or it already exists");
  }
  fileClose(0x01);
}

//appendFile()====================================================================================
//is used to write data to the end of the file, without erasing the contents of the file.
void appendFile(String fileName, String data)
{
  resetALL();             //Reset the module
  set_USB_Mode(0x06);     //Set to USB Mode
  diskConnectionStatus(); //Check that communication with the USB device is possible
  USBdiskMount();         //Prepare the USB for reading/writing - you need to mount the USB disk for proper read/write operations.
  setFileName(fileName);  //Set File name
  fileOpen();             //Open the file
  filePointer(false);     //filePointer(false) is to set the pointer at the end of the file.  filePointer(true) will set the pointer to the beginning.
  fileWrite(data);        //Write data to the end of the file
  fileClose(0x01);        //Close the file using 0x01 - which means to update the size of the file on close.
}

//filePointer========================================================================================
//is used to set the file pointer position. true for beginning of file, false for the end of the file.
void filePointer(boolean fileBeginning)
{
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x39);
  if (fileBeginning)
  {
    USB.write((byte)0x00); //beginning of file
    USB.write((byte)0x00);
    USB.write((byte)0x00);
    USB.write((byte)0x00);
  }
  else
  {
    USB.write((byte)0xFF); //end of file
    USB.write((byte)0xFF);
    USB.write((byte)0xFF);
    USB.write((byte)0xFF);
  }
  if (waitForResponse("setting file pointer"))
  { //wait for a response from the CH376S.
    if (getResponseFromUSB() == 0x14)
    { //CH376S will send 0x14 if this command was successful
      Serial.println("Pointer successfully applied");
    }
  }
}

//fileWrite=======================================================================================
//are the commands used to write to the file
void fileWrite(String data)
{
  Serial.println("Writing to file:");
  byte dataLength = (byte)data.length(); // This variable holds the length of the data to be written (in bytes)
  Serial.println(data);
  Serial.print("Data Length:");
  Serial.println(dataLength);
  delay(100);
  // This set of commands tells the CH376S module how many bytes to expect from the Arduino.  (defined by the "dataLength" variable)
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x3C);
  USB.write((byte)dataLength);
  USB.write((byte)0x00);
  if (waitForResponse("setting data Length"))
  { // Wait for an acknowledgement from the CH376S module before trying to send data to it
    if (getResponseFromUSB() == 0x1E)
    { // 0x1E indicates that the USB device is in write mode.
      USB.write(0x57);
      USB.write(0xAB);
      USB.write(0x2D);
      USB.print(data); // write the data to the file

      if (waitForResponse("writing data to file"))
      { // wait for an acknowledgement from the CH376S module
      }
      Serial.print("Write code (normally FF and 14): ");
      Serial.print(USB.read(), HEX); // code is normally 0xFF
      Serial.print(",");
      USB.write(0x57);
      USB.write(0xAB);
      USB.write(0x3D); // This is used to update the file size. Not sure if this is necessary for successful writing.
      if (waitForResponse("updating file size"))
      { // wait for an acknowledgement from the CH376S module
      }
      Serial.println(USB.read(), HEX); //code is normally 0x14
    }
  }
}

//fileCreate()========================================================================================
//the command sequence to create a file
boolean fileCreate()
{
  boolean createdFile = false;
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x34);
  //TODO Check file exist or not
  if (waitForResponse("creating file"))
  { //wait for a response from the CH376S. If file has been created successfully, it will return true.
    if (getResponseFromUSB() == 0x14)
    { //CH376S will send 0x14 if this command was successful
      createdFile = true;
    }
  }
  return (createdFile);
}
//fileClose=======================================================================================
//closes the file
void fileClose(byte closeCmd)
{
  Serial.println("Closing file:");
  USB.write(0x57);
  USB.write(0xAB);
  USB.write(0x36);
  USB.write((byte)closeCmd); // closeCmd = 0x00 = close without updating file Size, 0x01 = close and update file Size

  if (waitForResponse("closing file"))
  { // wait for a response from the CH376S.
    byte resp = getResponseFromUSB();
    if (resp == 0x14)
    { // CH376S will send 0x14 if this command was successful
      Serial.println(">File closed successfully.");
    }
    else
    {
      Serial.print(">Failed to close file. Error code:");
      Serial.println(resp, HEX);
    }
  }
}

//waitForResponse===================================================================================
//is used to wait for a response from USB. Returns true when bytes become available, false if it times out.
boolean waitForResponse(String errorMsg)
{
  boolean bytesAvailable = true;
  int counter = 0;
  while (!USB.available())
  { //wait for CH376S to verify command
    delay(1);
    counter++;
    if (counter > timeOut)
    {
      Serial.print("TimeOut waiting for response: Error while: ");
      Serial.println(errorMsg);
      bytesAvailable = false;
      break;
    }
  }
  delay(1);
  return (bytesAvailable);
}

//getResponseFromUSB================================================================================
//is used to get any error codes or messages from the CH376S module (in response to certain commands)
byte getResponseFromUSB()
{
  byte response = byte(0x00);
  if (USB.available())
  {
    response = USB.read();
  }
  return (response);
}

//blinkLED==========================================================================================
//Turn an LED on for 1 second
void blinkLED()
{
  digitalWrite(greenLED, HIGH);
  digitalWrite(buzzerPin, HIGH);
  delay(1000);
  digitalWrite(greenLED, LOW);
  digitalWrite(buzzerPin, LOW);
}

void errorSignal()
{
  digitalWrite(redLED, HIGH);
  digitalWrite(buzzerPin, HIGH);
  delay(100);
  digitalWrite(redLED, LOW);
  digitalWrite(buzzerPin, LOW);
  delay(100);
}
