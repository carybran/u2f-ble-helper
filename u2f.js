//U2F helper functions
var U2F_HEADER_BYTES = 7;
var U2F_KEYHANDLE_BYTE_LENGTH = 1;


var U2F_BLE_PING = 0x81;
var U2F_BLE_MSG = 0x83;
var U2F_BLE_ERROR = 0xbf;

var U2F_ENROLL_COMMAND = 0x01;
var U2F_AUTHENTICATE_COMMAND = 0x02;

var U2F_REQUIRE_PHYSICAL_PRESENCE = 0x03;



/**
 * Enroll helper request comes in from U2F extension as
 *
 * {
     "type":"enroll_request_type",
     "enrollChallenges":[
       {
         "appIdHash": websafe-b64,
         "challengeHash": websafe-b64,
         "version": ""
       }
     ],
     "signData":[
       {
         "keyHandle": websafe-b64,
         "appIdHash": websafe-b64,
         "challengeHash": websafe-b64,
         "version": ""
       }
     ],
     "timeoutSeconds":
   }
 *
 *
 * */
function createEnrollCommand(enrollInfo){
  var hashChallenge = B64_decode(enrollInfo.enrollChallenges[0].challengeHash); 
  var hashApp = B64_decode(enrollInfo.enrollChallenges[0].appIdHash);
  
  var lenU2F = hashChallenge.length + hashApp.length;
  var lenData = lenU2F + U2F_HEADER_BYTES;
  var msgLengthHi = (lenData & 0XFF00) >> 8;
  var msgLengthLow = (lenData & 0x00FF);
  
  //calculate the enroll request length
  var enrollLengthHi = (lenU2F & 0XFF00) >> 8;
  var enrollLengthLow = (lenU2F & 0x00FF);
  
  //build up the message to send to the BLE U2F authenticator
  var apdu = new Uint8Array([U2F_BLE_MSG, msgLengthHi, msgLengthLow, 0x00, U2F_ENROLL_COMMAND, U2F_REQUIRE_PHYSICAL_PRESENCE, 0x00, 0x00, enrollLengthHi, enrollLengthLow]);
  var u8 = new Uint8Array(apdu.length +  hashChallenge.length + hashApp.length);
  u8.set(apdu);
  u8.set(hashChallenge, apdu.length);
  u8.set(hashApp, apdu.length + hashChallenge.length);
  return u8.buffer;
}

/**
 * Sign helper request coming in looks like this
 * 
 * var sign_helper_request = {
  "type": "sign_helper_request",
  "timeoutSeconds": float
  "signData": [
    {
      "version": undefined || "U2F_V1" || "U2F_V2",
      "appIdHash": websafe-b64
      "challengeHash": websafe-b64
      "keyHandle": websafe-b64
    }+
  ],
 };
*/
function createSignCommand(signInfo){
  var hashChallenge = B64_decode(signInfo.signData[0].challengeHash); 
  var hashApp = B64_decode(signInfo.signData[0].appIdHash);
  var hashHandle = B64_decode(signInfo.signData[0].keyHandle);
  
  var lenU2F = hashChallenge.length + hashApp.length + hashHandle.length;
  var lenData = lenU2F + U2F_HEADER_BYTES;
  var msgLengthHi = (lenData & 0XFF00) >> 8;
  var msgLengthLow = (lenData & 0x00FF);
  
  //calculate the authentication message length
  var authLengthHi = (lenU2F & 0XFF00) >> 8;
  var authLengthLow = (lenU2F & 0x00FF);
  
  var keyHandleLength = hashHandle.length;
  
  //build up the message to send to the BLE U2F authenticator
  var apdu = new Uint8Array([U2F_BLE_MSG, msgLengthHi, msgLengthLow, 0x00, U2F_AUTHENTICATE_COMMAND, U2F_REQUIRE_PHYSICAL_PRESENCE, 0x00, 0x00, authLengthHi, authLengthLow]);
  var u8 = new Uint8Array(apdu.length +  hashChallenge.length + hashApp.length + U2F_KEYHANDLE_BYTE_LENGTH + hashHandle.length);
  u8.set(apdu);
  u8.set(hashChallenge, apdu.length);
  u8.set(hashApp, apdu.length + hashChallenge.length);
  u8[apdu.length + hashChallenge.length + hashApp.length] = keyHandleLength;
  u8.set(hashHandle, apdu.length + hashChallenge.length + hashApp.length + U2F_KEYHANDLE_BYTE_LENGTH);
  return u8.buffer;
  
  
}

 //takes a hex string and for each character this
  //method will parse the integer value and packs it into a uint8 byte array
function packHexToBinary(hexString){
    if (!hexString || hexString == "") {
          throw "Error parsing hexidecimal string to binary array";
    }
    var buffer = new ArrayBuffer(hexString.length/2);
    var data_view = new Uint8Array(buffer);
    var nibbles = "U2F Message Nibbles:";
    var index = 0;
    for (var i = 0; i < hexString.length; i+=2) {
        var sub = hexString.charAt(i) + hexString.charAt(i+1);
        nibbles += (" " + sub)
        var b = parseInt(sub, 16);
        data_view[index++] = b;
    }
    console.log(nibbles);
    return buffer;
}

  //this function unpacks the byte array into a series of hex values
function unPackBinaryToHex(byteArray){
      if (!byteArray) {
            throw "invalid byte array passed";
      }
      var data_view = new Uint8Array(byteArray);
      var hexString = "";
      for(var i = 0; i < data_view.length; i++){
           var hexVal = data_view[i].toString(16);
           if (hexVal.length == 1) {
            //if the hex return only takes up 4-bits, pad the value to include the leading 0
            //so all 8 bits are represented
            hexVal = "0" + hexVal;
           }
           hexString += hexVal;
      }
      return hexString;
  }
