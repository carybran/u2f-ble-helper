//U2F helper functions
var U2F_HEADER_BYTES = 7;


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
function buildU2FRegisterCommand(enrollInfo){
  var registerCommandHex = "83"

  //challenge parameter
  var challengeB64 = enrollInfo.enrollChallenges[0].challengeHash;//base64FromURLSafe(enrollInfo.enrollChallenges[0].challengeHash);
  var cryptoChallenge = CryptoJS.SHA256(challengeB64);
  var hashChallengeHex = cryptoChallenge.toString(CryptoJS.enc.Hex);

  var appB64 = enrollInfo.enrollChallenges[0].appIdHash;//base64FromURLSafe(enrollInfo.enrollChallenges[0].appIdHash);
  var cryptoApp = CryptoJS.SHA256(appB64);
  var hashAppHex = cryptoApp.toString(CryptoJS.enc.Hex);

  console.log("got challenge: " + hashChallengeHex);
  console.log("got app: " + hashAppHex);

   var lenU2F = (hashAppHex.length/2) + (hashChallengeHex.length/2);
   var lenU2FHex = lenU2F.toString(16);
   if(lenU2F < 256){
     lenU2FHex = "0000" + ( lenU2F > 15 ? lenU2FHex : "0" + lenU2FHex);
   }
   else if(lenU2F > 255 && lenU2F < 65536){
     lenU2FHex = "00" + ( lenU2F > 4095 ? lenU2FHex : "0" + lenU2FHex);
   }
   else{
     lenU2FHex =( lenU2F > 1048575 ? lenU2FHex : "0" + lenU2FHex);
   }

   var lenData = lenU2F + U2F_HEADER_BYTES;
   var lenDataHex = lenData.toString(16);
   if(lenData <  256){
     lenDataHex = "00" + ( lenData > 15 ? lenDataHex : "0" + lenDataHex);
   }
   else if(lenData > 255){
     lenDataHex = ( lenU2F > 4095 ? lenDataHex : "0" + lenDataHex);
   }

  var messageHex = "83" + lenDataHex + "00010300" + lenU2FHex + hashChallengeHex + hashAppHex;

  return packHexToBinary(messageHex);


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

function base64FromURLSafe(webSafeB64){
  var b64 = "";
  for(var i = 0; i < webSafeB64.length; i++){
    var c = webSafeB64.charAt(i);
    switch(c){
      case '+':
        b64 += '-';
        break;
      case '/':
        b64 += '_';
        break;
      case '=':
        b64 += '*';
        break;
      default:
        b64 += c;
        break;
    }
  }
  return b64;
}