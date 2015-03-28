//FIDO Bluetooth UUIDs
var FIDO_U2F_SERVICE_UUID = "f1d0fff0-deaa-ecee-b42f-c9ba7ed623bb";
var U2F_CONTROL_POINT_ID  = "f1d0fff1-deaa-ecee-b42f-c9ba7ed623bb";
var U2F_STATUS_ID  = "f1d0fff2-deaa-ecee-b42f-c9ba7ed623bb";
var CHARACTERISTIC_UPDATE_NOTIFICATION_DESCRIPTOR_UUID = "00002902-0000-1000-8000-00805f9b34fb";

var MAX_CHARACTERISTIC_LENGTH = 80;
var U2F_MESSAGE_TYPE = 0x83;

var ENABLE_NOTIFICATIONS = new ArrayBuffer(2);
var en_view = new Uint8Array(ENABLE_NOTIFICATIONS);
en_view[0] = 1;
en_view[1] = 0;


var HELPER_ENROLL_MSG_TYPE = "enroll_helper_request";
var HELPER_SIGN_MSG_TYPE = "sign_helper_request";
var authenticator;
var u2fService;
var u2fStatus;
var u2fControl;


var U2F_STATE_IDLE = 0;
var U2F_STATE_ENROLL = 1;
var U2F_STATE_SIGN = 2;
var U2F_STATE = U2F_STATE_IDLE;

var MESSAGE_STATE_WAITING_FOR_BITS = 0;
var MESSAGE_STATE_IDLE = 1;
var MESSAGE_STATE = MESSAGE_STATE_IDLE;
var bitIndex = 0;
var messageFromDevice;

var helperResponse;

var enroll_helper_reply = {
 "type":"enroll_helper_reply",
 "code": null,
 "version":"U2F_V2",
 "enrollData": null
};
     
var sign_helper_reply = {
 "type": "sign_helper_reply",
 "code": 0,  
 "responseData": {
   "version": "U2F_V2",
   "appIdHash": null,
   "challengeHash": null,
   "keyHandle": null,
   "signatureData": null
  }
};

function init() {

  console.log("sending notification registration to FIDO U2F extension");
  chrome.runtime.sendMessage('pfboblefjcgdjicmnffhdgionmgcdmne', chrome.runtime.id);

  document.querySelector('#greeting').innerText =
    'Hello, World! It is ' + new Date();

  //if there are any connected authenticators find one
  chrome.bluetooth.getDevices(function(devices){
    for(var i = 0; i < devices.length; i++){
      var device = devices[i];
      //if check for connected U2F Authenticator
      if(!device.uuids || device.uuids.indexOf(FIDO_U2F_SERVICE_UUID) < 0 || !device.connected){
        continue;
      }
      //got one
      chrome.bluetoothLowEnergy.connect(device.address, function () {
        if (chrome.runtime.lastError) {
          console.log('Failed to connect: ' + chrome.runtime.lastError.message);
          return;
        }
        //connection established
        console.log("connected to FIDO U2F authenticator");
        authenticator = device;
        chrome.bluetoothLowEnergy.getServices(authenticator.address, function(services){
          for(var i = 0; i < services.length; i++){
            if (services[i].uuid == FIDO_U2F_SERVICE_UUID){
                initializeService(services[i]);
                break;
            }
          }
        });
      });
    }
  });
};

chrome.bluetooth.onDeviceChanged.addListener(
  function(device){
    if(!authenticator){
      return;
    }
    if((device.address == authenticator.address) && (device.connected === false)){
      console.log("authenticator has disconnected");
      authenticator = null;
      MESSAGE_STATE = MESSAGE_STATE_IDLE;
      U2F_STATE = U2F_STATE_IDLE;
      
    }
  });

chrome.bluetooth.onDeviceAdded.addListener(
  function(device){
    if (!device.uuids || device.uuids.indexOf(FIDO_U2F_SERVICE_UUID) < 0){
      return;
    }
    if(authenticator !== null){
      //return for now
      return;
    }
    console.log('found a FIDO U2F BLE authenticator - connecting!');

    chrome.bluetoothLowEnergy.connect(device.address, function () {
      if (chrome.runtime.lastError) {
        console.log('Failed to connect: ' + chrome.runtime.lastError.message);
        return;
      }
      //connection established
      console.log("connected to FIDO U2F authenticator");
      authenticator = device;
    });
});

var lastBytesRecieved = null;
chrome.bluetoothLowEnergy.onCharacteristicValueChanged.addListener(function(characteristic){
    //console.log("value changed on characteristic " + characteristic.instanceId);
    if(characteristic.uuid != U2F_STATUS_ID || !characteristic.value){
      return;
    }
    console.log("U2F status characteristic changed");
    var data_view = new Uint8Array(characteristic.value);
    
    if(lastBytesRecieved == unPackBinaryToHex(characteristic.value)){
      console.log("received duplicate packet from authenticator - ignoring");
      return;
    }
    lastBytesRecieved = unPackBinaryToHex(characteristic.value);
    console.log('Current packet received from authenticator:' + lastBytesRecieved);
    var msg_view;
    if(MESSAGE_STATE == MESSAGE_STATE_IDLE && data_view[0] == U2F_MESSAGE_TYPE){
      //first message that comes in from the status will contain the 
      //length of the message - will use the size to allocate the 
      //ArrayBuffer to populate with the entire message
      var messageBits = data_view[1] << 8;
      messageBits += (data_view[2] & 0xFF);
      if(messageBits == 2){
        console.log('Error from authenticator');
        messageFromDevice = new ArrayBuffer(messageBits);
        msg_view = new Uint8Array(messageFromDevice);
        msg_view.set(data_view.subarray(3));
        MESSAGE_STATE = MESSAGE_STATE_IDLE;
        sendResponseToHelper();
      }
      else{
        messageFromDevice = new ArrayBuffer(messageBits - 2); //remove the status word
        msg_view= new Uint8Array(messageFromDevice);
        msg_view.set(data_view.subarray(3));
        
        bitIndex = data_view.length - 3;
        MESSAGE_STATE = MESSAGE_STATE_WAITING_FOR_BITS;
        console.log("U2F message received: length " + messageBits + " next index = " + bitIndex);
      }
    }
    else if(MESSAGE_STATE == MESSAGE_STATE_WAITING_FOR_BITS){
      msg_view = new Uint8Array(messageFromDevice);
      console.log("U2F message fragment length = " + data_view.length  + " index = " + bitIndex + " message length = " + msg_view.length);
      //if((bitIndex + data_view.length - 2) == msg_view.length){
      if(msg_view.length <  MAX_CHARACTERISTIC_LENGTH -1){
        console.log("U2F message end - removing status word from message");
        msg_view.set(data_view.subarray(0, data_view.length-2), bitIndex);
        console.log("U2F message has been completely received");
        MESSAGE_STATE = MESSAGE_STATE_IDLE;
        sendResponseToHelper();
      }
      else{
        msg_view.set(data_view, bitIndex);
        bitIndex += data_view.length;
      }
    }
 });
 
 function sendResponseToHelper(){
   var data = unPackBinaryToHex(messageFromDevice);
   console.log("message data as hex : " + data);
   if(messageFromDevice.byteLength == 2){
     U2F_STATE = U2F_STATE_IDLE;
     console.log('going to process this error ' + data);
     return;
   }
   if(U2F_STATE == U2F_STATE_ENROLL){
     var b64 = B64_encode(new Uint8Array(messageFromDevice));
     console.log("base64 websaft enroll data " + b64);
     enroll_helper_reply.code = 0;
     enroll_helper_reply.enrollData = b64;
     console.log("sending enroll response back to chrome extension");
     if(helperResponse){
       helperResponse(enroll_helper_reply);
       helperResponse = null;
       messageFromDevice = null;
       U2F_STATE = U2F_STATE_IDLE;
     }
   }
   else if(U2F_STATE == U2F_STATE_SIGN){
     console.log('implement sign');
   }
    

 }
 
function sha256HashOfString(string) {
  var s = new SHA256();
  s.update(UTIL_StringToBytes(string));
  return s.digest();
}

function UTIL_StringToBytes(s, bytes) {
  bytes = bytes || new Array(s.length);
  for (var i = 0; i < s.length; ++i)
    bytes[i] = s.charCodeAt(i);
  return bytes;
}

function initializeService(service){
    if(service === null){
      console.log("u2f service disconnect");
      u2fService = null;
    }
    else{
      u2fService = service;
      chrome.bluetoothLowEnergy.getCharacteristics(u2fService.instanceId, function(characteristics){
        for(var i = 0; i < characteristics.length; i++){
          if(characteristics[i].uuid == U2F_STATUS_ID){
            u2fStatus = characteristics[i];
          }
          else if(characteristics[i].uuid == U2F_CONTROL_POINT_ID){
            u2fControl = characteristics[i];
          }
        }
        if(u2fStatus !== null){
         chrome.bluetoothLowEnergy.startCharacteristicNotifications(u2fStatus.instanceId, function(){
              if(chrome.runtime.lastError){
                console.log('failed to enable notifications for u2f status characteristic: ' + chrome.runtime.lastError.message);
                return;
              }
              console.log("notifications set up on u2f status characteristic");
            });
        }
      });
    }
  }

  chrome.bluetoothLowEnergy.onServiceAdded.addListener(function(service) {
    if (service.uuid == FIDO_U2F_SERVICE_UUID)
      initializeService(service);
  });

  chrome.bluetoothLowEnergy.onServiceRemoved.addListener(function(service) {
    if (service.uuid == FIDO_U2F_SERVICE_UUID)
      initializeService(null);
  });

chrome.runtime.onMessageExternal.addListener(
  function(request, sender, sendResponse) {
    console.log("got a message from the extenstion " + JSON.stringify(request));
    if(request.type == HELPER_ENROLL_MSG_TYPE){
      sendEnrollRequest(request, sendResponse);
    }
    else if(request.type == HELPER_SIGN_MSG_TYPE){
      sendSignRequest(request, sendResponse);
    }
    else{
      console.log("unknown request type sent by FIDO extension");
    }
    
    //returning true will allow for the asynchronous calling of the sendResponse function
    return true;
});



function sendMessageToAuthenticator(message){
  if(!message || message.byteLength === 0){
    return;
  }
  var data_view =  new Uint8Array(message);
  if(data_view.length < MAX_CHARACTERISTIC_LENGTH){
    console.log("Writing message to U2F control chacteristic  - length = " + message.byteLength);
    chrome.bluetoothLowEnergy.writeCharacteristicValue(u2fControl.instanceId, message, function(){
      console.log('Complete message to authenticator has been sent!');
    });
  }
  else{
    console.log("Writing message to U2F control chacteristic  - length = " + message.byteLength);
    var messageSegment = message.slice(0, MAX_CHARACTERISTIC_LENGTH - 1);
    chrome.bluetoothLowEnergy.writeCharacteristicValue(u2fControl.instanceId, messageSegment, function(){
      if(chrome.runtime.lastError){
           console.log('Failed to write to characteristic: ' + chrome.runtime.lastError.message);
           return;
      }
      sendMessageToAuthenticator(message.slice(MAX_CHARACTERISTIC_LENGTH - 1));
    });
  }
}

function continueMessageSend(message){
  console.log("segment written to characteristic: continuing write with " + message.byteLength + " bytes left");
  sendMessageToAuthenticator(message);
}

function sendEnrollRequest(request, sendResponse){
    console.log("sending enroll request");
    U2F_STATE = U2F_STATE_ENROLL;
    var enrollMessage = createEnrollCommand(request);
    sendMessageToAuthenticator(enrollMessage);
    helperResponse = sendResponse;
}

function sendSignRequest(request, sendResponse){
    console.log("sending sign request");
    if(request.signData.length > 1){
      console.log('Batch authentication request not implemented yet');
      return;
    }
    U2F_STATE = U2F_STATE_SIGN;
    sign_helper_reply.responseData.appIdHash = request.signData[0].appIdHash;
    sign_helper_reply.responseData.challengeHash = request.signData[0].challengeHash;
    sign_helper_reply.responseData.keyHandle =  request.signData[0].keyHandle;
    var signMessage = createSignCommand(request);
    sendMessageToAuthenticator(signMessage);
    helperResponse = sendResponse;
}


init();