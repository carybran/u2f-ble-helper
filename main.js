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
var messageBits = 0;
var messageFromDevice;

var helperResponse;

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

chrome.bluetoothLowEnergy.onCharacteristicValueChanged.addListener(function(characteristic){
    //console.log("value changed on characteristic " + characteristic.instanceId);
    if(characteristic.uuid != U2F_STATUS_ID || !characteristic.value){
      return;
    }
    console.log("U2F status characteristic changed");
    var data_view = new Uint8Array(characteristic.value);
    var msg_view;
    if(MESSAGE_STATE == MESSAGE_STATE_IDLE && data_view[0] == U2F_MESSAGE_TYPE){
      //first message that comes in from the status will contain the 
      //length of the message - will use the size to allocate the 
      //ArrayBuffer to populate with the entire message
      messageBits = data_view[1] << 8;
      messageBits += (data_view[2] & 0xFF);
      messageFromDevice = new ArrayBuffer(messageBits);
      msg_view= new Uint8Array(messageFromDevice);
      msg_view.set(data_view.subarray(3));
      bitIndex = data_view.length - 3;
      MESSAGE_STATE = MESSAGE_STATE_WAITING_FOR_BITS;
      console.log("U2F message received: length " + messageBits + " next bits index = " + bitIndex);
      
    }
    else if(MESSAGE_STATE == MESSAGE_STATE_WAITING_FOR_BITS){
      msg_view = new Uint8Array(messageFromDevice);
      msg_view.set(data_view, bitIndex);
      bitIndex += data_view.length;
      if(bitIndex == msg_view.length){
        console.log("U2F message has been completely received");
        MESSAGE_STATE = MESSAGE_STATE_IDLE;
        sendResponseToHelper();
      }
    }
 });
 
 function sendResponseToHelper(){
   var data = unPackBinaryToHex(messageFromDevice);
   if(U2F_STATE == U2F_STATE_ENROLL){
     var enroll_helper_reply = {
       "type":"enroll_helper_reply",
       "code":0,
       "version":"U2F_V2",
       "enrollData": data
     };
     console.log("sending enroll response back to chrome extension");
     if(helperResponse){
       helperResponse(enroll_helper_reply);
       helperResponse = null;
       messageFromDevice = null;
       U2F_STATE = U2F_STATE_IDLE;
     }
   }
    

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
      U2F_STATE = U2F_STATE_ENROLL;
      sendEnrollRequest(request, sendResponse);
    }
    else if(request.type == HELPER_SIGN_MSG_TYPE){
      U2F_STATE = U2F_STATE_SIGN;
      sendSignRequest(request, sendResponse);
    }
    else{
      console.log("unknown request type sent by FIDO extension");
    }
    
    //returning true will allow for the asynchronous calling of the sendResponse function
    return true;
});

function sendMessageToAuthenticator(message){
  console.log("writing message to U2F control chacteristic");
  if(message.byteLength <= MAX_CHARACTERISTIC_LENGTH){
    chrome.bluetoothLowEnergy.writeCharacteristicValue(u2fControl.instanceId, message, function(){
      console.log('message sent!');
    })
  }
}


function sendEnrollRequest(request, sendResponse){

    var registerMessage = buildU2FRegisterCommand(request);
    console.log("sending enroll request");
    sendMessageToAuthenticator(registerMessage);
    helperResponse = sendResponse;


}

function sendSignRequest(request, sendResponse){
    console.log("sending sign request")
}


init();