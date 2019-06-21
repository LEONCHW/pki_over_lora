# **【 eWBM's MS500 MCU 】**
- Secure MCU with high performing hardware crypto engines 
- Secure boot and secure storage mechanism built-in
- True Random Number Generator (TRNG) for key generation

# **【 What is PKI over LoRa? 】**
- Propose a mechanism to place a section key using PKI-based real-time key exchange and device authentication mechanism as a solution to solve problems that may arise from PSK (pre-shared key) scheme currently used by LoRaWAN.

## Advantage
   - No Extra procedure before deployment
      - Follow the regular procedure of PSK (pre-share key) mechanism
   - No human involvement during new key generation procedure
      - It’s based on PKI (public Key Infrastructure)
      - After first key exchange, the root key is stored encrypted inside secure MCU     

## Key Provisioning in 3 Steps
   - Step 1 - Join Request (Over-the-Air Activation)
      - Initial Join Procedure - connection with the network server
      
   - Step2 – Key exchange between Device and Join server
      - Join server and the device perform ECDH (Elliptic Curve Diffie-Hellman) 
      - Both Join server and device generate a new AppKey from the shared secret 
      - Join server send the new AppKey to network server
      - Device set up the root key with the new Appkey
      - Reset the device and set the device to send rejoin request with the new AppKey
      
   - Step 3 – Rejoin Request
      - Join request with the new AppKey


# **【 Supported Operating Environment 】**
## Windows
   - Windows 10
   
## Linux & BSD
   - ***TBD***


# **【 Features 】**
## Device authentication 
   - Authenticate between devices and servers using the ECDSA mechanism
   
## Realtime new key provisioning 
   - Makes a real-time secret keys between devices and servers using the ECDH mechanism

# **【 Related Crypto Libraries 】**
   - OpenSSL-1.1.Of-vs2017

 # **【 Requirements 】**
 |   CID    |     Command     |   Device     |   Server     |                    Description                               |
 |----------|-----------------|--------------|--------------|--------------------------------------------------------------|
 |0x01      | PubKeyReq       |     X        |              | The device requests the public key to Server                 |
 |0x02      | PubKeyAns       |              |      X       | Send the Public key in regards to the PubkeyReq response     |
 |0x03      | SigVerifyReq    |     X        |              | The device sends the signature data(48byte) request the authentication from Server            |
 |0x04      | SigVerifyAns    |              |     X        | Sends the result in regard to the device authentication (CID + Result - 2byte |
 |0x05      | KeyChangeReq |  X  |  |  On the node that has been certified successfully, request the server to change the key |
 
<span style="color:red"> Notice </span>
   - A Port 1 is dedicated to eWBM PKI communication and is therefore forbidden to use.
   - If you attempt UPLINK up to eight times to receive server response from End-Device and do not receive PKIServer Answer, it is a failure.
  
 # **【 Quickstart 】**
 
 # **【 License 】**
   - [LICENSE TERM](LICENSE.md)



***[eWBM Home](https://www.ewbm.com "Title")***


