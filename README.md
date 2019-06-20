# **【 eWBM's MS500 MCU 】**
- Secure MCU with high performing hardware crypto engines 
- Secure boot and secure storage mechanism built-in
- True Random Number Generator (TRNG) for key generation

# **【 What is PKI over LoRa? 】**
PKI 가 필요한 배경에 대해 설명 할 예정 

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
      -Join request with the new AppKey


# **【 Supported Operating Environment 】**


# **【 Features 】**


# **【 Related Crypto Libraries 】**
- OpenSSL-1.1.Of-vs2017
- ECC
  - Curve parameter (Secp256R1)
 
