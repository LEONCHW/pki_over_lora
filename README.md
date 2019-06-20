# **【 eWBM's MS500 MCU 】**
- Secure MCU with high performing hardware crypto engines 
- Secure boot and secure storage mechanism built-in
- True Random Number Generator (TRNG) for key generation

# **【 What is PKI over LoRa? 】**
우리는 LoRaWAN 에서 현재 사용하고 있는 PSK (Pre-shared key) scheme 에서 발생할 수 있는 문제점을 해결하기 위한 Solution으로 PKI 기반의 실시간 Key 교환 및 장치인증 메커니즘을 이용한 섹션키를 배치할 수 있는 메커니즘을 제안한다.   

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
   - *** TBD ***
  


# **【 Features 】**
## Device authentication 
   - ECDSA 메커니즘을 사용하여 장치와 서버간 인증
   
## Realtime Key exchange
   - ECDH 메커니즘을 사용하여 장치와 서버간 실시간 비밀키 생성

# **【 Related Crypto Libraries 】**
- OpenSSL-1.1.Of-vs2017

 # **【 Requirements 】**
  
 # **【 Quickstart 】**
