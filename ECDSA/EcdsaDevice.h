/* ========================================================================================
** PKI over LoRa
** 2019 06 18
** Kim Woong Jea, Park Sung Jin
** www.ewbm.co.kr
** ========================================================================================*/


#pragma once


#define ECDSA_DEVICE_KEY_SIZE			50
#define ECDSA_PUBLIC_KEY_SIZE			48
#define ECDSA_PRIVATE_KEY_SIZE			24
#define ECDSA_SHARED_KEY_SIZE			32
#define ECDSA_SIGNATURE_SIZE			48


typedef struct {
	char		szDevID[ECDSA_DEVICE_KEY_SIZE * 2 + 1];
	char		szDevName[ECDSA_DEVICE_KEY_SIZE * 2 + 1];
	char		szDevPublicKey[ECDSA_PUBLIC_KEY_SIZE * 2 + 1];
	char		szDevSignature[ECDSA_SIGNATURE_SIZE * 2 + 1];

	char		szSvrPublicKey[ECDSA_PUBLIC_KEY_SIZE * 2 + 1];
	char		szSvrPrivateKey[ECDSA_PRIVATE_KEY_SIZE * 2 + 1];
	char		szSharedKey[ECDSA_SHARED_KEY_SIZE * 2 + 1];
	//char		szSignature[ECDSA_SIGNATURE_SIZE * 2 + 1];
}sEcdsaCfgType;



class CEcdsaDevice
{
public:
	CEcdsaDevice(void);
	~CEcdsaDevice(void);

	BYTE				m_bSigVerify;
	sEcdsaCfgType*		GetCfg() { return &m_sCfg; };
	CStringArray*		GetLog() { return &m_Log; };
	CString				AddPkiCmdLog(int nCid, char* pszData);
	CString				AddEcdsaLog(CString strData);
	CString				GetLastLog();

private:
	sEcdsaCfgType		m_sCfg;
	CStringArray		m_Log;
};

