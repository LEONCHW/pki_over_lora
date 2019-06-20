/* ========================================================================================
** PKI over LoRa
** 2019 06 18
** Kim Woong Jea, Park Sung Jin
** www.ewbm.co.kr
** ========================================================================================*/

#include "StdAfx.h"
#include "EcdsaMgr.h"
#include "EcdsaDevice.h"

extern "C" {
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/ec.h"
#include "openssl/sha.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/aes.h"
}


#ifdef _DEBUG
#pragma comment (lib, "libcryptoMDd.lib")
#pragma comment (lib, "libsslMDd.lib")
#else
#pragma comment (lib, "libcryptoMD.lib")
#pragma comment (lib, "libsslMD.lib")
#endif

CEcdsaMgr::CEcdsaMgr(void)
{
	m_pWnd = NULL;
	m_bInitialize = FALSE;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
}

CEcdsaMgr::~CEcdsaMgr(void)
{
	
}

BOOL CEcdsaMgr::SetInitialize()
{
	CPtrList ptrFreeList;

	if (m_bInitialize == TRUE) {
		return TRUE;
	}

	LOCK("CClientSocketMgr::Initialize");
	for (int i = 0; i < MAX_DEVICE_CNT; i++) {
		CEcdsaDevice	*pDevice = new CEcdsaDevice();
		ptrFreeList.AddTail(pDevice);
	}
	CBaseMgr::Initialize(_T("CEcdsaMgr"), &ptrFreeList);
	RELEASE("CClientSocketMgr::Initialize");
	return TRUE;
}


void CEcdsaMgr::SetUninitialize()
{
	if (m_bInitialize == FALSE) {
		return;
	}

	LOCK("CClientSocketMgr::Uninitialize");
	CBaseMgr::Uninitialize();
	CPtrList *pList = CBaseMgr::GetPoolList();
	while (pList->GetCount() > 0) {
		CEcdsaDevice *pDevice = (CEcdsaDevice*)pList->RemoveTail();
		delete pDevice;
	}

	RELEASE("CClientSocketMgr::Uninitialize");
	
}


void  CEcdsaMgr::SetWnd(CWnd *pWnd)
{
	m_pWnd = pWnd;
}


/* PKI SERVER START FUNCTION
** CID : 0
** PUB KEY = 48 BYTE
*/
CEcdsaDevice* CEcdsaMgr::RecvPublicKeyReq(CJSonPKI *pPki)
{
	char szDevID[100] = { NULL, };
	char szDevName[100] = { NULL, };
	char szPubKey[100] = { NULL, };
	BYTE bData[ECDSA_PUBLIC_KEY_SIZE] = { NULL, };

	/* Find Device -----------------------*/
	pPki->GetRxField(STR_JSON_DEVID, szDevID);
	pPki->GetRxField(STR_JSON_NAME, szDevName);
	pPki->GetRxField(STR_JSON_DATA, szPubKey);

	CEcdsaDevice *pDev = (CEcdsaDevice*)CBaseMgr::GetStrMapObject(szDevID);
	if (pDev == NULL) {
		return NULL;
	}

	pDev->AddPkiCmdLog(PKI_CID_PUBKEY_REQ, szPubKey);
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	/* 기존 데이터는 모두 RESET 된다. */
	memset(pDev->GetCfg(), NULL, sizeof(sEcdsaCfgType));
	strcpy(pDev->GetCfg()->szDevID, szDevID);
	strcpy(pDev->GetCfg()->szDevName, szDevName);
	strcpy(pDev->GetCfg()->szDevPublicKey, szPubKey);

	/* 서버에서 ECC KEY 생성한다. --------------------------*/

	CWinUtils::GetHexByteFromStr(szPubKey, bData, ECDSA_PUBLIC_KEY_SIZE);
	if (CrateKeySet(bData, pDev)) {
		
	}
	else {
		return NULL;
	}

		

	return pDev;
}


BOOL CEcdsaMgr::SendPublicKeyRes(CEcdsaDevice *pDev, CJSonPKI *pPki)
{
	char szValue[100];

	sprintf(szValue, "%s", pDev->GetCfg()->szDevID);
	pPki->AddTxField(STR_JSON_DEVID, szValue);

	sprintf(szValue, "%02d", PKI_CID_PUBKEY_ANS);
	pPki->AddTxField(STR_JSON_CID, szValue);

	sprintf(szValue, "%s", pDev->GetCfg()->szSvrPublicKey);
	pPki->AddTxField(STR_JSON_DATA, szValue);

	pDev->AddPkiCmdLog(PKI_CID_PUBKEY_ANS, szValue);
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	return TRUE;
}


CEcdsaDevice* CEcdsaMgr::RecvSigVerifyReq(CJSonPKI *pPki)
{
	char szDevID[100];
	char szSignature[100];

	/* Find Device -----------------------*/
	pPki->GetRxField(STR_JSON_DEVID, szDevID);
	pPki->GetRxField(STR_JSON_DATA, szSignature);

	CEcdsaDevice *pDev = (CEcdsaDevice*)CBaseMgr::GetStrMapObject(szDevID);
	if (pDev == NULL) {
		return NULL;
	}

	pDev->AddPkiCmdLog(PKI_CID_SIGVERIFY_REQ, szSignature);
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	strcpy(pDev->GetCfg()->szDevSignature, szSignature);
	/* Verify를 하고, 결과를 확인한다. --------------------------*/
	// add-code  success(0)  or fail ?

	if (PubKeyVerify(pDev)) {
		pDev->m_bSigVerify = PKI_VEROFY_SUCC;
	}
	else {
		pDev->m_bSigVerify = PKI_VEROFY_FAIL;
	}

	
	return pDev;
}


BOOL CEcdsaMgr::SendSigVerifyRes(CEcdsaDevice *pDev, CJSonPKI *pPki)
{
	char szValue[100];

	sprintf(szValue, "%s", pDev->GetCfg()->szDevID);
	pPki->AddTxField(STR_JSON_DEVID, szValue);

	sprintf(szValue, "%02d", PKI_CID_SIGVERIFY_ANS);
	pPki->AddTxField(STR_JSON_CID, szValue);

	sprintf(szValue, "%02d", pDev->m_bSigVerify);
	pPki->AddTxField(STR_JSON_DATA, szValue);

	pDev->AddPkiCmdLog(PKI_CID_SIGVERIFY_ANS, szValue);
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	return TRUE;
}



CEcdsaDevice* CEcdsaMgr::RecvKeyChangeReq(CJSonPKI *pPki)
{
	char szDevID[100];
	
	/* Find Device -----------------------*/
	pPki->GetRxField(STR_JSON_DEVID, szDevID);

	CEcdsaDevice *pDev = (CEcdsaDevice*)CBaseMgr::GetStrMapObject(szDevID);
	if (pDev == NULL) {
		return NULL;
	}

	pDev->AddPkiCmdLog(PKI_CID_KEYCHANGE_REQ, NULL);
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	return pDev;
}


BOOL CEcdsaMgr::SendKeyChangeRes(CEcdsaDevice *pDev, CJSonPKI *pPki)
{
	char szValue[100];

	sprintf(szValue, "%s", pDev->GetCfg()->szDevID);
	pPki->AddTxField(STR_JSON_DEVID, szValue);

	sprintf(szValue, "%02d", PKI_CID_KEYCHANGE_ANS);
	pPki->AddTxField(STR_JSON_CID, szValue);

	sprintf(szValue, "%s", pDev->GetCfg()->szSharedKey);
	pPki->AddTxField(STR_JSON_DATA, szValue);

	pDev->AddPkiCmdLog(PKI_CID_KEYCHANGE_ANS, szValue);
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	return TRUE;
}

CStringArray*  CEcdsaMgr::GetDevLog(CString strDevId)
{
	CEcdsaDevice *pDev = (CEcdsaDevice*)CBaseMgr::GetStrMapObject(strDevId);

	if (pDev != NULL) {
		return pDev->GetLog();
	}

	return NULL;
}

BOOL CEcdsaMgr::CrateKeySet(BYTE *pubKey, CEcdsaDevice *pDev)
{
	sEcdsaCfgType*	psCfgType = pDev->GetCfg();

	BOOL			bResult = TRUE;

	EC_KEY*			pecKey = NULL;
	EC_KEY*			pecDevKeyNew = NULL;

	size_t			ecsize = 0;

	int				nidEcc;

	const BYTE*		szTmp = NULL;

	BYTE*			puszPriData = NULL;
	BYTE*			puszPubData = NULL;
	BYTE			uszSharBuf[MAX_PATH] = { NULL, };
	BYTE			uszSha256Buf[SHA256_DIGEST_LENGTH];
	
	// Set Key Type.   NID_X9_62_prime256v1
	nidEcc = OBJ_txt2nid("prime192v1");
	pecKey = EC_KEY_new_by_curve_name(nidEcc);//(NID_secp192k1);
	if (pecKey == NULL) {
		pDev->AddEcdsaLog(_T("Server Key Generate Error"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		ERR_print_errors_fp(stderr);
		bResult = FALSE;
		goto CreateEnd;
	}

	EC_KEY_generate_key(pecKey);
	pDev->AddEcdsaLog(_T("Server Key Generate"));
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	ecsize = i2d_ECPrivateKey(pecKey, &puszPriData);
	ecsize = i2o_ECPublicKey(pecKey, &puszPubData);

	CWinUtils::ByteToStrData(puszPriData + 7, psCfgType->szSvrPrivateKey, NULL, (int)(ecsize - 1) / 2);
	CWinUtils::ByteToStrData(puszPubData + 1, psCfgType->szSvrPublicKey, NULL, (int)ecsize - 1);
	
	memcpy(&puszPubData[1], pubKey, ECDSA_PUBLIC_KEY_SIZE);
	szTmp = puszPubData;

	pecDevKeyNew = o2i_ECPublicKey(&pecKey, &szTmp, (long)ecsize);
	if (pecDevKeyNew == NULL) {
		pDev->AddEcdsaLog(_T("Shared Key Create Error 01"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		bResult = FALSE;
		goto CreateEnd;
	}
	
	ecsize = EC_GROUP_get_degree(EC_KEY_get0_group(pecKey));
	ecsize = (ecsize + 7) / 8;

	int result = ECDH_compute_key(uszSharBuf, ecsize, EC_KEY_get0_public_key(pecDevKeyNew), pecKey, NULL);
	if (result == 0) {
		pDev->AddEcdsaLog(_T("Shared Key Create Error 02"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		bResult = FALSE;
		goto CreateEnd;
	}
	pDev->AddEcdsaLog(_T("Shared Key Create"));
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	Sha256(uszSharBuf, result, uszSha256Buf);
	CWinUtils::ByteToStrData(uszSha256Buf, psCfgType->szSharedKey, NULL, SHA256_DIGEST_LENGTH);

	pDev->AddEcdsaLog(_T("Shared Key Hash"));
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

CreateEnd:
	if (pecKey != NULL) {
		EC_KEY_free(pecKey);
	}

	if (puszPubData != NULL) {
		delete puszPubData;
		puszPubData = NULL;
	}

	if (puszPriData != NULL) {
		delete puszPriData;
		puszPriData = NULL;
	}

	return bResult;
}


BOOL CEcdsaMgr::PubKeyVerify(CEcdsaDevice *pDev)
{
	sEcdsaCfgType*	sCfgType = pDev->GetCfg();

	BOOL			bResult = TRUE;

	EC_KEY*			pecKey = NULL;
	EC_KEY*			pecKeyPubNew = NULL;
	EC_KEY*			pecKeyPreNew = NULL;

	size_t			ecSize = 0;

	int				nidEcc;
	int				nEcdsaRet;

	unsigned int	unlenSig;

	const BYTE*		pszTmp = NULL;
	BYTE*			pszPubData = NULL;
	BYTE*			pszPreData = NULL;
	BYTE			uszSerPreKey[ECDSA_PRIVATE_KEY_SIZE + 1] = { NULL, };
	BYTE			uszSerPubKey[ECDSA_PUBLIC_KEY_SIZE + 1] = { NULL, };
	BYTE			uszSha256Buf[SHA256_DIGEST_LENGTH];
	BYTE			uszSinBuf[MAX_PATH];
	BYTE			uszDevSig[MAX_PATH] = { NULL, };

	CWinUtils::GetHexByteFromStr(sCfgType->szSvrPrivateKey, uszSerPreKey, ECDSA_PRIVATE_KEY_SIZE);
	CWinUtils::GetHexByteFromStr(sCfgType->szSvrPublicKey, uszSerPubKey, ECDSA_PUBLIC_KEY_SIZE);

	nidEcc = OBJ_txt2nid("prime192v1");
	pecKey = EC_KEY_new_by_curve_name(nidEcc);	// Set Curve
	if (pecKey == NULL) {
		pDev->AddEcdsaLog(_T("Server Key Load Error 00"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		bResult = FALSE;
		goto VerifyEnd;
	}	

	EC_KEY_generate_key(pecKey);		// Create ECC Key
	
	ecSize = i2o_ECPublicKey(pecKey, &pszPubData);		// Get Pub Key
	memcpy(&pszPubData[1], uszSerPubKey, ECDSA_PUBLIC_KEY_SIZE);

	pszTmp = pszPubData;
	pecKeyPubNew = o2i_ECPublicKey(&pecKey, &pszTmp, (long)ecSize);  // Set Pub Key
	if (pecKeyPubNew == NULL) {
		pDev->AddEcdsaLog(_T("Server Key Load Error 01"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		bResult = FALSE;
		goto VerifyEnd;
	}

	ecSize = i2d_ECPrivateKey(pecKeyPubNew, &pszPreData);	// Get Pri Key
	memcpy(&pszPreData[7], uszSerPreKey, ECDSA_PRIVATE_KEY_SIZE);

	pszTmp = pszPreData;
	pecKeyPreNew = d2i_ECPrivateKey(&pecKeyPubNew, &pszTmp, (long)ecSize);	// Set Pri Key
	if (pecKeyPreNew == NULL) {
		pDev->AddEcdsaLog(_T("Server Key Load Error 02"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		bResult = FALSE;
		goto VerifyEnd;
	}

	pDev->AddEcdsaLog(_T("Server Key Load"));
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	CWinUtils::GetHexByteFromStr(sCfgType->szDevSignature, uszDevSig, ECDSA_SIGNATURE_SIZE);
	Sha256(uszDevSig, ECDSA_SIGNATURE_SIZE, uszSha256Buf);

	pDev->AddEcdsaLog(_T("Dev Key Hash"));
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	// Sign Message Digest.
	nEcdsaRet = ECDSA_sign(0, uszSha256Buf, SHA256_DIGEST_LENGTH, uszSinBuf, &unlenSig, pecKeyPreNew);
	if (nEcdsaRet != 1) {
		pDev->AddEcdsaLog(_T("Key Signe Error"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		bResult = FALSE;
		goto VerifyEnd;
	}
	pDev->AddEcdsaLog(_T("Key Signe"));
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);

	nEcdsaRet = ECDSA_verify(0, uszSha256Buf, SHA256_DIGEST_LENGTH, uszSinBuf, unlenSig, pecKeyPreNew);
	if (nEcdsaRet != 1) {
		pDev->AddEcdsaLog(_T("Key Verify Error"));
		SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
		bResult = FALSE;
	}
	pDev->AddEcdsaLog(_T("Key Verify"));
	SendEccMessage(WM_ECDSA_MSG, MSG_LOG_ADD_LIST, (LPARAM)pDev);
	   	
VerifyEnd:
	if (pecKey != NULL) {
		EC_KEY_free(pecKey);
	}

	if (pszPubData != NULL) {
		delete pszPubData;
		pszPubData = NULL;
	}

	if (pszPreData != NULL) {
		delete pszPreData;
		pszPreData = NULL;
	}

	return bResult;
}

void CEcdsaMgr::Sha256(BYTE* pSrcData, int len, BYTE* pOutput)
{
	SHA256_CTX sha256Ctx;

	// Generate Hash for signing
	SHA256_Init(&sha256Ctx);
	SHA256_Update(&sha256Ctx, pSrcData, len);
	SHA256_Final(pOutput, &sha256Ctx);
	OPENSSL_cleanse(&sha256Ctx, sizeof(sha256Ctx));
}

void CEcdsaMgr::SendEccMessage(UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (m_pWnd->GetSafeHwnd() != NULL) {
		m_pWnd->SendMessage(msg, wParam, lParam);
	}

}