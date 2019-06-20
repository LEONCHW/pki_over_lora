/* ========================================================================================
** PKI over LoRa 
** 2019 06 18
** Kim Woong Jea, Park Sung Jin
** www.ewbm.co.kr
** ========================================================================================*/
#pragma once

#include "BaseMgr.h"
#include "JSonPKI.h"

class CEcdsaDevice;
class CEcdsaMgr : public CBaseMgr
{
public:
	CEcdsaMgr(void);
	~CEcdsaMgr(void);

	BOOL				SetInitialize();
	void				SetUninitialize();

	void				SetWnd(CWnd *pWnd);

	CEcdsaDevice*		RecvPublicKeyReq(CJSonPKI *pPki);
	BOOL				SendPublicKeyRes(CEcdsaDevice *pDev, CJSonPKI *pPki);

	CEcdsaDevice*		RecvSigVerifyReq(CJSonPKI *pPki);
	BOOL				SendSigVerifyRes(CEcdsaDevice *pDev, CJSonPKI *pPki);

	CEcdsaDevice*		RecvKeyChangeReq(CJSonPKI *pPki);
	BOOL				SendKeyChangeRes(CEcdsaDevice *pDev, CJSonPKI *pPki);

	CStringArray*		GetDevLog(CString strDevId);

private:
	CWnd*				m_pWnd;

	BOOL				CrateKeySet(BYTE *pubKey, CEcdsaDevice *pDev);
	BOOL				PubKeyVerify(CEcdsaDevice *pDev);
	void				Sha256(BYTE* pSrcData, int len, BYTE* pOutput);
	void				SendEccMessage(UINT msg, WPARAM wParam, LPARAM lParam);
};

