/* ========================================================================================
** PKI over LoRa
** 2019 06 18
** Kim Woong Jea, Park Sung Jin
** www.ewbm.co.kr
** ========================================================================================*/


#include "StdAfx.h"
#include "EcdsaDevice.h"

CEcdsaDevice::CEcdsaDevice(void)
{
	
}

CEcdsaDevice::~CEcdsaDevice(void)
{
	
}


CString CEcdsaDevice::AddPkiCmdLog(int nCid, char* pszData)
{
	CTime time = CTime::GetCurrentTime();
	CString strLog;
	CString strData = CA2W(pszData);
	CString strTime = time.Format(DEF_CTIME_LOG_FORMAT);

	strLog.Format(_T("%s%s%02d%s%s"), strTime, BASE_LOG_TOKENIZE, nCid, BASE_LOG_TOKENIZE, strData);

	while (m_Log.GetCount() >= MAX_LIST_LOG_COUNT) {
		m_Log.RemoveAt(0);
	}
	m_Log.Add(strLog);
	return strLog;
}


CString CEcdsaDevice::AddEcdsaLog(CString strData)
{
	CTime time = CTime::GetCurrentTime();
	CString strLog;
	CString strTime = time.Format(DEF_CTIME_LOG_FORMAT);

	strLog.Format(_T("%s%s  %s%s"), strTime, BASE_LOG_TOKENIZE, BASE_LOG_TOKENIZE, strData);

	while (m_Log.GetCount() >= MAX_LIST_LOG_COUNT) {
		m_Log.RemoveAt(0);
	}
	m_Log.Add(strLog);
	return strLog;
}


CString CEcdsaDevice::GetLastLog()
{
	int nLastLog = (int)m_Log.GetCount() -1;
	if (nLastLog < 0 ) {
		return _T("");
	}

	return m_Log.GetAt(nLastLog);

}