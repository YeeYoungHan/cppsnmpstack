/* 
 * Copyright (C) 2012 Yee Young Han <websearch@naver.com> (http://blog.naver.com/websearch)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA 
 */

/**
 * @ingroup SnmpParser
 * @brief msgPrivacyParameters 값을 설정하고 PDU 를 암호화한다.
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpMessage::SetPrivParams( )
{
	int		iPacketLen;
	char	szPacket[SNMP_MAX_PACKET_SIZE];
	struct timeval sttTime;
	uint32_t	iSec, iNanoSec;

	m_strMsgPrivParams.clear();
	m_strEncryptedPdu.clear();

	if( m_strPrivPassWord.empty() ) return true;

	gettimeofday( &sttTime, NULL );
	iSec = sttTime.tv_sec;
	iNanoSec = sttTime.tv_usec;

	memcpy( szPacket, &iSec, 4 );
	memcpy( szPacket + 4, &iNanoSec, 4 );

	m_strMsgPrivParams.append( szPacket, 8 );

	CAsnComplex * pclsData = CreateMsgData();
	if( pclsData == NULL ) return false;

	iPacketLen = pclsData->MakePacket( szPacket, sizeof(szPacket) );
	delete pclsData;

	if( iPacketLen == -1 ) return false;

	if( SnmpEncrypt( szPacket, iPacketLen, m_strPrivPassWord.c_str(), m_strMsgAuthEngineId.c_str(), m_strMsgAuthEngineId.length()
				, m_strMsgPrivParams.c_str(), m_strMsgPrivParams.length(), m_strEncryptedPdu ) == false )
	{
		return false;
	}

	m_cMsgFlags |= SNMP_MSG_FLAG_ENCRYPT;

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief msgAuthenticationParameters 값을 계산한다.
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpMessage::SetAuthParams( )
{
	int		iPacketLen;
	char	szPacket[SNMP_MAX_PACKET_SIZE];

	m_strMsgAuthParams.clear();
	if( m_strAuthPassWord.empty() ) return true;

	m_cMsgFlags |= SNMP_MSG_FLAG_AUTH;

	for( int i = 0; i < 12; ++i )
	{
		m_strMsgAuthParams.append( " " );
		m_strMsgAuthParams.at(i) = '\0';
	}

	iPacketLen = MakePacket( szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 ) return false;

	if( SnmpMakeHmac( szPacket, iPacketLen, m_strAuthPassWord.c_str(), m_strMsgAuthEngineId.c_str(), m_strMsgAuthEngineId.length(), m_strMsgAuthParams ) == false )
	{
		return false;
	}

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief 암호화된 PDU 를 복호화하여서 내부 변수에 저장한다.
 * @returns 성공하면 true 를 리턴하고 그렇지 않으면 false 를 리턴한다.
 */
bool CSnmpMessage::ParseEncryptedPdu( )
{
	std::string strPlain;

	if( SnmpDecrypt( m_strEncryptedPdu.c_str(), m_strEncryptedPdu.length(), m_strPrivPassWord.c_str()
			, m_strMsgAuthEngineId.c_str(), m_strMsgAuthEngineId.length(), m_strMsgPrivParams.c_str(), m_strMsgPrivParams.length(), strPlain ) == false )
	{
		CLog::Print( LOG_ERROR, "%s msgData decrypt error", __FUNCTION__ );
		return false;
	}

	CAsnComplex clsData;

	if( clsData.ParsePacket( strPlain.c_str(), strPlain.length() ) == -1 )
	{
		CLog::Print( LOG_ERROR, "%s msgData parse error", __FUNCTION__ );
		return false;
	}

	if( SetMsgData( &clsData ) == false )
	{
		CLog::Print( LOG_ERROR, "%s SetMsgData error", __FUNCTION__ );
		return false;
	}

	return true;
}

bool CSnmpMessage::CheckAuth( )
{
	if( ( m_cMsgFlags & SNMP_MSG_FLAG_AUTH ) == 0 ) return true;

	if( m_strMsgAuthParams.length() != 12 ) 
	{
		CLog::Print( LOG_ERROR, "%s msgAuthParam length(%d) is not 12", __FUNCTION__, m_strMsgAuthParams.length() );
		return false;
	}

	std::string strMsgAuthParams = m_strMsgAuthParams;
	int		iPacketLen;
	char	szPacket[SNMP_MAX_PACKET_SIZE];

	for( int i = 0; i < 12; ++i )
	{
		m_strMsgAuthParams.at(i) = '\0';
	}

	iPacketLen = MakePacket( szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 )
	{
		CLog::Print( LOG_ERROR, "%s MakePacket error", __FUNCTION__ );
		return false;
	}

	if( SnmpMakeHmac( szPacket, iPacketLen, m_strAuthPassWord.c_str(), m_strMsgAuthEngineId.c_str(), m_strMsgAuthEngineId.length(), m_strMsgAuthParams ) == false )
	{
		CLog::Print( LOG_ERROR, "%s SnmpMakeHmac error", __FUNCTION__ );
		return false;
	}

	if( strncmp( m_strMsgAuthParams.c_str(), strMsgAuthParams.c_str(), 12 ) )
	{
		CLog::Print( LOG_ERROR, "%s msgAuthParam is not correct", __FUNCTION__ );
		m_strMsgAuthParams = strMsgAuthParams;
		return false;
	}

	return true;
}
