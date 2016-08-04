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
 * @brief 내부 변수를 패킷에 저장한다.
 * @param pszPacket		패킷
 * @param iPacketSize 패킷 크기
 * @returns 성공하면 저장된 패킷 길이를 리턴하고 실패하면 -1 을 리턴한다.
 */
int CSnmpMessage::MakePacket( char * pszPacket, int iPacketSize )
{
	if( m_cVersion != SNMP_VERSION_3 )
	{
		return MakePacketV2( pszPacket, iPacketSize );
	}

	return MakePacketV3( pszPacket, iPacketSize );
}

/**
 * @ingroup SnmpParser
 * @brief 패킷을 생성하여서 내부 변수에 저장한다.
 * @returns 성공하면 true 를 리턴하고 실패하면 false 를 리턴한다.
 */
bool CSnmpMessage::MakePacket( )
{
	if( m_pszPacket == NULL )
	{
		m_pszPacket = (char *)malloc( SNMP_MAX_PACKET_SIZE );
		if( m_pszPacket == NULL ) return false;
	}

	m_iPacketLen = MakePacket( m_pszPacket, SNMP_MAX_PACKET_SIZE );
	if( m_iPacketLen == -1 ) 
	{
		free( m_pszPacket );
		m_pszPacket = NULL;
		return false;
	}

	return true;
}

/**
 * @ingroup SnmpParser
 * @brief SNMPv3 msgGlobalData 영역으로 CAsnComplex 로 생성한다.
 * @returns 성공하면 생성된 CAsnComplex 객체의 포인터를 리턴하고 그렇지 않으면 NULL 을 리턴한다.
 */
CAsnComplex * CSnmpMessage::CreateMsgGlobalData( )
{
	CAsnComplex * pclsComplex = new CAsnComplex();
	if( pclsComplex == NULL ) return NULL;

	if( pclsComplex->AddInt( m_iMsgId ) == false ) goto FUNC_ERROR;
	if( pclsComplex->AddInt( m_iMsgMaxSize ) == false ) goto FUNC_ERROR;
	if( pclsComplex->AddString( m_cMsgFlags ) == false ) goto FUNC_ERROR;
	if( pclsComplex->AddInt( m_iMsgSecurityModel ) == false ) goto FUNC_ERROR;

	return pclsComplex;

FUNC_ERROR:
	delete pclsComplex;

	return NULL;
}

/**
 * @ingroup SnmpParser
 * @brief SNMPv3 msgSecurityParameters 영역을 CAsnString 로 생성한다.
 * @returns 성공하면 생성된 CAsnString 객체의 포인터를 리턴하고 그렇지 않으면 NULL 을 리턴한다.
 */
CAsnString * CSnmpMessage::CreateMsgSecurityParameters( )
{
	CAsnComplex clsComplex;

	if( clsComplex.AddString( m_strMsgAuthEngineId ) == false ) return NULL;
	if( clsComplex.AddInt( m_iMsgAuthEngineBoots ) == false ) return NULL;
	if( clsComplex.AddInt( m_iMsgAuthEngineTime ) == false ) return NULL;
	if( clsComplex.AddString( m_strMsgUserName ) == false ) return NULL;
	if( clsComplex.AddString( m_strMsgAuthParams ) == false ) return NULL;
	if( clsComplex.AddString( m_strMsgPrivParams ) == false ) return NULL;

	char szPacket[SNMP_MAX_PACKET_SIZE];
	int iPacketLen = clsComplex.MakePacket( szPacket, sizeof(szPacket) );
	if( iPacketLen == -1 )
	{
		return NULL;
	}

	CAsnString * pclsValue = new CAsnString();
	if( pclsValue == NULL )
	{
		return NULL;
	}

	pclsValue->m_strValue.append( szPacket, iPacketLen );

	return pclsValue;
}

/**
 * @ingroup SnmpParser
 * @brief SNMPv3 msgData 영역으로 CAsnComplex 로 생성한다.
 * @returns 성공하면 생성된 CAsnComplex 객체의 포인터를 리턴하고 그렇지 않으면 NULL 을 리턴한다.
 */
CAsnComplex * CSnmpMessage::CreateMsgData( )
{
	CAsnComplex * pclsCommand = CreateCommand( );
	if( pclsCommand == NULL ) return NULL;

	CAsnComplex * pclsComplex = new CAsnComplex();
	if( pclsComplex == NULL ) goto FUNC_ERROR;

	if( pclsComplex->AddString( m_strContextEngineId ) == false ) goto FUNC_ERROR;
	if( pclsComplex->AddString( m_strContextName ) == false ) goto FUNC_ERROR;
	if( pclsComplex->AddComplex( pclsCommand ) == false ) goto FUNC_ERROR;

	return pclsComplex;

FUNC_ERROR:
	if( pclsComplex )
	{
		delete pclsComplex;
	}
	else if( pclsCommand )
	{
		delete pclsCommand;
	}

	return NULL;
}

/**
 * @ingroup SnmpParser
 * @brief SNMP command 영역으로 CAsnComplex 로 생성한다.
 * @returns 성공하면 생성된 CAsnComplex 객체의 포인터를 리턴하고 그렇지 않으면 NULL 을 리턴한다.
 */
CAsnComplex * CSnmpMessage::CreateCommand( )
{
	CAsnComplex * pclsCommand = NULL, *pclsBody = NULL;

	pclsCommand = new CAsnComplex();
	if( pclsCommand == NULL ) return NULL;

	pclsCommand->m_cType = m_cCommand;
	if( pclsCommand->AddInt( m_iRequestId ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorStatus ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorIndex ) == false ) goto FUNC_ERROR;

	if( m_pclsOidValueList )
	{
		pclsBody = m_pclsOidValueList->GetComplex();
		if( pclsBody == NULL ) goto FUNC_ERROR;
		pclsCommand->AddComplex( pclsBody );
		}

	return pclsCommand;

FUNC_ERROR:
	if( pclsCommand ) delete pclsCommand;
	if( pclsBody ) delete pclsBody;

	return NULL;
}

/**
 * @ingroup SnmpParser
 * @brief SNMPv2 패킷을 생성한다.
 * @param pszPacket		패킷 저장 변수
 * @param iPacketSize 패킷 저장 변수의 크기
 * @returns 성공하면 패킷의 길이를 리턴하고 그렇지 않으면 -1 을 리턴한다.
 */
int CSnmpMessage::MakePacketV2( char * pszPacket, int iPacketSize )
{
	CAsnComplex clsComplex;
	CAsnComplex * pclsCommand = NULL;

	if( clsComplex.AddInt( m_cVersion ) == false ) return -1;
	if( clsComplex.AddString( m_strCommunity.c_str() ) == false ) return -1;

	pclsCommand = CreateCommand();
	if( pclsCommand == NULL ) return -1;

	clsComplex.AddComplex( pclsCommand );

	return clsComplex.MakePacket( pszPacket, iPacketSize );
}

/**
 * @ingroup SnmpParser
 * @brief SNMPv3 패킷을 생성한다.
 * @param pszPacket		패킷 저장 변수
 * @param iPacketSize 패킷 저장 변수의 크기
 * @returns 성공하면 패킷의 길이를 리턴하고 그렇지 않으면 -1 을 리턴한다.
 */
int CSnmpMessage::MakePacketV3( char * pszPacket, int iPacketSize )
{
	CAsnComplex clsComplex;
	CAsnComplex * pclsGlobalData = NULL, * pclsData = NULL;
	CAsnString * pclsSecurityParams = NULL;
	int n;

	pclsGlobalData = CreateMsgGlobalData();
	if( pclsGlobalData == NULL ) goto FUNC_ERROR;

	pclsSecurityParams = CreateMsgSecurityParameters();
	if( pclsSecurityParams == NULL ) goto FUNC_ERROR;

	if( clsComplex.AddInt( m_cVersion ) == false ) goto FUNC_ERROR;
	if( clsComplex.AddComplex( pclsGlobalData ) == false ) goto FUNC_ERROR;
	if( clsComplex.AddValue( pclsSecurityParams ) == false ) goto FUNC_ERROR;

	if( m_strEncryptedPdu.empty() )
	{
		pclsData = CreateMsgData();
		if( pclsData == NULL ) goto FUNC_ERROR;

		if( clsComplex.AddComplex( pclsData ) == false ) goto FUNC_ERROR;
	}
	else
	{
		if( clsComplex.AddString( m_strEncryptedPdu ) == false ) goto FUNC_ERROR;
	}

	n = clsComplex.MakePacket( pszPacket, iPacketSize );
	if( n == -1 ) goto FUNC_ERROR;

	return n;

FUNC_ERROR:
	if( pclsGlobalData ) delete pclsGlobalData;
	if( pclsData ) delete pclsData;
	if( pclsSecurityParams ) delete pclsData;

	return -1;
}
