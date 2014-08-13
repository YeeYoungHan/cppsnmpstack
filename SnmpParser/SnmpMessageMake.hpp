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

CAsnComplex * CSnmpMessage::CreateCommand( )
{
	CAsnComplex * pclsCommand = NULL, *pclsBodyFrame = NULL, *pclsBody = NULL;

	pclsCommand = new CAsnComplex();
	if( pclsCommand == NULL ) return NULL;

	pclsCommand->m_cType = m_cCommand;
	if( pclsCommand->AddInt( m_iRequestId ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorStatus ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorIndex ) == false ) goto FUNC_ERROR;

	pclsBodyFrame = new CAsnComplex();
	if( pclsBodyFrame == NULL ) goto FUNC_ERROR;

	if( m_strOid.empty() == false )
	{
		pclsBody = new CAsnComplex();
		if( pclsBody == NULL ) goto FUNC_ERROR;

		if( pclsBody->AddOid( m_strOid.c_str() ) == false ) goto FUNC_ERROR;

		{
			CAsnType * pclsValue = m_pclsValue->Copy();
			if( pclsValue == NULL ) goto FUNC_ERROR;
			if( pclsBody->AddValue( pclsValue ) == false ) goto FUNC_ERROR;
		}

		pclsBodyFrame->AddComplex( pclsBody );
	}
	
	pclsCommand->AddComplex( pclsBodyFrame );

	return pclsCommand;

FUNC_ERROR:
	if( pclsCommand ) delete pclsCommand;
	if( pclsBodyFrame ) delete pclsBodyFrame;
	if( pclsBody ) delete pclsBody;

	return NULL;
}

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

	pclsData = CreateMsgData();
	if( pclsData == NULL ) goto FUNC_ERROR;

	if( clsComplex.AddInt( m_cVersion ) == false ) goto FUNC_ERROR;
	if( clsComplex.AddComplex( pclsGlobalData ) == false ) goto FUNC_ERROR;
	if( clsComplex.AddValue( pclsSecurityParams ) == false ) goto FUNC_ERROR;
	if( clsComplex.AddComplex( pclsData ) == false ) goto FUNC_ERROR;

	n = clsComplex.MakePacket( pszPacket, iPacketSize );
	if( n == -1 ) goto FUNC_ERROR;

	return n;

FUNC_ERROR:
	if( pclsGlobalData ) delete pclsGlobalData;
	if( pclsData ) delete pclsData;
	if( pclsSecurityParams ) delete pclsData;

	return -1;
}
