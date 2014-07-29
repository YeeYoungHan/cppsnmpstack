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

#include "SnmpMessage.h"
#include "AsnInt.h"
#include "AsnString.h"
#include "AsnOid.h"
#include "AsnComplex.h"

CSnmpMessage::CSnmpMessage()
{
}

CSnmpMessage::~CSnmpMessage()
{
}

int CSnmpMessage::ParsePacket( const char * pszPacket, int iPacketLen )
{
	int iPos = 0, n;
	CAsnInt		clsInt;
	CAsnString	clsStr;
	CAsnOid			clsOid;
	CAsnVariable	clsVar;

	iPos += 2;

	n = clsInt.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	m_cVersion = clsInt.m_iValue;

	n = clsStr.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	m_strCommunity = clsStr.m_strValue;

	m_cCommand = pszPacket[iPos++];
	int iDataLen = pszPacket[iPos++];

	n = clsInt.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	m_iRequestId = clsInt.m_iValue;

	n = clsInt.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	m_iErrorStatus = clsInt.m_iValue;

	n = clsInt.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	m_iErrorIndex = clsInt.m_iValue;

	++iPos;
	int iComplexLen = pszPacket[iPos++];

	++iPos;
	iComplexLen = pszPacket[iPos++];

	n = clsOid.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	m_strOid = clsOid.m_strValue;

	n = m_clsVariable.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	return iPos;
}

int CSnmpMessage::MakePacket( char * pszPacket, int iPacketSize )
{
	CAsnComplex clsComplex;
	CAsnComplex *pclsCommand = NULL, *pclsBodyFrame = NULL, *pclsBody = NULL;

	if( clsComplex.AddInt( m_cVersion ) == false ) return -1;
	if( clsComplex.AddString( m_strCommunity.c_str() ) == false ) return -1;

	pclsCommand = new CAsnComplex();
	if( pclsCommand == NULL ) return -1;

	pclsCommand->m_cType = m_cCommand;
	if( pclsCommand->AddInt( m_iRequestId ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorStatus ) == false ) goto FUNC_ERROR;
	if( pclsCommand->AddInt( m_iErrorIndex ) == false ) goto FUNC_ERROR;

	pclsBodyFrame = new CAsnComplex();
	if( pclsBodyFrame == NULL ) goto FUNC_ERROR;

	pclsBody = new CAsnComplex();
	if( pclsBody == NULL ) goto FUNC_ERROR;

	if( pclsBody->AddOid( m_strOid.c_str() ) == false ) goto FUNC_ERROR;
	if( pclsBody->AddValue( m_pclsValue ) == false ) goto FUNC_ERROR;

	pclsBodyFrame->AddComplex( pclsBody );
	pclsCommand->AddComplex( pclsBodyFrame );
	clsComplex.AddComplex( pclsCommand );

	return clsComplex.MakePacket( pszPacket, iPacketSize );

FUNC_ERROR:
	if( pclsCommand ) delete pclsCommand;
	if( pclsBodyFrame ) delete pclsBodyFrame;
	if( pclsBody ) delete pclsBody;

	return -1;
}

