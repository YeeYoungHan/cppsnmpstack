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
	CAsnVariable	clsVar;

	iPos += 2;

	n = clsInt.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	m_cVersion = clsInt.m_iValue;

	n = clsVar.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	if( clsVar.GetString( m_strCommunity ) == false ) return -1;

	m_cCommand = pszPacket[iPos++];
	int iDataLen = pszPacket[iPos++];

	n = clsVar.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	if( clsVar.GetInt( m_iRequestId ) == false ) return -1;

	n = clsVar.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	if( clsVar.GetInt( m_iErrorStatus ) == false ) return -1;

	n = clsVar.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	if( clsVar.GetInt( m_iErrorIndex ) == false ) return -1;

	++iPos;
	int iComplexLen = pszPacket[iPos++];

	++iPos;
	iComplexLen = pszPacket[iPos++];

	n = clsVar.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	if( clsVar.GetOid( m_strOid ) == false ) return -1;

	n = m_clsVariable.ParsePacket( pszPacket + iPos, iPacketLen - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	return iPos;
}

int CSnmpMessage::MakePacket( char * pszPacket, int iPacketSize )
{
	int iPos = 0, n;
	int arrPos[3];
	CAsnVariable	clsVar;

	pszPacket[iPos++] = ASN_TYPE_COMPLEX;
	++iPos;

	clsVar.SetInt( m_cVersion );
	n = clsVar.MakePacket( pszPacket + iPos, iPacketSize - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	clsVar.SetString( m_strCommunity.c_str() );
	n = clsVar.MakePacket( pszPacket + iPos, iPacketSize - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	pszPacket[iPos++] = m_cCommand;
	arrPos[0] = iPos;
	++iPos;

	clsVar.SetInt( m_iRequestId );
	n = clsVar.MakePacket( pszPacket + iPos, iPacketSize - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	clsVar.SetInt( m_iErrorStatus );
	n = clsVar.MakePacket( pszPacket + iPos, iPacketSize - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	clsVar.SetInt( m_iErrorIndex );
	n = clsVar.MakePacket( pszPacket + iPos, iPacketSize - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	pszPacket[iPos++] = ASN_TYPE_COMPLEX;
	arrPos[1] = iPos;
	++iPos;

	pszPacket[iPos++] = ASN_TYPE_COMPLEX;
	arrPos[2] = iPos;
	++iPos;

	clsVar.SetOid( m_strOid.c_str() );
	n = clsVar.MakePacket( pszPacket + iPos, iPacketSize - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	n = m_clsVariable.MakePacket( pszPacket + iPos, iPacketSize - iPos );
	if( n == -1 ) return -1;
	iPos += n;

	pszPacket[arrPos[2]] = iPos - arrPos[2] - 1;
	pszPacket[arrPos[1]] = iPos - arrPos[1] - 1;
	pszPacket[arrPos[0]] = iPos - arrPos[0] - 1;
	pszPacket[1] = iPos - 2;

	return iPos;
}

