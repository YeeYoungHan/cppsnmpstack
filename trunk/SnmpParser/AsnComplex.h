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

#ifndef _ASN_COMPLEX_H_
#define _ASN_COMPLEX_H_

#include "AsnType.h"
#include <list>

typedef std::list< CAsnType * > ASN_TYPE_LIST;

/**
 * @ingroup SnmpParser
 * @brief ASN ���� Ÿ�� Ŭ����
 */
class CAsnComplex : public CAsnType
{
public:
	CAsnComplex();
	virtual ~CAsnComplex();

	virtual int ParsePacket( const char * pszPacket, int iPacketLen );
	virtual int MakePacket( char * pszPacket, int iPacketSize );
	virtual CAsnType * Copy( );

	bool AddInt( uint32_t iValue );
	bool AddString( const char * pszValue );
	bool AddString( std::string & strValue );
	bool AddOid( const char * pszValue );
	bool AddNull( );
	bool AddComplex( CAsnComplex * pclsValue );
	bool AddValue( CAsnType * pclsValue );

	void Clear();

	ASN_TYPE_LIST m_clsList;
};

#endif