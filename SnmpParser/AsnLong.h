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

#ifndef _ASN_LONG_H_
#define _ASN_LONG_H_

#include "AsnType.h"

/**
 * @ingroup SnmpParser
 * @brief ASN long 타입 클래스
 */
class CAsnLong : public CAsnType
{
public:
	CAsnLong();
	CAsnLong( uint8_t cType );
	virtual ~CAsnLong();

	virtual int ParsePacket( const char * pszPacket, int iPacketLen );
	virtual int MakePacket( char * pszPacket, int iPacketSize );
	virtual CAsnType * Copy( );

	virtual bool GetLong( uint64_t & iValue );

	int ParseLong( const char * pszPacket, int iPacketLen, uint8_t cLength, uint64_t & iValue );

	/** ASN 값 */
	uint64_t	m_iValue;
};

#endif
