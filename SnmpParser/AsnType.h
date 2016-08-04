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

#ifndef _ASN_TYPE_H_
#define _ASN_TYPE_H_

#include "SnmpPlatformDefine.h"
#include <string>

#define ASN_TYPE_BOOL					0x01
#define ASN_TYPE_INT					0x02
#define ASN_TYPE_BIT_STR			0x03
#define ASN_TYPE_OCTET_STR		0x04
#define ASN_TYPE_NULL					0x05
#define ASN_TYPE_OID					0x06
#define ASN_TYPE_SEQUENCE			0x10
#define ASN_TYPE_CONSTRUCTOR	0x20

#define ASN_TYPE_COMPLEX				0x30
#define ASN_TYPE_COUNTER_32			0x41
#define ASN_TYPE_GAUGE_32				0x42
#define ASN_TYPE_TIMETICKS			0x43
#define ASN_TYPE_COUNTER_64			0x46
#define ASN_TYPE_NO_SUCH_OBJECT	0x80
#define ASN_TYPE_NO_SUCH_INSTANCE	0x81

/**
 * @ingroup SnmpParser
 * @brief ASN 타입 클래스의 root 클래스
 */
class CAsnType
{
public:
	virtual ~CAsnType(){ };

	uint8_t		m_cType;
	uint32_t	m_iLen;

	virtual int ParsePacket( const char * pszPacket, int iPacketLen ) = 0;
	virtual int MakePacket( char * pszPacket, int iPacketSize ) = 0;
	virtual CAsnType * Copy( ) = 0;

	virtual bool GetInt( uint32_t & iValue );
	virtual bool GetLong( uint64_t & iValue );
	virtual bool GetString( std::string & strValue );

	int ParseHeader( const char * pszPacket, int iPacketLen );
	int SetHeaderLength( char * pszPacket, int iPacketSize, int iLength );

	static int ParseInt( const char * pszPacket, int iPacketLen, uint8_t cLength, uint32_t & iValue );
	static int SetInt( uint8_t * pszPacket, int iPacketLen, uint32_t iValue );
};

#endif
