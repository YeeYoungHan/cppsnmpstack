#ifndef _ASN_COMPLEX_H_
#define _ASN_COMPLEX_H_

#include "AsnType.h"
#include <list>

typedef std::list< CAsnType * > ASN_TYPE_LIST;

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
	bool AddOid( const char * pszValue );
	bool AddNull( );
	bool AddComplex( CAsnComplex * pclsValue );
	bool AddValue( CAsnType * pclsValue );

	void Clear();

	ASN_TYPE_LIST m_clsList;
};

#endif
