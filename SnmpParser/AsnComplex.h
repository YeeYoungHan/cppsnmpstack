#ifndef _ASN_COMPLEX_H_
#define _ASN_COMPLEX_H_

#include "AsnType.h"
#include <list>

typedef std::list< CAsnType * > ASN_TYPE_LIST;

class CAsnComplex : public CAsnType
{
public:
	CAsnComplex();
	~CAsnComplex();

	virtual int ParsePacket( const char * pszPacket, int iPacketLen );
	virtual int MakePacket( char * pszPacket, int iPacketSize );

	void Clear();

	ASN_TYPE_LIST m_clsList;
};

#endif
