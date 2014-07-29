#ifndef _ASN_NULL_H_
#define _ASN_NULL_H_

#include "AsnType.h"

class CAsnNull : public CAsnType
{
public:
	CAsnNull();
	virtual ~CAsnNull();

	virtual int ParsePacket( const char * pszPacket, int iPacketLen );
	virtual int MakePacket( char * pszPacket, int iPacketSize );
	virtual CAsnType * Copy( );
};

#endif
