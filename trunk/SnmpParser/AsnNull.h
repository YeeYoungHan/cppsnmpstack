#ifndef _ASN_NULL_H_
#define _ASN_NULL_H_

#include "AsnType.h"

class CAsnNull : public CAsnType
{
public:
	CAsnNull();
	~CAsnNull();

	int ParsePacket( const char * pszPacket, int iPacketLen );
	int MakePacket( char * pszPacket, int iPacketSize );
};

#endif
