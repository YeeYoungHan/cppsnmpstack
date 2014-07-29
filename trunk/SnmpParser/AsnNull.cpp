#include "AsnNull.h"

CAsnNull::CAsnNull()
{
	m_cType = ASN_TYPE_NULL;
}

CAsnNull::~CAsnNull()
{
}

int CAsnNull::ParsePacket( const char * pszPacket, int iPacketLen )
{
	m_cType = pszPacket[0];

	return 2;
}

int CAsnNull::MakePacket( char * pszPacket, int iPacketSize )
{
	pszPacket[0] = m_cType;
	pszPacket[1] = 0;

	return 2;
}

CAsnType * CAsnNull::Copy( )
{
	CAsnNull * pclsValue = new CAsnNull();
	if( pclsValue == NULL ) return NULL;

	pclsValue->m_cType = m_cType;

	return pclsValue;
}
