#include "protocol.h"


PACKET_IMPEMENTION_BEGIN(Hello, ePacketTypeId::eHello)
uint32_t Hello::GetLength() {
#pragma message("22222222222222")
	return get_length(a, b, c, d) + BASIC_LENGTH;
}
PACKET_IMPEMENTION_END(Hello)


PACKET_IMPEMENTION_BEGIN(Reissue, ePacketTypeId::eReissue)
uint32_t Reissue::GetLength() {
	return get_length(m_oDateTime, m_iLong, m_iLat, m_iStatus, m_iFlag) + m_vCanDate.size() * 10 + BASIC_LENGTH2;
}
PACKET_IMPEMENTION_END(Reissue)


//REGISTER_POLYMORPHIC_RELATION(base, Hello)
//REGISTER_TYPE(Hello)
//
//REGISTER_POLYMORPHIC_RELATION(base, Packets::Reissue)
//REGISTER_TYPE(Packets::Reissue)