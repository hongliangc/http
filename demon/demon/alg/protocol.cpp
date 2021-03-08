#include "protocol.h"
namespace Packets
{
	PACKET_IMPEMENTION_BEGIN(Hello, ePacketTypeId::eHello)
		uint32_t Hello::GetLength() {
			#pragma message("22222222222222")
			return get_length(a, b, c, d) + BASIC_LENGTH;
	}
	PACKET_IMPEMENTION_END


	PACKET_IMPEMENTION_BEGIN(Reissue, ePacketTypeId::eReissue)
		uint32_t Reissue::GetLength() {
		return get_length(m_oDateTime, m_iLong, m_iLat, m_iStatus, m_iFlag) + m_vCanDate.size()*10 + BASIC_LENGTH + 1;
	}
	PACKET_IMPEMENTION_END
}