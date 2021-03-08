#pragma once
#include "IPackets.h"
#include <vector>
#include <string.h>

typedef struct tagCanMessage {
	struct {
		time_t tv_sec;
		uint32_t tv_nsec;
	} t; /* time stamp */
	uint8_t   bus;     /* can bus */
	uint32_t  id;      /* numeric CAN-ID */
	uint8_t   dlc;
	uint8_t   byte_arr[8];
	uint8_t   flag;	  /* determine the state of the can msg,0-the msg is send now, 1-the msg was previously send*/
	tagCanMessage()
	{
		memset(&t, 0, sizeof(t));
		bus = 0;
		id = 0;
		dlc = 0;
		memset(byte_arr, 0, sizeof(byte_arr));
		flag = 0;
	}
} canMessage_t;

namespace Packets
{
	PACKET_DECLARATION_BEGIN(Hello)
		template<class Archive>
		void serialize(Archive &ar)
		{
			Prologue(ar);
			ar(a, b, c, d);
			Epilogue(ar);
		}

		uint8_t a;
		uint16_t b;
		uint32_t c;
		uint64_t d;
	PACKET_DECLARATION_END


	PACKET_DECLARATION_BEGIN(Reissue)
 		template<class Archive>
 		bool Prologue(Archive &ar)
 		{
 			if (ar.IsWrite())
 			{
 				m_length = GetLength();
 			}
 			ar(m_prefix, (uint8_t)m_typeid, m_length);
 			return true;
 		}

		template<class Archive>
		void serialize(Archive &ar)
		{
			Prologue(ar);
			if (ar.IsRead())
			{
				ar & m_iFlag & m_oDateTime & m_iStatus & m_iLong & m_iLat;
				uint32_t count = 1;
				uint32_t len = get_length(m_oDateTime, m_iLong, m_iLat, m_iStatus, m_iFlag) + BASIC_LENGTH+1;
				while (m_length - len >= count*10 )
				{
					canMessage_t e;
					ar & (*(uint16_t*)&e.id) & e.byte_arr;
					m_vCanDate.push_back(e);
					count++;
				}
			}
			else if (ar.IsWrite())
			{
				ar & m_iFlag & m_oDateTime & m_iStatus & m_iLong & m_iLat;
				for (auto e: m_vCanDate)
				{
					ar & (*(uint16_t*)&e.id) & e.byte_arr;
				}
			}
			Epilogue(ar);
		}


		uint8_t			m_oDateTime[6];
		//经纬度
		uint32_t		m_iLong;//经度
		uint32_t		m_iLat; //纬度
		uint8_t			m_iStatus;
		uint8_t			m_iFlag;
		vector<canMessage_t> m_vCanDate;
	PACKET_DECLARATION_END

}