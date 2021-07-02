#include "Protoco.h"
#include "tinyxml.h"

CBase::CBase(eDataType type)
{
	m_type = type;
	m_buf = NULL;
	m_len = 0;
}

CBase::~CBase()
{
	FREE_PTR(m_buf);
}

eDataType CBase::GetType()
{
	return m_type;
}
unsigned char* CBase::Serialize(BYTE* buf, UINT len) { return NULL; }
int CBase::UnSerialize(BYTE* buf, UINT len) 
{ 
	if (buf == NULL || len == 0)
	{
		return RET_FAIL;
	}
	m_len = len + 1;
	m_buf = new BYTE[m_len + 1];
	m_buf[0] = (BYTE)m_type;
	if (m_buf)
	{
		memcpy(m_buf + 1, buf, len);
	}
	return RET_FAIL; 
}

/**
* @brief CVehicle类描述
*	整车数据
*/
CVehicle::CVehicle():CBase(eVehicle) {}
CVehicle::~CVehicle() {}
unsigned char* CVehicle::Serialize(BYTE* buf, UINT len) 
{
	return buf;
}
int CVehicle::UnSerialize(BYTE* buf, UINT len) 
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_vehicle))
	{
		LOGERR("param error!");
	}
	memcpy(&m_vehicle, buf, sizeof(StruVehicle));
	m_vehicle.m_Mileage = _HTONL(m_vehicle.m_Mileage);
	m_vehicle.m_Voltage = _HTONS(m_vehicle.m_Voltage);
	m_vehicle.m_Current = _HTONS(m_vehicle.m_Current); 
	m_vehicle.m_Speed = _HTONS(m_vehicle.m_Speed);
	m_vehicle.m_Resistance = _HTONS(m_vehicle.m_Resistance);
	offset = sizeof(StruVehicle);
	CBase::UnSerialize(buf, offset);
	return offset;
}


/**
* @brief CDrivingMotor类描述
*	驱动电机数据
*/
CDrivingMotor::CDrivingMotor():CBase(eDrivingMotor) {}
CDrivingMotor::~CDrivingMotor() {}
unsigned char* CDrivingMotor::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CDrivingMotor::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_drivermotor))
	{
		LOGERR("param error!");
	}
	//获取电机个数
	memcpy(&m_drivermotor.m_Num, buf, sizeof(m_drivermotor.m_Num));
	offset += sizeof(m_drivermotor.m_Num);
	for (int i = 0; i < m_drivermotor.m_Num; i++)
	{
		StruMotor motor;
		memcpy(&motor, buf + offset, sizeof(motor));
		offset += sizeof(motor);
		m_drivermotor.m_pElment.push_back(motor);
	}
	CBase::UnSerialize(buf, offset);
	return offset;
}

/**
* @brief CFuelCell类描述
*	燃料电池数据
*/
CFuelCell::CFuelCell():CBase(eFuelCell) {}
CFuelCell::~CFuelCell() {}
unsigned char* CFuelCell::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CFuelCell::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_fuelcell))
	{
		LOGERR("param error!");
	}
	memcpy(&m_fuelcell.m_Voltage, buf + offset, int(&m_fuelcell.m_ProbeTempVec) - int(&m_fuelcell.m_Voltage));
	offset += int(&m_fuelcell.m_ProbeTempVec) - int(&m_fuelcell.m_Voltage);
	m_fuelcell.m_ProbeSum = _HTONS(m_fuelcell.m_ProbeSum);
	for (int i = 0; i < m_fuelcell.m_ProbeSum; i++)
	{
		BYTE ProbeTemp;
		memcpy(&ProbeTemp, buf + offset, sizeof(ProbeTemp));
		offset += sizeof(ProbeTemp);
		m_fuelcell.m_ProbeTempVec.push_back(ProbeTemp);
	}
	memcpy(&m_fuelcell.m_MaxTemperature, buf + offset, int(&m_fuelcell.m_DCState) - int(&m_fuelcell.m_MaxTemperature) + 1);
	offset += int(&m_fuelcell.m_DCState) - int(&m_fuelcell.m_MaxTemperature) + 1;
	m_fuelcell.m_MaxDensity = _HTONS(m_fuelcell.m_MaxDensity);
	m_fuelcell.m_MaxTemperature = _HTONS(m_fuelcell.m_MaxTemperature);

	CBase::UnSerialize(buf, offset);
	return offset;
}


/**
* @brief CEngine类描述
*	发动机数据
*/
CEngine::CEngine() :CBase(eEngine) {}
CEngine::~CEngine() {}
unsigned char* CEngine::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CEngine::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_engin))
	{
		LOGERR("param error!");
	}
	memcpy(&m_engin, buf, sizeof(StruEngine));
	offset = sizeof(StruEngine);
	CBase::UnSerialize(buf, offset);
	return sizeof(StruEngine);
}

/**
* @brief CVehiclePos类描述
*	车辆位置数据格式
*/
CVehiclePos::CVehiclePos() :CBase(eVehiclePos) {}
CVehiclePos::~CVehiclePos() {}
unsigned char* CVehiclePos::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CVehiclePos::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_vehiclePos))
	{
		LOGERR("param error!");
	}
	memcpy(&m_vehiclePos, buf, sizeof(StruVehiclePos));
	m_vehiclePos.m_Longitude = _HTONL(m_vehiclePos.m_Longitude);
	m_vehiclePos.m_Latitude = _HTONL(m_vehiclePos.m_Latitude);
	offset = sizeof(StruVehiclePos);
	CBase::UnSerialize(buf, offset);
	return sizeof(StruVehiclePos);
}

/**
* @brief CExtremum类描述
*	极值数据格式
*/
CExtremum::CExtremum() :CBase(eExtremum) {}
CExtremum::~CExtremum() {}
unsigned char* CExtremum::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CExtremum::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_extremum))
	{
		LOGERR("param error!");
	}
	memcpy(&m_extremum, buf, sizeof(StruExtremum));
	offset = sizeof(StruExtremum);
	CBase::UnSerialize(buf, offset);
	return sizeof(StruExtremum);
}

/**
* @brief CAlarmInfo类描述
*	报警数据格式
*/
CAlarmInfo::CAlarmInfo() :CBase(eAlarmInfo) {}
CAlarmInfo::~CAlarmInfo() {}
unsigned char* CAlarmInfo::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CAlarmInfo::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_alarmInfo))
	{
		LOGERR("param error!");
	}
// 	m_alarmInfo.m_MaxAlarmLevel = buf[offset];
// 	offset += sizeof(BYTE);
// 	m_alarmInfo.m_ComAlarmMark = _HTONL(*(DWORD*)(buf+offset));
// 	offset += sizeof(DWORD);
// 	m_alarmInfo.m_ChargeKitFaultSum = buf[offset];
// 	offset += sizeof(BYTE);
	memcpy(&m_alarmInfo.m_MaxAlarmLevel, buf + offset, int(&m_alarmInfo.m_ChargeKitFaultCodeList) - int(&m_alarmInfo.m_MaxAlarmLevel));
	offset += int(&m_alarmInfo.m_ChargeKitFaultCodeList) - int(&m_alarmInfo.m_MaxAlarmLevel);
	m_alarmInfo.m_ComAlarmMark = _HTONL(m_alarmInfo.m_ComAlarmMark);
	for (int i = 0; i < m_alarmInfo.m_ChargeKitFaultSum / 3; i++)
	{
		StruFaultData data;
		memcpy(&data, buf + offset, sizeof(data));
		data.m_Canid = _HTONS(data.m_Canid);
		data.m_ErrorCode = _HTONS(data.m_ErrorCode);
		m_alarmInfo.m_ChargeKitFaultCodeList.push_back(data);
		offset += sizeof(data);
	}
	memcpy(&m_alarmInfo.m_MotorFaultSum, buf + offset, sizeof(m_alarmInfo.m_MotorFaultSum));
	offset += sizeof(m_alarmInfo.m_MotorFaultSum);
	for (int i = 0; i < m_alarmInfo.m_MotorFaultSum / 3; i++)
	{
		StruFaultData data;
		memcpy(&data, buf + offset, sizeof(data));
		data.m_Canid = _HTONS(data.m_Canid);
		data.m_ErrorCode = _HTONS(data.m_ErrorCode);
		m_alarmInfo.m_MotorFaultCodeList.push_back(data);
		offset += sizeof(data);
	}
	memcpy(&m_alarmInfo.m_EngineFaultSum, buf + offset, sizeof(m_alarmInfo.m_EngineFaultSum));
	offset += sizeof(m_alarmInfo.m_EngineFaultSum);
	for (int i = 0; i < m_alarmInfo.m_EngineFaultSum; i++)
	{
		DWORD dwEngineFaultSum;
		memcpy(&dwEngineFaultSum, buf + offset, sizeof(dwEngineFaultSum));
		dwEngineFaultSum = _HTONL(dwEngineFaultSum);
		m_alarmInfo.m_EngineFaultCodeList.push_back(dwEngineFaultSum);
		offset += sizeof(dwEngineFaultSum);
	}
	memcpy(&m_alarmInfo.m_OhterFaultSum, buf + offset, sizeof(m_alarmInfo.m_OhterFaultSum));
	offset += sizeof(m_alarmInfo.m_OhterFaultSum);
	for (int i = 0; i < m_alarmInfo.m_OhterFaultSum / 3; i++)
	{
		StruFaultData data;
		memcpy(&data, buf + offset, sizeof(data));
		data.m_Canid = _HTONS(data.m_Canid);
		data.m_ErrorCode = _HTONS(data.m_ErrorCode);
		m_alarmInfo.m_OtherFaultCodeList.push_back(data);
		offset += sizeof(data);
	}

	CBase::UnSerialize(buf, offset);
	return offset;
}

/**
* @brief CVoltage类描述
*	充电储能装置电压数据格式
*/
CVoltage::CVoltage() :CBase(eVoltage) {}
CVoltage::~CVoltage() {}
unsigned char* CVoltage::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CVoltage::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_voltage))
	{
		LOGERR("param error!");
	}
	memcpy(&m_voltage.m_Num, buf, sizeof(m_voltage.m_Num));
	offset += sizeof(m_voltage.m_Num);
	for (int i = 0; i < m_voltage.m_Num; i++)
	{
		StruSubVoltage voltage;
		memcpy(&voltage.m_Sequence, buf + offset, int(&voltage.m_pSingleBatteryVoltage) - int(&voltage.m_Sequence));
		offset += int(&voltage.m_pSingleBatteryVoltage) - int(&voltage.m_Sequence);
		for (int j = 0; j < voltage.m_FrameBatterySum; j++)
		{
			WORD wSingleBatteryVoltage;
			memcpy(&wSingleBatteryVoltage, buf + offset, sizeof(wSingleBatteryVoltage));
			offset += sizeof(wSingleBatteryVoltage);
			wSingleBatteryVoltage = _HTONS(wSingleBatteryVoltage);
			voltage.m_pSingleBatteryVoltage.push_back(wSingleBatteryVoltage);
		}
		m_voltage.m_pElment.push_back(voltage);
	}
	CBase::UnSerialize(buf, offset);
	return offset;
}


/**
* @brief CTemperature类描述
*	充电储能装置温度数据格式
*/
CTemperature::CTemperature():CBase(eTemperature) {}
CTemperature::~CTemperature() {}
unsigned char* CTemperature::Serialize(BYTE* buf, UINT len)
{
	return buf;
}
int CTemperature::UnSerialize(BYTE* buf, UINT len)
{
	UINT offset = 0;
	if (buf == NULL || len < sizeof(m_temperature))
	{
		LOGERR("param error!");
	}
	memcpy(&m_temperature.m_Num, buf, sizeof(m_temperature.m_Num));
	offset += sizeof(m_temperature.m_Num);
	for (int i = 0; i < m_temperature.m_Num; i++)
	{
		StruSubTemperaturea temp;
		memcpy(&temp.m_Sequence, buf + offset, int(&temp.m_TemperatureVec) - int(&temp.m_Sequence));
		temp.m_ProbeNum = _HTONS(temp.m_ProbeNum);
		offset += int(&temp.m_TemperatureVec) - int(&temp.m_Sequence);
		for (int j = 0; j < temp.m_ProbeNum; j++)
		{
			BYTE Temperature;
			memcpy(&Temperature, buf + offset, sizeof(Temperature));
			offset += sizeof(Temperature);
			temp.m_TemperatureVec.push_back(Temperature);
		}
		m_temperature.m_pElment.push_back(temp);
	}
	CBase::UnSerialize(buf, offset);
	return offset;
}




CGBT32960PX37::CGBT32960PX37(){}
CGBT32960PX37::~CGBT32960PX37(){}

unsigned char* CGBT32960PX37::Serialize(BYTE* buf, UINT len)
{
	return NULL;
}


int CGBT32960PX37::Initialize()
{
	m_VehicleData[m_vehicle.GetType()] = &m_vehicle;
	m_VehicleData[m_motor.GetType()] = &m_motor;
	m_VehicleData[m_fuelcell.GetType()] = &m_fuelcell;
	m_VehicleData[m_engin.GetType()] = &m_engin;
	m_VehicleData[m_vehiclePos.GetType()] = &m_vehiclePos;
	m_VehicleData[m_extremum.GetType()] = &m_extremum;
	m_VehicleData[m_alarminfo.GetType()] = &m_alarminfo;
	m_VehicleData[m_voltage.GetType()] = &m_voltage;
	m_VehicleData[m_emperature.GetType()] = &m_emperature;
	return RET_SUCCESS;
}

int CGBT32960PX37::Destroy()
{
	m_VehicleData.clear();
	return RET_SUCCESS;
}

int CGBT32960PX37::CheckHDR(StruHDR hdr)
{
	//固定头
	if (hdr.m_StartCode[0] != 0x23 && hdr.m_StartCode[1] != 0x23)
	{
		return RET_FAIL;
	}
	//命令字只处理实时和历史数据
	if (hdr.m_CommandCode == eRealtimeData || hdr.m_CommandCode == eReissueData)
	{
		//应答标志为0xfe,加密方式为未加密1
		if (hdr.m_ResponsCode != 0xfe || hdr.m_Encryption != 0x01)
		{
			LOG("parse head failed,m_ResponsCode:%d, m_Encryption:%s\n", hdr.m_ResponsCode, hdr.m_ResponsCode);
			return RET_FAIL;
		}
	}
	else
	{
		LOG("parse head failed,m_CommandCode:%d\n", hdr.m_CommandCode);
		return RET_FAIL;
	}
	return RET_SUCCESS;
}


CBase *CGBT32960PX37::GetDataObject(eDataType type)
{
	return NULL;
}

//需要解析的数据都是大端数据，需要进行转化
int CGBT32960PX37::UnSerialize(BYTE* buf, UINT len)
{
	UINT32 offset = 0;
	if (NULL == buf || len < sizeof(StruHDR))
	{
		return RET_FAIL;
	}
	memcpy(&m_head, buf + offset, sizeof(StruHDR));
	offset += sizeof(StruHDR);
	if (CheckHDR(m_head) != RET_SUCCESS)
	{
		return RET_FAIL;
	}
	//获取时间信息
	memcpy(&m_time, buf + offset, sizeof(StruDate));
	offset += sizeof(StruDate);
	CBase *pBase = NULL;
	UINT16 datalen = 0;
	do 
	{
		//获取信息类型标志
		eDataType type = eBegin;
		memcpy(&type, buf + offset, 1);
		offset += 1;
		if (type >= eVehicle && type <= eTemperature)
		{
			pBase = m_VehicleData[type];
			if (pBase == NULL)
			{
				return RET_FAIL;
			}
			datalen = pBase->UnSerialize(buf + offset, len - offset);
			offset += datalen;
		}
		else
		{
			LOG("parse data failed,type:%d, offset:%d\n", type, offset);
			return RET_FAIL;
		}
	} while (len > offset);
	Save2Xml();
	return RET_SUCCESS;
}
bool CGBT32960PX37::Save2Xml()
{
	auto fn = [](const unsigned char *in, int ilen, string name,TiXmlElement *&child) {
		string content;
		CUtility::ConvertStr2Hex(in, ilen, content);
		if (content.length() > 0)
		{
			child->SetAttribute(name.c_str(), content.c_str());
		}
	};
	TiXmlDocument doc("Data.xml");
	if (!doc.LoadFile())
	{
		LOG("Could not load file . Error='%s'. Exiting.\n", doc.ErrorDesc());
		TiXmlDeclaration * decl = new TiXmlDeclaration("1.0", "utf-8", "");
		doc.LinkEndChild(decl);

		//创建根节点root
		TiXmlElement * root = new TiXmlElement("Data");
		
		//创建子节点
		TiXmlElement * child = new TiXmlElement("Data");
		fn(m_vehicle.m_buf, m_vehicle.m_len, "vehicle", child);
		fn(m_motor.m_buf, m_motor.m_len, "moto", child);
		fn(m_fuelcell.m_buf, m_fuelcell.m_len, "fuelcell", child);
		fn(m_engin.m_buf, m_engin.m_len, "engine", child);
		fn(m_extremum.m_buf, m_extremum.m_len, "extrem", child);
		fn(m_voltage.m_buf, m_voltage.m_len, "resvoltiage", child);
		fn(m_emperature.m_buf, m_emperature.m_len, "restemp", child);
		fn(m_alarminfo.m_buf, m_alarminfo.m_len, "alarm", child);
		//链接child为root的子节点
		root->LinkEndChild(child);
		doc.LinkEndChild(root);
	}
	else
	{
		TiXmlElement* child = doc.RootElement()->FirstChildElement();
		fn(m_vehicle.m_buf, m_vehicle.m_len, "vehicle", child);
		fn(m_motor.m_buf, m_motor.m_len, "moto", child);
		fn(m_fuelcell.m_buf, m_fuelcell.m_len, "fuelcell", child);
		fn(m_engin.m_buf, m_engin.m_len, "engine", child);
		fn(m_extremum.m_buf, m_extremum.m_len, "extrem", child);
		fn(m_voltage.m_buf, m_voltage.m_len, "resvoltiage", child);
		fn(m_emperature.m_buf, m_emperature.m_len, "restemp", child);
		fn(m_alarminfo.m_buf, m_alarminfo.m_len, "alarm", child);
	}
	doc.Print(stdout);
	doc.SaveFile("Data.xml");
	return RET_SUCCESS;
}