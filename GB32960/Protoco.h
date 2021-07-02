#pragma once
#include "Common.h"


/**
* @brief CBase类描述
*	GBT32960协议基类
*/
class CBase
{
public:
	CBase(eDataType type);
	~CBase();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
	virtual eDataType GetType();
public:
	eDataType m_type;
	BYTE* m_buf;
	UINT m_len;
};


/**
* @brief CVehicle类描述
*	整车数据
*/
class CVehicle : public CBase
{
public:
	CVehicle();
	~CVehicle();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//整车数据
	StruVehicle			m_vehicle;
};


/**
* @brief CDrivingMotor类描述
*	驱动电机数据
*/
class CDrivingMotor : public CBase
{
public:
	CDrivingMotor();
	~CDrivingMotor();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//驱动电机数据
	StruDrivingMotor	m_drivermotor;
};


/**
* @brief CFuelCell类描述
*	燃料电池数据
*/
class CFuelCell : public CBase
{
public:
	CFuelCell();
	~CFuelCell();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//燃料电池数据
	StruFuelCell		m_fuelcell;
};

/**
* @brief CEngine类描述
*	发动机数据
*/
class CEngine : public CBase
{
public:
	CEngine();
	~CEngine();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//发动机数据
	StruEngine			m_engin;
};

/**
* @brief CVehiclePos类描述
*	车辆位置数据格式
*/
class CVehiclePos : public CBase
{
public:
	CVehiclePos();
	~CVehiclePos();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//车辆位置数据格式
	StruVehiclePos		m_vehiclePos;
};

/**
* @brief CExtremum类描述
*	极值数据格式
*/
class CExtremum : public CBase
{
public:
	CExtremum();
	~CExtremum();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//极值数据格式
	StruExtremum		m_extremum;
};

/**
* @brief CAlarmInfo类描述
*	报警数据格式
*/
class CAlarmInfo : public CBase
{
public:
	CAlarmInfo();
	~CAlarmInfo();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//报警数据格式
	StruAlarmInfo		m_alarmInfo;
};

/**
* @brief CVoltage类描述
*	充电储能装置电压数据格式
*/
class CVoltage : public CBase
{
public:
	CVoltage();
	~CVoltage();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//充电储能装置电压数据格式
	StruVoltage		m_voltage;
};


/**
* @brief CTemperature类描述
*	充电储能装置温度数据格式
*/
class CTemperature : public CBase
{
public:
	CTemperature();
	~CTemperature();
public:
	virtual unsigned char* Serialize(BYTE* buf, UINT len);
	virtual int UnSerialize(BYTE* buf, UINT len);
public:
	//充电储能装置温度数据格式
	StruTemperature		m_temperature;
};

/**
* @brief CGBT32960PX37类描述
*	x37上报数据
*/
class CGBT32960PX37
{
public:
	CGBT32960PX37();
	~CGBT32960PX37();
public:
	int Initialize();
	int Destroy();
	int CheckHDR(StruHDR hdr);
	CBase *GetDataObject(eDataType type);
	unsigned char* Serialize(BYTE* buf, UINT len);
	int UnSerialize(BYTE* buf, UINT len);

	bool Save2Xml();
public:
	map<eDataType, CBase*>	m_VehicleData;
public:
	//通用头
	StruHDR					m_head;
	//时间
	StruDate				m_time;
	//整车数据
	CVehicle				m_vehicle;
	//驱动电机数据
	CDrivingMotor			m_motor;
	//燃料电池数据
	CFuelCell				m_fuelcell;
	//发动机数据
	CEngine					m_engin;
	//车辆位置数据格式
	CVehiclePos				m_vehiclePos;
	//极值数据格式
	CExtremum				m_extremum;
	//报警数据格式
	CAlarmInfo				m_alarminfo;
	//充电储能装置电压数据格式
	CVoltage				m_voltage;
	//充电储能装置温度数据格式
	CTemperature			m_emperature;
};

