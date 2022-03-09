#pragma once
#include <iostream>
#include <string.h>
#include <string>
#include <list>
#include <map>
#include <vector>
#include <queue>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <sstream> // std::stringstream
#include "Log.h"
using namespace std;

typedef char CHAR;
typedef signed char INT8;
typedef unsigned char UCHAR;
typedef unsigned char UINT8;
typedef unsigned char BYTE;
typedef short SHORT;
typedef signed short INT16;
typedef unsigned short USHORT;
typedef unsigned short UINT16;
typedef unsigned short WORD;
typedef int INT;
typedef signed int INT32;
typedef unsigned int UINT;
typedef unsigned int UINT32;
typedef long LONG;
typedef unsigned long ULONG;
typedef unsigned long DWORD;
typedef __int64 LONGLONG;
typedef __int64 LONG64;
typedef signed __int64 INT64;
typedef unsigned __int64 ULONGLONG;
typedef unsigned __int64 DWORDLONG;
typedef unsigned __int64 ULONG64;
typedef unsigned __int64 DWORD64;
typedef unsigned __int64 UINT64;

/** @brief 返回值(成功)																	*/
#define RET_SUCCESS (0)

/** @brief 返回值(失败)																	*/
#define RET_FAIL (-1)

#define FREE_PTR(x)    \
	{                  \
		if (NULL != x) \
		{              \
			delete x;  \
			x = NULL;  \
		}              \
	}

#define FREE_ARR(x)     \
	{                   \
		if (NULL != x)  \
		{               \
			delete[] x; \
			x = NULL;   \
		}               \
	}

#define _HTONS(x) ((((UINT16)(x)&0xff00) >> 8) | (((UINT16)(x)&0xff) << 8))
#define _HTONL(x) (((UINT32)(x) >> 24) | (((UINT32)(x)&0xff0000) >> 8) | (((UINT32)(x)&0xff) << 24) | (((UINT32)(x)&0xff00) << 8))

//日志输出
#define LOG CLog::GetInstance().OutPutLog
#define LOGERR(x) CLog::GetInstance().OutPutLog("[%s %d] %s\n", __FUNCTION__, __LINE__, x)
#define LOGERR2(x, y) CLog::GetInstance().OutPutLog("[%s %d] %s %s\n", __FUNCTION__, __LINE__, x, y)
#define LOGSYSERR CLog::GetInstance().OutPutLog("[%s %d] error:%d\n", __FUNCTION__, __LINE__, GetLastError())

//数据转换为16进制格式打印
#define LOGHEX(data, len) CLog::GetInstance().OutPutLogHex(data, len, __FUNCTION__, __LINE__)

/**
 * @brief eCommandType
 *		命令表示类型
 */
enum eCommandType
{
	eLogin = 0x01,	   /*车辆登入*/
	eRealtimeData,	   /*实时数据*/
	eReissueData,	   /*补发数据*/
	eLogout,		   /*车辆登出*/
	eHeartbeat = 0x07, /*心跳数据*/
	eTerminalTiming,   /*终端校时*/
};

/**
 * @brief eDataType
 *		数据类型
 */
enum eDataType
{
	eBegin = 0x00,
	eVehicle = 0x01, /*整车数据*/
	eDrivingMotor,	 /*驱动电机数据*/
	eFuelCell,		 /*燃料电池数据*/
	eEngine,		 /*发动机数数据*/
	eVehiclePos,	 /*车辆位置*/
	eExtremum,		 /*极值数据*/
	eAlarmInfo,		 /*报警数据*/
	eVoltage,		 /*充电储能装置电压*/
	eTemperature,	 /*充电储能装置温度*/
	eEnd,
};

/**
 * @brief eResponseType
 *		命令表示类型
 */
enum eResponseType
{
	eSuccess = 0x01, /*接受信息正确*/
	eFailure,		 /*设置未成功*/
	eVinRepeat,		 /*vin重复错误*/
	eCommand,		 /*表示数据包围命令包，而非应答包*/
};

#pragma pack(push, 1) //作用：是指把原来对齐方式设置压栈，并设新的对齐方式设置为一个字节对齐

/**
 * @brief StruHDR
 *		上报平台的24个字节数据头
 */
typedef struct tagStruHDR
{
	//起始符
	BYTE m_StartCode[2];
	//命令标识
	BYTE m_CommandCode;
	//应答标识
	BYTE m_ResponsCode;
	// VIN
	BYTE m_Vin[17];
	//加密方式
	BYTE m_Encryption;
	//数据长度
	WORD m_Len;
} StruHDR, *LPStruHDR;

/**
 * @brief StruVehicle
 *		整车数据
 */
typedef struct tagStruVehicle
{
	//车辆状态
	BYTE m_VehicleState; /*0x01:车辆启动;0x02:熄火;0x03:其它状态;0xFE:异常;0xFF:无效*/
	//充电状态
	BYTE m_ChargeState; /*0x01:停车充电;0x02:行驶充电;0x03:未充电状态;0x04:充电完成;0xFF:无效*/
	//运行模式
	BYTE m_DrivingMode; /*0x01:纯电;0x02:混动;0x03:燃油;0xFE:异常;0xFF:无效*/
	//车速
	WORD m_Speed;
	//里程
	DWORD m_Mileage;
	//总电压
	WORD m_Voltage;
	//总电流
	WORD m_Current;
	// SOC
	BYTE m_Soc;
	// DC状态
	BYTE m_DCState;
	//档位
	BYTE m_Gear;
	//绝缘电阻
	WORD m_Resistance;
	//加速踏板行程值
	BYTE m_AcceleratorPedalValue;
	//制动踏板
	BYTE m_BreakPedal;
} StruVehicle, *LPStruVehicle;

/**
 * @brief StruMotor
 *		驱动电机数据
 */
typedef struct tagStruMotor
{
	//电机序列号
	BYTE m_Seq;
	//电机状态 0x01:耗电,0x02:发电,0x03关闭状态，0x04:准备状态，0xFE:异常，0xFF:无效
	BYTE m_State;
	//电机控制温度
	BYTE m_ControlTemperature;
	//电机转速
	WORD m_RotateSpeed;
	//电机扭矩
	WORD m_Torque;
	//电机温度
	BYTE m_Temperature;
	//电机控制器输入电压
	WORD m_InputVoltage;
	//电机控制器直流母线电流
	WORD m_Current;
} StruMotor, *LPStruMotor;

/**
 * @brief StruDrivingMotor
 *		驱动电机数据
 */
typedef struct tagStruDrivingMotor
{
	//驱动电机个数
	BYTE m_Num;
	//单个驱动电机集
	vector<StruMotor> m_pElment;
} StruDrivingMotor, *LPStruDrivingMotor;

/**
 * @brief StruFuelCell
 *		燃料电池数据
 */
typedef struct tagStruFuelCell
{
	//燃料电池电压
	WORD m_Voltage;
	//燃料电池电流
	WORD m_Current;
	//燃料消耗
	WORD m_Consumption;
	//燃料电池温度探针总数 N 范围:0~65531
	WORD m_ProbeSum;
	//探针温度值 1*N
	vector<BYTE> m_ProbeTempVec;
	//氢系统中最高温度 范围：0～2400
	WORD m_MaxTemperature;
	//氢系统中最高温度探针代号
	BYTE m_TempProbeNo;
	//氢系统中最高浓度
	WORD m_MaxDensity;
	//氢系统中最高浓度传感器代号
	BYTE m_DenProbeNo;
	//氢系统中最高压力
	WORD m_MaxPressure;
	//氢系统中最高压力传感器代号
	BYTE m_PresProbeNo;
	//高压 DC/DC状态
	BYTE m_DCState;
} StruFuelCell, *LPStruFuelCell;

/**
 * @brief StruEngine
 *		发动机数据
 */
typedef struct tagStruEngine
{
	//发动机状态 0x01:启动状态,0x02:关闭状态,0xFE:异常，0xFF:无效
	BYTE m_State;
	//曲轴速度
	WORD m_CrankSpeed;
	//燃油消耗率
	WORD m_FuelConsumptionRate;
} StruEngine, *LPStruEngine;

/**
 * @brief StruVehiclePos
 *		车辆位置数据格式
 */
typedef struct tagStruVehiclePos
{
	//定位状态
	BYTE m_State;
	//经度
	DWORD m_Longitude;
	//纬度
	DWORD m_Latitude;
} StruVehiclePos, *LPStruVehiclePos;

/**
 * @brief StruExtremum
 *		极值数据格式
 */
typedef struct tagStruExtremum
{
	//最高电压电池子系统号
	BYTE m_MaxVolSubsystemNo;
	//最高电压电池单体代号
	BYTE m_MaxVolBatteryNo;
	//电池单体电压最高值
	WORD m_MaxVoltage;
	//最低电压电池子系统号
	BYTE m_MinVolSubsystemNo;
	//最低电压电池单体代号
	BYTE m_MinVolBatteryNo;
	//电池单体电压最低值
	WORD m_MinVoltage;
	//最高温度子系统号
	BYTE m_MaxTempSubsystemNo;
	//最高温度探针序号
	BYTE m_MaxTempProbeNo;
	//最高温度值
	BYTE m_MaxTemperature;
	//最低温度子系统号
	BYTE m_MinTempSubsystemNo;
	//最低温度探针序号
	BYTE m_MinTempProbeNo;
	//最低温度值
	BYTE m_MinTemperature;

} StruExtremum, *LPStruExtremum;

/**
 * @brief StruFaultData
 *		错误报文数据
 */
typedef struct tagStruFaultData
{
	WORD m_ErrorCode;
	WORD m_Canid;
	BYTE m_RawPacket[8];
} StruFaultData, *LPStruFaultData;

/**
 * @brief StruAlarmInfo
 *		报警数据格式
 */
typedef struct tagStruAlarmInfo
{
	//报警最高等级
	BYTE m_MaxAlarmLevel;
	//通用报警标志
	DWORD m_ComAlarmMark;
	//可充电储能装置故障总数 N1
	BYTE m_ChargeKitFaultSum;
	//可充电储能装置故障代码列表 4*N1
	vector<StruFaultData> m_ChargeKitFaultCodeList;
	//驱动电机故障总数 N2
	BYTE m_MotorFaultSum;
	//驱动电机故障总数故障代码列表 4*N2
	vector<StruFaultData> m_MotorFaultCodeList;
	//发动机故障总数 N3
	BYTE m_EngineFaultSum;
	//发动机故障总数故障代码列表 4*N3
	vector<DWORD> m_EngineFaultCodeList;
	//其它故障总数 N4
	BYTE m_OhterFaultSum;
	//发动机故障总数故障代码列表 4*N4
	vector<StruFaultData> m_OtherFaultCodeList;

} StruAlarmInfo, *LPStruAlarmInfo;

/**
 * @brief StruSubVoltage
 *		充电储能子系统电压数据格式
 */
typedef struct tagStruSubVoltage
{
	//序号
	BYTE m_Sequence;
	//充电储能装置电压
	WORD m_Voltage;
	//充电储能装置电流
	WORD m_Current;
	//单体电池总数
	WORD m_BatterySum;
	//本帧起始电池序号
	WORD m_FrameBatterySeq;
	//本帧单体电池总数 m(hex),范围：1-200
	BYTE m_FrameBatterySum;
	//单体电池电压	2*m,范围：0V～60.000V
	vector<WORD> m_pSingleBatteryVoltage;
} StruSubVoltage, *LPStruSubVoltage;

/**
 * @brief StruVoltage
 *		充电储能装置电压数据格式
 */
typedef struct tagStruVoltage
{
	//子系统个数
	BYTE m_Num;
	//单个子系统集
	vector<StruSubVoltage> m_pElment;
} StruVoltage, *LPStruVoltage;

/**
 * @brief StruSubTemperature
 *		充电储能子系统温度数据格式
 */
typedef struct tagStruSubTemperature
{
	//序号
	BYTE m_Sequence;
	//充电储能温度探针个数 N(hex)
	WORD m_ProbeNum;
	//充电储能子系统各温度探针检测到的温度值 N
	vector<BYTE> m_TemperatureVec;
} StruSubTemperaturea, *LPStruSubTemperature;

/**
 * @brief StruTemperature
 *		充电储能装置温度数据格式
 */
typedef struct tagStruTemperature
{
	//子系统个数
	BYTE m_Num;
	//命令标识
	vector<StruSubTemperaturea> m_pElment;
} StruTemperature, *LPStruTemperature;

/**
 * @brief StruDate
 *		时间信息
 */
typedef struct tagStruDate
{
	//年
	BYTE m_Year;
	//月
	BYTE m_Mon;
	//日
	BYTE m_Day;
	//时
	BYTE m_Hour;
	//分
	BYTE m_Min;
	//秒
	BYTE m_Sec;
} StruDate, *LPStruDate;

/**
 * @brief StruVehicleLogin
 *		车辆登入数据格式
 */
typedef struct tagStruVehicleLogin
{
	//数据采集时间
	BYTE m_Time[6];
	//登入流水号
	WORD m_Seq;
	// ICCID
	BYTE m_IccId[20];
	//可充电储能子系统个数 n 0～250
	BYTE m_SubSystemCount;
	//可充电储能子系统编码长度 m 范围0～50
	BYTE m_CodeLen;
	//可充电储能子系统编码 n*m
	vector<BYTE> m_Code;
} StruVehicleLogin, *LPStruVehicleLogin;

#pragma pack(pop) //作用：恢复对齐状态

class CUtility
{
public:
	// transform strings to hex
	static bool ConvertStr2Hex(const unsigned char *in, int ilen, string &out)
	{
		if (ilen == 0 || in == NULL)
		{
			return false;
		}
		std::stringstream ss;
		for (int i = 0; i < ilen; i++)
		{
			//字符转换成16进制存放在ss中
			ss << std::hex << (in[i] >> 4) << (in[i] & 0x0f);
		}
		ss >> out;
		return true;
	}
	// transform hex to strings
	static bool ConvertHex2Str(const unsigned char *in, int ilen, string &out)
	{
		if (ilen == 0 || ilen % 2 != 0 || in == NULL)
		{
			return false;
		}
		out.resize(ilen / 2);
		std::stringstream s1;
		int temp = 0;
		for (int i = 0; i < ilen; i += 2)
		{
			//字符转换成16进制存放在ss中
			s1 << std::hex << in[i] << in[i + 1];
			//将16进制字符重定向到int数据中
			s1 >> temp;
			s1.clear();
			//字符串保存数据
			out[i / 2] = temp;
		}
		return true;
	}
};
#if 1
#define DELEGATE
#else
#define GB32960
#endif
