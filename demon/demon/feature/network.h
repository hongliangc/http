#pragma once
#include "common.h"

class FEATURE_API CNetWork
{
public:
	CNetWork();
	~CNetWork();
public:
	bool Socket(_In int af, _In int type, _In int protocol);
};