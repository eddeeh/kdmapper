#pragma once
#include <Windows.h>
#include <string>

namespace service
{
	bool RegisterAndStart(const std::string &driver_name, const std::string &driver_path);
	bool StopAndRemove(const std::string &driver_name);
};