#pragma once
#include <Windows.h>
#include <stdint.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>

#include "portable_executable.hpp"
#include "utils.hpp"
#include "nt.hpp"
#include "intel_driver.hpp"

class KernelDriverMapper
{
public:
	bool Initialize();
	~KernelDriverMapper();
public:
	uint64_t MapDriver(const std::string &driver_path);
private:
	void RelocateImageByDelta(portable_executable::vec_relocs relocs, const uint64_t delta);
	bool ResolveImports(portable_executable::vec_imports imports);
private:
	intel_driver::Iqvw64e m_iqvw64e;
};