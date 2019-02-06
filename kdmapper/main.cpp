#include "kdmapper.hpp"

int main(const int argc, char** argv)
{
	if (argc != 2 || std::filesystem::path(argv[1]).extension().string().compare(".sys"))
	{
		std::cout << "[-] Incorrect usage" << std::endl;
		return -1;
	}
	
	const std::string driver_path = argv[1];

	if (!std::filesystem::exists(driver_path))
	{
		std::cout << "[-] File " << driver_path << " doesn't exist" << std::endl;
		return -1;
	}
	
	KernelDriverMapper kdmapper;

	if (!kdmapper.Initialize())
	{
		std::cout << "[-] Failed to initalize kdmapper" << std::endl;
		return -1;
	}
	 
	const uint64_t mapped_driver = kdmapper.MapDriver(driver_path);
	
	if (!mapped_driver)
	{
		std::cout << "[-] Failed to map " << driver_path << std::endl;
		return -1;
	}
}