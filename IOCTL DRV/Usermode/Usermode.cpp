#include <Windows.h>
#include <TlHelp32.h>
#include <string>

#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0301, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0302, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define FORCE_JUMP 0x528790C
#define LOCAL_PLAYER 0xDC14BC
#define FFLAGS 0x104

typedef struct _KERNEL_READ_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	ULONG Response;
	ULONG Size;

} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	ULONG Value;
	ULONG Size;

} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

class Controller
{
public:
	HANDLE DriverHandle;

	Controller(LPCSTR RegistryPath)
	{
		HANDLE DriverHandle = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	template <typename type>
	type ReadVirtualMemory(ULONG ProcessId, ULONG ReadAddress,
		SIZE_T Size)
	{
		if (DriverHandle == INVALID_HANDLE_VALUE)
			return (type)false;

		DWORD Return, Bytes;
		KERNEL_READ_REQUEST ReadRequest;

		ReadRequest.ProcessId = ProcessId;
		ReadRequest.Address = ReadAddress;
		ReadRequest.Size = Size;

		if (DeviceIoControl(DriverHandle, IO_READ_REQUEST, &ReadRequest,
			sizeof(ReadRequest), &ReadRequest, sizeof(ReadRequest), 0, 0))
			return (type)ReadRequest.Response;
		else
			return (type)false;
	}

	bool WriteVirtualMemory(ULONG ProcessId, ULONG WriteAddress,
		ULONG WriteValue, SIZE_T WriteSize)
	{
		if (DriverHandle == INVALID_HANDLE_VALUE)
			return false;
		DWORD Bytes;

		KERNEL_WRITE_REQUEST  WriteRequest;
		WriteRequest.ProcessId = ProcessId;
		WriteRequest.Address = WriteAddress;
		WriteRequest.Value = WriteValue;
		WriteRequest.Size = WriteSize;

		if (DeviceIoControl(DriverHandle, IO_WRITE_REQUEST, &WriteRequest, sizeof(WriteRequest),
			0, 0, &Bytes, NULL))
			return true;
		else
			return false;
	}
};

DWORD GetProcessId(std::string ProcessName)
{
	HANDLE hsnap;
	PROCESSENTRY32 pt;
	DWORD PiD;
	hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	do {
		if (!strcmp(pt.szExeFile, ProcessName.c_str())) {
			CloseHandle(hsnap);
			PiD = pt.th32ProcessID;
			return PiD;
			if (PiD != NULL) {
				return 0;
			}
		}
	} while (Process32Next(hsnap, &pt));
	return 1;
}

DWORD GetModule(TCHAR* lpszModuleName, DWORD pID) 
{
	DWORD dwModuleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
	MODULEENTRY32 ModuleEntry32 = { 0 };
	ModuleEntry32.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnapshot, &ModuleEntry32))
	{
		do {
			if (strcmp(ModuleEntry32.szModule, lpszModuleName) == 0)
			{
				dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnapshot, &ModuleEntry32));


	}
	CloseHandle(hSnapshot);
	return dwModuleBaseAddress;
}

int main()
{
	Controller controller("\\\\.\\IOCTL_Drv");

	DWORD pid = GetProcessId("csgo.exe");
	DWORD Client = GetModule((char*)"client.dll", pid);
	DWORD Engine = GetModule((char*)"engine.dll", pid);

	if (pid)
		printf("[+] Process not found!");
	else
		printf("[+] Process found!");

	if (Client)
		printf("[+] Client not found!");
	else
		printf("[+] Client found!");

	if (Engine)
		printf("[+] Engine not found!");
	else
		printf("[+] Engine found!");

	DWORD localPlayer = controller.ReadVirtualMemory<DWORD>(pid, Client + LOCAL_PLAYER, sizeof(ULONG));

	if (localPlayer)
		printf("[+] LocalPlayer not found!");
	else
		printf("[+] LocalPlayer found!");

	while (true)
	{
		DWORD Flags = controller.ReadVirtualMemory<DWORD>(pid, localPlayer + FFLAGS, sizeof(ULONG));
		if (GetAsyncKeyState(VK_SPACE) && Flags & (1 << 0))
		{
			controller.WriteVirtualMemory(pid, Client + FORCE_JUMP, 5, 8);
		}
	}
}