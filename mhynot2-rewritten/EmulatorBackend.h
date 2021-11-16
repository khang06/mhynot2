#pragma once

#include "Backend.h"

class EmulatorBackend : public Backend {
public:
	static constexpr SC_HANDLE DUMMY_HANDLE = (SC_HANDLE)0x0B00B135;

	std::optional<SC_HANDLE> CreateServiceWHook(LPCWSTR lpServiceName);
	std::optional<SC_HANDLE> OpenServiceWHook(LPCWSTR lpServiceName);
	std::optional<BOOL> StartServiceWHook(SC_HANDLE hService);
	std::optional<BOOL> ControlServiceHook(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus);
	std::optional<BOOL> DeleteServiceHook(SC_HANDLE hService);
	std::optional<BOOL> CloseServiceHandleHook(SC_HANDLE hService);

	std::optional<HANDLE> OpenDriverPipe();
	std::optional<std::vector<uint8_t>> DriverInit(LPVOID input);
	std::optional<std::vector<uint8_t>> HandleIOCTLRequest(DWORD control_code, std::vector<uint8_t> input);
	void HandleIOCTLResponse(DWORD control_code, std::vector<uint8_t> input, std::vector<uint8_t> output);

private:
	bool service_created = false;
};