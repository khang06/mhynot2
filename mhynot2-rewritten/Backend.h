#pragma once
#include <Windows.h>
#include <optional>
#include <vector>
#include <cstdint>

class Backend {
public:
	// service hooks, only passing what's necessary
	virtual std::optional<SC_HANDLE> CreateServiceWHook(LPCWSTR lpServiceName) = 0;
	virtual std::optional<SC_HANDLE> OpenServiceWHook(LPCWSTR lpServiceName) = 0;
	virtual std::optional<BOOL> StartServiceWHook(SC_HANDLE hService) = 0;
	//virtual bool QueryServiceStatusHook(SC_HANDLE hService) = 0; // doesn't actually get called??
	virtual std::optional<BOOL> ControlServiceHook(SC_HANDLE hService, DWORD dwControl, LPSERVICE_STATUS lpServiceStatus) = 0;
	virtual std::optional<BOOL> DeleteServiceHook(SC_HANDLE hService) = 0;
	virtual std::optional<BOOL> CloseServiceHandleHook(SC_HANDLE hService) = 0;

	// not technically hooks
	virtual std::optional<HANDLE> OpenDriverPipe() = 0;
	virtual std::optional<std::vector<uint8_t>> DriverInit(LPVOID input) = 0;
	virtual std::optional<std::vector<uint8_t>> HandleIOCTLRequest(DWORD control_code, std::vector<uint8_t> input) = 0;
	virtual void HandleIOCTLResponse(DWORD control_code, std::vector<uint8_t> input, std::vector<uint8_t> output) = 0;

	HANDLE driver_pipe = INVALID_HANDLE_VALUE;
};