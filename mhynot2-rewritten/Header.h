#pragma once
#include <windows.h>

class RequestHandler {
	virtual void HandleIOCTL(DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned) = 0;
};