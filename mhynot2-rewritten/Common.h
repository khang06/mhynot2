#pragma once

#include <Windows.h>
#include <cstdarg>
#include <cstdio>
#include <string>

#define LODWORD(x)  (*((uint32_t*)&(x)))

#define BLK "\x1b[0;30m"
#define RED "\x1b[0;31m"
#define GRN "\x1b[0;32m"
#define YEL "\x1b[0;33m"
#define BLU "\x1b[0;34m"
#define MAG "\x1b[0;35m"
#define CYN "\x1b[0;36m"
#define WHT "\x1b[0;37m"

EXTERN_C IMAGE_DOS_HEADER __ImageBase;

namespace Common {
	__declspec(noreturn) void Panic(const char* msg, ...);
	void Hexdump(void* ptr, size_t buflen);
	std::wstring PIDToProcessName(DWORD pid);
}