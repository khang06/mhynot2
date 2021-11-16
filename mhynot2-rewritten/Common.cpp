#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include "Common.h"

namespace Common {
    __declspec(noreturn) void Panic(const char* msg, ...) {
        va_list args;
        va_start(args, msg);

        char buf[1024] = {};
        vsnprintf(buf, sizeof(buf) - 1, msg, args);

        MessageBoxA(NULL, buf, "PANIC!!!!!!", 0);

        va_end(args);
        exit(1);
    }

    // https://stackoverflow.com/questions/29242/off-the-shelf-c-hex-dump-code
    void Hexdump(void* ptr, size_t buflen) {
        unsigned char* buf = (unsigned char*)ptr;
        size_t i, j;
        for (i = 0; i < buflen; i += 16) {
            printf("%06x: ", i);
            for (j = 0; j < 16; j++)
                if (i + j < buflen)
                    printf("%02x ", buf[i + j]);
                else
                    printf("   ");
            printf(" ");
            for (j = 0; j < 16; j++)
                if (i + j < buflen)
                    printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
            printf("\n");
        }
    }

    std::wstring PIDToProcessName(DWORD pid) {
        auto snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        std::wstring ret = L"???";

        if (snap) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(snap, &pe32)) {
                do {
                    if (pe32.th32ProcessID == pid) {
                        ret = pe32.szExeFile;
                        break;
                    }
                } while (Process32Next(snap, &pe32));
            }
            CloseHandle(snap);
        } else {
            Panic("CreateToolhelp32Snapshot failed somehow...");
        }

        return ret;
    }
}