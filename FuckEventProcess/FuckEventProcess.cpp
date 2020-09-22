#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <winternl.h>
#include <Tlhelp32.h>
#include <string.h>
#include <strsafe.h>
#pragma comment(lib, "ntdll.lib") 


typedef long NTSTATUS;

/**/
typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS    exitStatus;
    PVOID       pTebBaseAddress;
    CLIENT_ID   clientId;
    KAFFINITY               AffinityMask;
    int						Priority;
    int						BasePriority;
    int						v;

} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef enum _SC_SERVICE_TAG_QUERY_TYPE
{
    ServiceNameFromTagInformation = 1,
    ServiceNameReferencingModuleInformation,
    ServiceNameTagMappingInformation,
} SC_SERVICE_TAG_QUERY_TYPE, * PSC_SERVICE_TAG_QUERY_TYPE;

typedef struct _SC_SERVICE_TAG_QUERY
{
    ULONG   processId;
    ULONG   serviceTag;
    ULONG   reserved;
    PVOID   pBuffer;
} SC_SERVICE_TAG_QUERY, * PSC_SERVICE_TAG_QUERY;

typedef ULONG(WINAPI* pI_QueryTagInformation)(PVOID, SC_SERVICE_TAG_QUERY_TYPE, PSC_SERVICE_TAG_QUERY);
typedef NTSTATUS(WINAPI* pNtQueryInformationThread)(HANDLE, THREAD_INFORMATION_CLASS, PVOID, ULONG, PULONG);


BOOL CheckEventProcess(DWORD ProcessId) {
    BOOL result = 0;
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessId);
    if (!hProcess)
    {
        return false;
    }
    DWORD status = NtQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0, &pbi, sizeof(PVOID) * 6, NULL);

    PPEB ppeb = (PPEB)((PVOID*)&pbi)[1];
    PEB pebdata = { 0 };

    ReadProcessMemory(hProcess, ppeb, &pebdata, sizeof(PEB), NULL);

    PRTL_USER_PROCESS_PARAMETERS prtlp = (&pebdata)->ProcessParameters;
    RTL_USER_PROCESS_PARAMETERS rtlp = { 0 };

    ReadProcessMemory(hProcess, prtlp, &rtlp, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL);

    PWSTR lpBuffer = (PWSTR)(&rtlp)->CommandLine.Buffer;
    USHORT len = (USHORT)(&rtlp)->CommandLine.Length;

    LPWSTR lpStrings = (LPWSTR)malloc(len);

    ZeroMemory(lpStrings, len);

    ReadProcessMemory(hProcess, lpBuffer, lpStrings, len, NULL);


    if (wcsstr(lpStrings, L"EventLog"))
    {
        result = true;
    }

    free(lpStrings);

    return result;
}

DWORD GetEventLogProcessId() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return 0;
    }
    DWORD logpid = 0;
    PROCESSENTRY32W pe32 = { 0 };
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    BOOL bRet = Process32FirstW(hSnapshot, &pe32);
    while (bRet)
    {
        if (CheckEventProcess(pe32.th32ProcessID))
        {
            logpid = pe32.th32ProcessID;
            CloseHandle(hSnapshot);
            return logpid;
        }
        bRet = Process32NextW(hSnapshot, &pe32);
    }
    CloseHandle(hSnapshot);
    return 0;
}


BOOL CheckAndFuckEventProcess(DWORD processId, DWORD threadId, PULONG pServiceTag)
{


    ;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HANDLE hTag = NULL;
    HMODULE advapi32 = NULL;
    THREAD_BASIC_INFORMATION tbi = { 0 };
    pI_QueryTagInformation I_QueryTagInformation = NULL;
    pNtQueryInformationThread NtQueryInformationThread = NULL;
    SC_SERVICE_TAG_QUERY tagQuery = { 0 };
    WCHAR Buffer[MAX_PATH] = { 0 };

    NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);
    NtQueryInformationThread(hThread, (THREAD_INFORMATION_CLASS)0, &tbi, 0x30, NULL);//内存对齐
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    ReadProcessMemory(hProcess, ((PBYTE)tbi.pTebBaseAddress + 0x1720), &hTag, sizeof(HANDLE), NULL);


    advapi32 = LoadLibrary(L"advapi32.dll");

    I_QueryTagInformation = (pI_QueryTagInformation)GetProcAddress(advapi32, "I_QueryTagInformation");
    tagQuery.processId = processId;
    tagQuery.serviceTag = (ULONG)hTag;
    I_QueryTagInformation(NULL, ServiceNameFromTagInformation, &tagQuery);
    if (tagQuery.pBuffer != 0)
    {
        StringCbCopy(Buffer, MAX_PATH, (PCWSTR)tagQuery.pBuffer);
    }
    else
    {

        CloseHandle(hProcess);
        CloseHandle(hThread);
        FreeLibrary(advapi32);
        return 0;
    }

    if (!wcscmp(Buffer, L"EventLog"))
    {
        TerminateThread(hThread,0);
        wprintf((WCHAR*)L"%d %s\n", threadId, Buffer);
    }
    LocalFree(tagQuery.pBuffer);
    CloseHandle(hProcess);
    CloseHandle(hThread);
    FreeLibrary(advapi32);

    return 1;
}

int main() {
    DWORD dwPid;

    dwPid = GetEventLogProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (INVALID_HANDLE_VALUE == hSnapshot)
    {
        return 0;
    }
    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);

    BOOL bRet = Thread32First(hSnapshot, &te32);
    while (bRet)
    {
        if (te32.th32OwnerProcessID == dwPid)
        {
            CheckAndFuckEventProcess(dwPid, te32.th32ThreadID, NULL);
        }


        bRet = Thread32Next(hSnapshot, &te32);
    }
    CloseHandle(hSnapshot);
    return 0;

}