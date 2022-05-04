// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "detours.h"
#include <fstream>
#include <stdio.h>
#include <chrono>
#include <Windows.h>
#include <Winternl.h>
#include <shellapi.h>
#include <atlstr.h>
#include <sstream>
#include <winternl.h>
#include <winreg.h>
#include <synchapi.h>
#include <winreg.h>
//#include <ntifs.h>


using namespace std;
#pragma warning(disable:4996)

//const char* logsFile = "C:\\Windows\\Temp\\API_Calls_Monitor_Logs2.txt";
wstring logCall;
int flag = 0;


void printError(const char* msg);


std::wstring s2ws(const std::string& str)
{
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}


static BOOL(WINAPI* realCreateProcess)(LPCWSTR lpszImageName, LPWSTR lpszCmdLine, LPSECURITY_ATTRIBUTES lpsaProcess, LPSECURITY_ATTRIBUTES lpsaThread, BOOL fInheritHandles, DWORD fdwCreate, LPVOID lpvEnvironment, LPCWSTR lpszCurDir, LPSTARTUPINFOW lpsiStartInfo, LPPROCESS_INFORMATION lppiProcInfo) = CreateProcess;
BOOL WINAPI HookedCreateProcess(LPCWSTR lpszImageName, LPWSTR lpszCmdLine, LPSECURITY_ATTRIBUTES lpsaProcess, LPSECURITY_ATTRIBUTES lpsaThread, BOOL fInheritHandles, DWORD fdwCreate, LPVOID lpvEnvironment, LPCWSTR lpszCurDir, LPSTARTUPINFOW lpsiStartInfo, LPPROCESS_INFORMATION lppiProcInfo)
{

    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CreateProcess : ";
    logCall += (LPCWSTR)lpszImageName;

    logCall += L" : ";
    logCall += (LPCWSTR)lpszCmdLine;

    logCall += L" : ";
    logCall += (LPCWSTR)lpszCurDir;
    logCall += L" : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));

    return realCreateProcess( lpszImageName,  lpszCmdLine,  lpsaProcess,  lpsaThread,  fInheritHandles,  fdwCreate,  lpvEnvironment,  lpszCurDir,  lpsiStartInfo,  lppiProcInfo);
}


static BOOL (WINAPI* realCreateProcessA)(LPCSTR  lpApplicationName, LPSTR   lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL    bInheritHandles, DWORD   dwCreationFlags, LPVOID  lpEnvironment, LPCSTR  lpCurrentDirectory, LPSTARTUPINFOA        lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)= CreateProcessA;
BOOL WINAPI HookedCreateProcessA(LPCSTR  lpApplicationName, LPSTR   lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL    bInheritHandles, DWORD   dwCreationFlags, LPVOID  lpEnvironment, LPCSTR  lpCurrentDirectory, LPSTARTUPINFOA        lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] ShellExecuteA : ";
    logCall += (LPCWSTR)lpApplicationName;

    logCall += L" : ";
    logCall += (LPCWSTR)lpCommandLine;

    logCall += L" : ";
    logCall += (LPCWSTR)lpCurrentDirectory;
    logCall += L" : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));

    return realCreateProcessA(  lpApplicationName,    lpCommandLine,  lpProcessAttributes,  lpThreadAttributes,     bInheritHandles,    dwCreationFlags,   lpEnvironment,   lpCurrentDirectory,         lpStartupInfo,  lpProcessInformation);
}

//GetCommandLine Hooking
static LPWSTR(WINAPI* realGetCommandLine)() = GetCommandLine;
LPWSTR WINAPI HookedGetCommandLine() 
{
    LPWSTR ret = realGetCommandLine();

    OutputDebugString(L"[+] GetCommandLine is called!!");

    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] GetCommandLine : ";
    logCall += L"  : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return ret;

}

// GetStartupInfo Hooking
static void (WINAPI* realGetStartupInfo)(LPSTARTUPINFO lpStartupInfo) = GetStartupInfo;
void WINAPI HookedGetStartupInfo(LPSTARTUPINFO lpStartupInfo)
{
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] GetStartupInfo : ";
    logCall += L"  : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realGetStartupInfo(lpStartupInfo);
}

//OpenProcess Hooking
static HANDLE(WINAPI* TrueOpenProcess) (DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) = OpenProcess;
HANDLE WINAPI InterceptOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
    HANDLE ret = TrueOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);

    //writeLog("\n[+] OpenProcess is called!!");
    OutputDebugString(L"[+] OpenProcess is called!!");
    return 0;
}


static void(WINAPI* realExitProcess)(UINT  uExitCode)= ExitProcess;
void WINAPI HookedExitProcess(UINT  uExitCode) 
{
    OutputDebugString(L"[+] ExitProcess is called!!");

    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] ExitProcess : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));

    return realExitProcess(uExitCode);
}


static HINSTANCE(WINAPI* realShellExecuteA)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd) = ShellExecuteA;
HINSTANCE WINAPI HookedShellExecuteA(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd) 
{
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] ShellExecuteA : ";
    logCall += (LPCWSTR)lpOperation;

    logCall += L" : ";
    logCall += (LPCWSTR)lpFile;

    logCall += L" : ";
    logCall += (LPCWSTR)lpParameters;

    logCall += L" : ";
    logCall += (LPCWSTR)lpDirectory;
    logCall += L" : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));

    return realShellExecuteA( hwnd,  lpOperation,  lpFile,  lpParameters,  lpDirectory,  nShowCmd);
}


static HANDLE(WINAPI* realCreateFile)(LPCWSTR  lpFileName, DWORD   dwDesiredAccess, DWORD   dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD   dwCreationDisposition, DWORD   dwFlagsAndAttributes, HANDLE  hTemplateFile)= CreateFile;
HANDLE WINAPI HookedCreateFile(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDispostion, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
        HANDLE   ret = realCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDispostion, dwFlagsAndAttributes, hTemplateFile);
        if (flag == 1) { flag = 0; return ret; }
        

        /*
        string x = "C:\\Windows\\Temp\\API_Calls_Monitor_Logs.txt";
        int wchars_num = MultiByteToWideChar(CP_UTF8, 0, x.c_str(), -1, NULL, 0);
        wchar_t* wstr = new wchar_t[wchars_num];
        MultiByteToWideChar(CP_UTF8, 0, x.c_str(), -1, wstr, wchars_num);
        // do whatever with wstr
        delete[] wstr;
        */

        OutputDebugString(L"[+] CreateFile is called!!");
        OutputDebugString(lpFileName);
        auto start = std::chrono::system_clock::now();
        std::time_t end_time = std::chrono::system_clock::to_time_t(start);
        logCall += L"[+] CreateFile : ";
        logCall += lpFileName;
        logCall += L"  : ";
        //logCall += GetCurrentProcessId();
        //logCall += L" : ";
        logCall += s2ws(std::ctime(&end_time));
        OutputDebugString(L"-----------------------------------------");

    
  //  writeLog((char*)lpFileName);
    return ret;

}


static HANDLE(WINAPI* realCreateFileA)(LPCSTR  lpFileName, DWORD   dwDesiredAccess, DWORD   dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD   dwCreationDisposition, DWORD   dwFlagsAndAttributes, HANDLE  hTemplateFile) = CreateFileA;
HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDispostion, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE   ret = realCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDispostion, dwFlagsAndAttributes, hTemplateFile);
    if (flag == 1) { flag = 0; return ret; }

    OutputDebugString(L"[+] CreateFileA is called!!");
    OutputDebugString((LPCWSTR)lpFileName);
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CreateFileA : ";
    logCall += (LPCWSTR)lpFileName;
    logCall += L"  : ";

    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    OutputDebugString(L"-----------------------------------------");


    //  writeLog((char*)lpFileName);
    return ret;

}


static HANDLE(WINAPI* realCreateFileW)(LPCWSTR  lpFileName, DWORD   dwDesiredAccess, DWORD   dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD   dwCreationDisposition, DWORD   dwFlagsAndAttributes, HANDLE  hTemplateFile) = CreateFileW;
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDispostion, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE   ret = realCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDispostion, dwFlagsAndAttributes, hTemplateFile);
    if (flag == 1) { flag = 0; return ret; }

    OutputDebugString(L"[+] CreateFileW is called!!");
    OutputDebugString(lpFileName);
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CreateFileW : ";
    logCall += lpFileName;
    logCall += L"  : ";

    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    OutputDebugString(L"-----------------------------------------");


    //  writeLog((char*)lpFileName);
    return ret;

}


//static NTSYSCALLAPI NTSTATUS(WINAPI* realNtWriteFile)(HANDLE  FileHandle, HANDLE  Event, PIO_APC_ROUTINE  ApcRoutine, PVOID   ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID   Buffer,
  //  ULONG  Length, PLARGE_INTEGER   ByteOffset, PULONG  Key) = NtWriteFile;

typedef NTSTATUS(WINAPI* PtrRealNtWriteFile)(HANDLE  FileHandle, HANDLE  Event, PIO_APC_ROUTINE  ApcRoutine, PVOID   ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID   Buffer,
      ULONG  Length, PLARGE_INTEGER   ByteOffset, PULONG  Key);

PtrRealNtWriteFile realNtWriteFile;

NTSTATUS WINAPI HookedNtWriteFile(HANDLE  FileHandle, HANDLE  Event, PIO_APC_ROUTINE  ApcRoutine, PVOID   ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID   Buffer,
    ULONG  Length, PLARGE_INTEGER   ByteOffset, PULONG  Key)
{
    OutputDebugString(L"[+] NtWriteFile is called!!");

    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] NtWriteFile : ";

    logCall += L"  : ";

    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realNtWriteFile(  FileHandle,   Event,   ApcRoutine,    ApcContext,  IoStatusBlock,    Buffer,
          Length,    ByteOffset,   Key);
}




typedef NTSTATUS(WINAPI* PtrRealNtOpenFile)(PHANDLE FileHandle, ACCESS_MASK  DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG   ShareAccess, ULONG    OpenOptions);

PtrRealNtOpenFile realNtOpenFile;

NTSTATUS WINAPI HookedNtOpenFile(PHANDLE FileHandle, ACCESS_MASK  DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG   ShareAccess, ULONG    OpenOptions)
{
    OutputDebugString(L"[+] NtOpenFile is called!!");

    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] NtOpenFile : ";

    logCall += L"  : ";
    WCHAR szTest[256];
    swprintf_s(szTest, 256 ,L"%d", DesiredAccess);

    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += L"ACCESS_MASK#";
    logCall += szTest;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realNtOpenFile( FileHandle, DesiredAccess,  ObjectAttributes,  IoStatusBlock, ShareAccess, OpenOptions);
}



//NTSYSCALLAPI NTSTATUS WINAPI HookedNtWriteFile(HANDLE  FileHandle, HANDLE  Event, PIO_APC_ROUTINE  ApcRoutine, PVOID   ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID   Buffer, ULONG  Length, PLARGE_INTEGER   ByteOffset, PULONG  Key) {}

typedef NTSTATUS(WINAPI* PtrRealNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID,
    ULONG);

PtrRealNtCreateFile realNtCreateFile;

//static HANDLE (WINAPI* realNtCreateFile)(PHANDLE  FileHandle, ACCESS_MASK        DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER     AllocationSize, ULONG    FileAttributes, ULONG    ShareAccess, ULONG    CreateDisposition, ULONG    CreateOptions, PVOID    EaBuffer, ULONG    EaLength) = NtCreateFile;
NTSTATUS WINAPI HookedNtCreateFile(PHANDLE  FileHandle, ACCESS_MASK  DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK   IoStatusBlock, PLARGE_INTEGER     AllocationSize, ULONG    FileAttributes, ULONG    ShareAccess, ULONG    CreateDisposition, ULONG    CreateOptions, PVOID    EaBuffer, ULONG    EaLength)
{
    OutputDebugString(L"[+] NtCreateFile is called!!");

    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] NtCreateFile : ";

    logCall += L"  : ";

    WCHAR szTest[256];
    swprintf_s(szTest, 256, L"%d", DesiredAccess);

    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += L"ACCESS_MASK#";
    logCall += szTest;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realNtCreateFile(  FileHandle,         DesiredAccess,  ObjectAttributes,    IoStatusBlock,      AllocationSize,     FileAttributes,     ShareAccess,     CreateDisposition,     CreateOptions,     EaBuffer,     EaLength);
}



// Address of the real WriteFile API
BOOL(WINAPI* realWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    OutputDebugString(L"[+] WriteFile is called!!");
   // printError("[+] WriteFile is called!!\n");
    if (flag) { flag = 0; return  realWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped); }
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] WriteFile : ";
  //  logCall += lpFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));

    return realWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

static BOOL(WINAPI* realDeleteFile) (LPCTSTR lpFileName)= DeleteFile;
BOOL HookedDeleteFile(LPCTSTR lpFileName) 
{
    OutputDebugString(L"[+] DeleteFile is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] DeleteFile : ";
      logCall += lpFileName;
      //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realDeleteFile(lpFileName);
}

static BOOL(WINAPI* realDeleteFileA) (LPCSTR lpFileName) = DeleteFileA;
BOOL HookedDeleteFileA(LPCSTR lpFileName)
{
    OutputDebugString(L"[+] DeleteFileA is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] DeleteFileA : ";
    logCall += (LPCTSTR)lpFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realDeleteFileA(lpFileName);
}


static BOOL(WINAPI* realCopyFile) (LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL    bFailIfExists) = CopyFile;
BOOL HookedCopyFile(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL    bFailIfExists)
{
    OutputDebugString(L"[+] CopyFile is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CopyFile : ";
    logCall += L"lpExistingFileName # ";
    logCall += lpExistingFileName;
    logCall += L"_lpNewFileName # ";
    logCall += lpNewFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realCopyFile(lpExistingFileName, lpNewFileName, bFailIfExists);
}

static BOOL(WINAPI* realCopyFileA) (LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL    bFailIfExists) = CopyFileA;
BOOL HookedCopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL    bFailIfExists)
{
    OutputDebugString(L"[+] CopyFileA is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CopyFileA : ";
    logCall += L"lpExistingFileName # ";
    logCall += (LPCTSTR)lpExistingFileName;
    logCall += L"_lpNewFileName # ";
    logCall += (LPCTSTR)lpNewFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realCopyFileA(lpExistingFileName, lpNewFileName, bFailIfExists);
}

static BOOL(WINAPI* realCopyFileW) (LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL    bFailIfExists) = CopyFileW;
BOOL HookedCopyFileW(LPCTSTR lpExistingFileName, LPCTSTR lpNewFileName, BOOL    bFailIfExists)
{
    OutputDebugString(L"[+] CopyFileW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CopyFileW : ";
    logCall += L"lpExistingFileName # ";
    logCall += lpExistingFileName;
    logCall += L"_lpNewFileName # ";
    logCall += lpNewFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realCopyFileW(lpExistingFileName, lpNewFileName, bFailIfExists);
}


static HANDLE(WINAPI* realFindFirstFile)(LPCTSTR  lpFileName, LPWIN32_FIND_DATA  lpFindFileData) = FindFirstFile;
HANDLE WINAPI HookedFindFirstFile(LPCTSTR  lpFileName, LPWIN32_FIND_DATA  lpFindFileData) 
{
    OutputDebugString(L"[+] FindFirstFile  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] FindFirstFile : ";
    logCall += L"lpFileName # ";
    logCall += lpFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realFindFirstFile(lpFileName, lpFindFileData);
}

static HANDLE(WINAPI* realFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
HANDLE WINAPI HookedFindFirstFileA(LPCSTR  lpFileName, LPWIN32_FIND_DATAA  lpFindFileData)
{
    OutputDebugString(L"[+] FindFirstFileA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] FindFirstFileA : ";
    logCall += L"lpFileName # ";
    logCall += (LPCTSTR)lpFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realFindFirstFileA(lpFileName, lpFindFileData);
}


static HANDLE(WINAPI* realFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) = FindFirstFileW;
HANDLE WINAPI HookedFindFirstFileW(LPCTSTR  lpFileName, LPWIN32_FIND_DATA  lpFindFileData)
{
    OutputDebugString(L"[+] FindFirstFileW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] FindFirstFileW : ";
    logCall += L"lpFileName # ";
    logCall += lpFileName;
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realFindFirstFileW(lpFileName, lpFindFileData);
}


static BOOL(WINAPI* realFindNextFile)(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData) = FindNextFile;
BOOL WINAPI HookedFindNextFile(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData) 
{
    OutputDebugString(L"[+] HookedFindNextFile  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] HookedFindNextFile : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realFindNextFile(hFindFile, lpFindFileData);
}

static BOOL(WINAPI* realFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) = FindNextFileA;
BOOL WINAPI HookedFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
{
    OutputDebugString(L"[+] HookedFindNextFileA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] HookedFindNextFileA : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realFindNextFileA(hFindFile, lpFindFileData);
}

static BOOL(WINAPI* realFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) = FindNextFileW;
BOOL WINAPI HookedFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
{
    OutputDebugString(L"[+] HookedFindNextFileW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] HookedFindNextFileW : ";
    //logCall += GetCurrentProcessId();
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realFindNextFileW(hFindFile, lpFindFileData);
}

/*
*                               Mutex Functions
*                       OpenMutex , CreateMutex , ReleaseMutex
*/

            ///////////////////////OpenMutex/////////////////////////////////////
static HANDLE(WINAPI* realOpenMutex)(DWORD   dwDesiredAccess, BOOL    bInheritHandle, LPCWSTR lpName) = OpenMutex;
HANDLE WINAPI HookedOpenMutex(DWORD   dwDesiredAccess, BOOL    bInheritHandle, LPCWSTR lpName) 
{
    OutputDebugString(L"[+] OpenMutex  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] OpenMutex : ";
    //logCall += GetCurrentProcessId();
    logCall += L" lpName# ";
    logCall += lpName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realOpenMutex(dwDesiredAccess, bInheritHandle , lpName);
}

static HANDLE(WINAPI* realOpenMutexA)(DWORD   dwDesiredAccess, BOOL    bInheritHandle, LPCSTR lpName) = OpenMutexA;
HANDLE WINAPI HookedOpenMutexA(DWORD   dwDesiredAccess, BOOL    bInheritHandle, LPCSTR lpName)
{
    OutputDebugString(L"[+] OpenMutex  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] OpenMutex : ";
    //logCall += GetCurrentProcessId();
    logCall += L" lpName# ";
    logCall += (LPCWSTR)lpName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realOpenMutexA(dwDesiredAccess, bInheritHandle, lpName);
}

static HANDLE(WINAPI* realOpenMutexW)(DWORD   dwDesiredAccess, BOOL    bInheritHandle, LPCWSTR lpName) = OpenMutexW;
HANDLE WINAPI HookedOpenMutexW(DWORD   dwDesiredAccess, BOOL    bInheritHandle, LPCWSTR lpName)
{
    OutputDebugString(L"[+] OpenMutexW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] OpenMutexW : ";
    //logCall += GetCurrentProcessId();
    logCall += L" lpName# ";
    logCall += lpName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realOpenMutexW(dwDesiredAccess, bInheritHandle, lpName);
}


            ///////////////////////CreateMutex/////////////////////////////////////
static HANDLE(WINAPI* realCreateMutex)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCTSTR lpName) = CreateMutex;
HANDLE WINAPI HookedCreateMutex(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCTSTR lpName) 
{
    OutputDebugString(L"[+] CreateMutex  is called!!");
    
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CreateMutex : ";
    //logCall += GetCurrentProcessId();
    logCall += L" lpName# ";
   // logCall += lpName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    OutputDebugString(lpName);
    
    return realCreateMutex( lpMutexAttributes,  bInitialOwner,  lpName);
}

static HANDLE(WINAPI* realCreateMutexW)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCTSTR lpName) = CreateMutexW;
HANDLE WINAPI HookedCreateMutexW(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCTSTR lpName)
{
    OutputDebugString(L"[+] CreateMutexW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CreateMutexW : ";
    //logCall += GetCurrentProcessId();
    logCall += L" lpName# ";
   // logCall += lpName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realCreateMutexW(lpMutexAttributes, bInitialOwner, lpName);
}

static HANDLE(WINAPI* realCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName) = CreateMutexA;
HANDLE WINAPI HookedCreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName)
{
    OutputDebugString(L"[+] CreateMutexA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] CreateMutexA : ";
    //logCall += GetCurrentProcessId();
    logCall += L" lpName# ";
   // logCall += (LPCTSTR)lpName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realCreateMutexA(lpMutexAttributes, bInitialOwner, lpName);
}


            ///////////////////////ReleaseMutex/////////////////////////////////////
static BOOL(WINAPI* realReleaseMutex)(HANDLE hMutex) = ReleaseMutex;
BOOL WINAPI HookedReleaseMutex(HANDLE hMutex) 
{
   // OutputDebugString(L"[+] ReleaseMutex  is called!!");
   
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] ReleaseMutex : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
   
    return realReleaseMutex(hMutex);
}

/*
*                                     Regisry Functions
*          RegOpenKey, RegCloseKey, RegDeleteKey, RegDeleteValue, RegSetValue, RegSetKey
*/

        /*
        * Quick Note:
        * RegOpenKeyEx is better than RegOpenKey, because RegOpenKey returns HANDLE to the current KEY if the subkeyName is NULL or "", so if you close the HANDLE
        * in case the subkeyName is NULL or "", will not make issue in case of using RegOpenKeyEx, and it is recommended for all Applications.
        */

        ///////////////////////RegOpenKeyEx/////////////////////////////////////
static LSTATUS(WINAPI* realRegOpenKeyEx)(HKEY   hKey, LPCWSTR lpSubKey, DWORD   ulOptions, REGSAM  samDesired, PHKEY   phkResult) = RegOpenKeyEx;
LSTATUS WINAPI HookedRegOpenKeyEx(HKEY   hKey, LPCWSTR lpSubKey, DWORD   ulOptions, REGSAM  samDesired, PHKEY   phkResult)
{
    OutputDebugString(L"[+] RegOpenKeyEx  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegOpenKeyEx : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

        ///////////////////////RegOpenKeyExW/////////////////////////////////////
static LSTATUS(WINAPI* realRegOpenKeyExW)(HKEY   hKey, LPCWSTR lpSubKey, DWORD   ulOptions, REGSAM  samDesired, PHKEY   phkResult) = RegOpenKeyExW;
LSTATUS WINAPI HookedRegOpenKeyExW(HKEY   hKey, LPCWSTR lpSubKey, DWORD   ulOptions, REGSAM  samDesired, PHKEY   phkResult)
{
    OutputDebugString(L"[+] RegOpenKeyExW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegOpenKeyExW : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegOpenKeyExW(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}


        ///////////////////////RegOpenKeyExA/////////////////////////////////////
static LSTATUS(WINAPI* realRegOpenKeyExA)(HKEY   hKey, LPCSTR lpSubKey, DWORD   ulOptions, REGSAM  samDesired, PHKEY   phkResult) = RegOpenKeyExA;
LSTATUS WINAPI HookedRegOpenKeyExA(HKEY   hKey, LPCSTR lpSubKey, DWORD   ulOptions, REGSAM  samDesired, PHKEY   phkResult)
{
    OutputDebugString(L"[+] RegOpenKeyExA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegOpenKeyExA : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR) lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegOpenKeyExA( hKey,  lpSubKey,    ulOptions,   samDesired,    phkResult);
}

        ///////////////////////RegSetKeyValueA/////////////////////////////////////
static LSTATUS(WINAPI* realRegSetKeyValueA)(HKEY    hKey, LPCSTR  lpSubKey, LPCSTR  lpValueName, DWORD   dwType, LPCVOID lpData, DWORD   cbData) = RegSetKeyValueA;
LSTATUS WINAPI HookedRegSetKeyValueA(HKEY    hKey, LPCSTR  lpSubKey, LPCSTR  lpValueName, DWORD   dwType, LPCVOID lpData, DWORD   cbData) 
{
    OutputDebugString(L"[+] realRegSetKeyValueA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] realRegSetKeyValueA : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpValueName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegSetKeyValueA(hKey, lpSubKey,  lpValueName,    dwType,  lpData,    cbData);
}

///////////////////////RegSetKeyValueW/////////////////////////////////////
static LSTATUS(WINAPI* realRegSetKeyValueW)(HKEY    hKey, LPCWSTR  lpSubKey, LPCWSTR  lpValueName, DWORD   dwType, LPCVOID lpData, DWORD   cbData) = RegSetKeyValueW;
LSTATUS WINAPI HookedRegSetKeyValueW(HKEY    hKey, LPCWSTR  lpSubKey, LPCWSTR  lpValueName, DWORD   dwType, LPCVOID lpData, DWORD   cbData)
{
    OutputDebugString(L"[+] RegSetKeyValueW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegSetKeyValueW : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += lpValueName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegSetKeyValueW(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
}

///////////////////////RegSetKeyValue/////////////////////////////////////
static LSTATUS(WINAPI* realRegSetKeyValue)(HKEY    hKey, LPCTSTR  lpSubKey, LPCTSTR  lpValueName, DWORD   dwType, LPCVOID lpData, DWORD   cbData) = RegSetKeyValue;
LSTATUS WINAPI HookedRegSetKeyValue(HKEY    hKey, LPCTSTR  lpSubKey, LPCTSTR  lpValueName, DWORD   dwType, LPCVOID lpData, DWORD   cbData)
{
    OutputDebugString(L"[+] realRegSetKeyValue  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] realRegSetKeyValue : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpValueName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegSetKeyValue(hKey, lpSubKey, lpValueName, dwType, lpData, cbData);
}

        ///////////////////////RegSetValueEx/////////////////////////////////////
static LSTATUS(WINAPI* realRegSetValueEx) (HKEY hKey, LPCWSTR lpValueName, DWORD  Reserved, DWORD  dwType, const BYTE* lpData, DWORD  cbData) = RegSetValueEx;
LSTATUS WINAPI HookedRegSetValueEx(HKEY hKey, LPCWSTR lpValueName, DWORD  Reserved, DWORD  dwType, const BYTE* lpData, DWORD  cbData)
{
    OutputDebugString(L"[+] RegSetValueEx  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegSetValueEx : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpValueName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

///////////////////////RegSetValueExW/////////////////////////////////////
static LSTATUS(WINAPI* realRegSetValueExW) (HKEY hKey, LPCWSTR lpValueName, DWORD  Reserved, DWORD  dwType, const BYTE* lpData, DWORD  cbData) = RegSetValueExW;
LSTATUS WINAPI HookedRegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD  Reserved, DWORD  dwType, const BYTE* lpData, DWORD  cbData)
{
    OutputDebugString(L"[+] RegSetValueExW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegSetValueExW : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += lpValueName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

        ///////////////////////RegSetValueExA/////////////////////////////////////
static LSTATUS (WINAPI* realRegSetValueExA) (HKEY hKey, LPCSTR lpValueName, DWORD  Reserved, DWORD  dwType, const BYTE* lpData, DWORD  cbData)= RegSetValueExA;
LSTATUS WINAPI HookedRegSetValueExA (HKEY hKey, LPCSTR lpValueName, DWORD  Reserved, DWORD  dwType, const BYTE* lpData, DWORD  cbData)
{
    OutputDebugString(L"[+] RegSetValueExA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegSetValueExA : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpValueName;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegSetValueExA( hKey,  lpValueName,   Reserved,   dwType,   lpData,   cbData);
}



            ///////////////////////RegOpenKey/////////////////////////////////////
static LSTATUS(WINAPI* realRegOpenKey)(HKEY   hKey, LPCTSTR lpSubKey, PHKEY  phkResult)  = RegOpenKey;
LSTATUS WINAPI HookedRegOpenKey(HKEY   hKey, LPCTSTR lpSubKey, PHKEY  phkResult) 
{
    OutputDebugString(L"[+] RegOpenKey  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegOpenKey : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegOpenKey(hKey,  lpSubKey,   phkResult);
}

            ///////////////////////RegOpenKeyW/////////////////////////////////////
static LSTATUS(WINAPI* realRegOpenKeyW)(HKEY   hKey, LPCWSTR lpSubKey, PHKEY  phkResult) = RegOpenKeyW;
LSTATUS WINAPI HookedRegOpenKeyW(HKEY   hKey, LPCWSTR lpSubKey, PHKEY  phkResult)
{
    OutputDebugString(L"[+] RegOpenKeyW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegOpenKeyW : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegOpenKeyW(hKey, lpSubKey, phkResult);
}

            ///////////////////////RegOpenKeyA/////////////////////////////////////
static LSTATUS(WINAPI* realRegOpenKeyA)(HKEY   hKey, LPCSTR lpSubKey, PHKEY  phkResult)  = RegOpenKeyA;
LSTATUS WINAPI HookedRegOpenKeyA(HKEY   hKey, LPCSTR lpSubKey, PHKEY  phkResult)
{
    OutputDebugString(L"[+] RegOpenKeyA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegOpenKeyA : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegOpenKeyA(hKey, lpSubKey, phkResult);
}


            ///////////////////////RegCloseKey/////////////////////////////////////
static LSTATUS (WINAPI* realRegCloseKey)(HKEY hKey) = RegCloseKey ;
LSTATUS WINAPI HookedRegCloseKey(HKEY hKey) 
{
    OutputDebugString(L"[+] RegCloseKey  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegCloseKey : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegCloseKey(hKey);
}
            //////////////////////RegDeleteKeyEx/////////////////////////////////////
static LONG(WINAPI* realRegDeleteKeyEx)(HKEY    hKey, LPCTSTR lpSubKey, REGSAM  samDesired, DWORD   Reserved) = RegDeleteKeyEx;
LONG WINAPI HookedRegDeleteKeyEx(HKEY    hKey, LPCTSTR lpSubKey, REGSAM  samDesired, DWORD   Reserved)
{
    OutputDebugString(L"[+] RegDeleteKeyEx  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegDeleteKeyEx : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return RegDeleteKeyEx(hKey, lpSubKey, samDesired, Reserved);
}


            //////////////////////RegDeleteKeyExW/////////////////////////////////////
static LONG(WINAPI* realRegDeleteKeyExW)(HKEY    hKey, LPCTSTR lpSubKey, REGSAM  samDesired, DWORD   Reserved) = RegDeleteKeyExW;
LONG WINAPI HookedRegDeleteKeyExW(HKEY    hKey, LPCTSTR lpSubKey, REGSAM  samDesired, DWORD   Reserved)
{
    OutputDebugString(L"[+] RegDeleteKeyExW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegDeleteKeyExW : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return RegDeleteKeyExW(hKey, lpSubKey, samDesired, Reserved);
}


        //////////////////////RegDeleteKeyExA/////////////////////////////////////
static LONG(WINAPI* realRegDeleteKeyExA)(HKEY    hKey, LPCSTR lpSubKey, REGSAM  samDesired, DWORD   Reserved) = RegDeleteKeyExA;
LONG WINAPI HookedRegDeleteKeyExA(HKEY    hKey, LPCSTR lpSubKey, REGSAM  samDesired, DWORD   Reserved)
{
    OutputDebugString(L"[+] RegDeleteKeyExA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegDeleteKeyExA : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return RegDeleteKeyExA(hKey, lpSubKey, samDesired, Reserved);
}


             //////////////////////RegDeleteKey/////////////////////////////////////
static LSTATUS(WINAPI* realRegDeleteKey)(HKEY hKey, LPCTSTR lpSubKey) = RegDeleteKey;
LSTATUS WINAPI HookedRegDeleteKey(HKEY hKey, LPCSTR lpSubKey)
{
    OutputDebugString(L"[+] realRegDeleteKey  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] realRegDeleteKey : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegCloseKey(hKey);
}

             /////////////////////RegDeleteKeyW/////////////////////////////////////
static LSTATUS(WINAPI* realRegDeleteKeyW)(HKEY hKey, LPCWSTR lpSubKey) = RegDeleteKeyW;
LSTATUS WINAPI HookedRegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey)
{
    OutputDebugString(L"[+] realRegDeleteKeyW  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] realRegDeleteKeyW : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegCloseKey(hKey);
}

            ///////////////////////RegDeleteKeyA/////////////////////////////////////
static LSTATUS(WINAPI* realRegDeleteKeyA)(HKEY hKey , LPCSTR lpSubKey) = RegDeleteKeyA;
LSTATUS WINAPI HookedRegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
{
    OutputDebugString(L"[+] RegDeleteKeyA  is called!!");
    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    logCall += L"[+] RegDeleteKeyA : ";
    //logCall += GetCurrentProcessId();
    //logCall += L" : ";
    logCall += L"lpSubKey# ";
    logCall += (LPCWSTR)lpSubKey;
    logCall += L" : ";
    logCall += s2ws(std::ctime(&end_time));
    return realRegCloseKey(hKey);
}



void printError(const char* msg)
{
    flag = 1;
    ofstream myfile;
    myfile.open("C:\\Windows\\Temp\\API_Calls_Monitor_Logs.txt", std::ios_base::app);
    myfile << msg;
    myfile.close();
}


/**

typedef HANDLE(WINAPI* CREATEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* DELETEFILEW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);



CREATEFILEW OrigCreteFileW = NULL;
DELETEFILEW OrigDeleteFileW = NULL;




typedef LONG(WINAPI* REGSETVALUE)(HKEY, LPCTSTR, DWORD, LPCTSTR, DWORD);
REGSETVALUE OrigRegSetValue;
LONG WINAPI HookRegSetValue(HKEY hKey, LPCTSTR lpSubKey, DWORD dwType, LPCTSTR lpData, DWORD cbData)
{
   // MessageBox(0, "And text here3", "MessageBox caption", MB_OK);
    OutputDebugString(__TEXT("Inside HookRegSetValue"));
    OutputDebugStringW((LPCWSTR)hKey);
    return OrigRegSetValue(hKey, lpSubKey, dwType, lpSubKey, cbData);
}

*/

void InstallHook()
{

    ofstream myfile1;
  //  myfile1.open("C:\\Windows\\Temp\\API_Calls_Monitor_Logs.txt", std::ios_base::app);
  //  myfile1 << "[+] Install Hook Entry.\n";
   // myfile1.close();
    /*
    // HMODULE modKernel32 = GetModuleHandle(TEXT("KERNEL32.dll"));
    HMODULE kernelbase = GetModuleHandle(L"KernelBase.dll");



    HMODULE modKernel32 = GetModuleHandle(TEXT("KERNEL32.dll"));
    HMODULE advapi32 = GetModuleHandle(TEXT("ADVAPI32.dll"));


    //  OrigCreteFileW = (CREATEFILEW)GetProcAddress(kernelbase, "CreateFileW");
    //  OrigDeleteFileW = (DELETEFILEW)GetProcAddress(kernelbase, "DeleteFileW");
   // OrigRegSetValue = (REGSETVALUE)GetProcAddress(kernelbase, "RegOpenKeyExW");
  //  if (OrigRegSetValue == NULL) 
  //  {
   //     OutputDebugString(L"[-] NULL HANDLE !!!!!!!\n");
  //  }
   

  

    //realRegOpenKey2 = (ptrRegOpenKey)GetProcAddress(kernelbase, "RegOpenKeyA");
    long status = DetourAttach(&(PVOID&)OrigRegSetValue, HookRegSetValue);
  //  OutputDebugString(__TEXT("HookRegSetValue"));
  */
   
    HMODULE NtDLL = GetModuleHandle(L"ntdll.dll");

  //  OrigRegSetValue = (REGSETVALUE)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RegOpenKeyExW");
    DetourRestoreAfterWith(); // avoid repetition
    DetourTransactionBegin(); // start hook
    DetourUpdateThread(GetCurrentThread());
   
    realNtCreateFile= (PtrRealNtCreateFile)GetProcAddress(NtDLL,  "NtCreateFile");
   long status =  DetourAttach(&(PVOID&)realNtCreateFile, HookedNtCreateFile);

   realNtWriteFile = ( PtrRealNtWriteFile)GetProcAddress(NtDLL, "NtWriteFile");
    status = DetourAttach(&(PVOID&)realNtWriteFile, HookedNtWriteFile);

    realNtOpenFile = (PtrRealNtOpenFile)GetProcAddress(NtDLL, "NtOpenFile");
    status = DetourAttach(&(PVOID&)realNtOpenFile, HookedNtOpenFile);
    

    /*
    // Process APIs Functions
    DetourAttach(&(PVOID&)realCreateProcess, HookedCreateProcess);
    DetourAttach(&(PVOID&)realCreateProcessA, HookedCreateProcessA);

    DetourAttach(&(PVOID&)TrueOpenProcess, InterceptOpenProcess);

    DetourAttach(&(PVOID&)realShellExecuteA, HookedShellExecuteA);

    DetourAttach(&(PVOID&)realExitProcess, HookedExitProcess);

    DetourAttach(&(PVOID&)realGetCommandLine, HookedGetCommandLine);

    DetourAttach(&(PVOID&)realGetStartupInfo, HookedGetStartupInfo);


    //File APIs Functions
   // DetourAttach(&(PVOID&)realWriteFile, HookedWriteFile);
    DetourAttach(&(PVOID&)realCreateFile, HookedCreateFile);
    DetourAttach(&(PVOID&)realCreateFileA, HookedCreateFileA);
    DetourAttach(&(PVOID&)realCreateFileW, HookedCreateFileW);

    DetourAttach(&(PVOID&)realNtCreateFile, HookedNtCreateFile);
    DetourAttach(&(PVOID&)realNtOpenFile, HookedNtOpenFile);
    DetourAttach(&(PVOID&)realNtWriteFile, HookedNtWriteFile);

    DetourAttach(&(PVOID&)realDeleteFile, HookedDeleteFile);
    DetourAttach(&(PVOID&)realDeleteFileA, HookedDeleteFileA);

    DetourAttach(&(PVOID&)realCopyFile, HookedCopyFile);
    DetourAttach(&(PVOID&)realCopyFileA, HookedCopyFileA);
    DetourAttach(&(PVOID&)realCopyFileW, HookedCopyFileW);

    DetourAttach(&(PVOID&)realFindFirstFile, HookedFindFirstFile);
    DetourAttach(&(PVOID&)realFindFirstFileA, HookedFindFirstFileA);
    DetourAttach(&(PVOID&)realFindFirstFileW, HookedFindFirstFileW);

    DetourAttach(&(PVOID&)realOpenMutex, HookedOpenMutex);
    DetourAttach(&(PVOID&)realOpenMutexA, HookedOpenMutexA);
    DetourAttach(&(PVOID&)realOpenMutexW, HookedOpenMutexW);

    DetourAttach(&(PVOID&)realCreateMutex, HookedCreateMutex);
    DetourAttach(&(PVOID&)realCreateMutexA, HookedCreateMutexA);
    DetourAttach(&(PVOID&)realCreateMutexW, HookedCreateMutexW);

    DetourAttach(&(PVOID&)realReleaseMutex, HookedReleaseMutex);
   

 // DetourAttach(&(PVOID&)realRegOpenKey2, HookedRegOpenKey1);
   DetourAttach(&(PVOID&)realRegOpenKey, HookedRegOpenKey);
    DetourAttach(&(PVOID&)realRegOpenKeyW, HookedRegOpenKeyW);
    DetourAttach(&(PVOID&)realRegOpenKeyA, HookedRegOpenKeyA);
    
    DetourAttach(&(PVOID&)realRegCloseKey, HookedRegCloseKey);

   long status =  DetourAttach(&(PVOID&)realRegDeleteKey, HookedRegDeleteKey);
    DetourAttach(&(PVOID&)realRegDeleteKeyW, HookedRegDeleteKeyW);
    DetourAttach(&(PVOID&)realRegDeleteKeyA, HookedRegDeleteKeyA);

    DetourAttach(&(PVOID&)realRegDeleteKeyEx, HookedRegDeleteKeyEx);
    DetourAttach(&(PVOID&)realRegDeleteKeyExA, HookedRegDeleteKeyExA);
    DetourAttach(&(PVOID&)realRegDeleteKeyExW, HookedRegDeleteKeyExW);
   
    DetourAttach(&(PVOID&)realRegOpenKeyEx, HookedRegOpenKeyEx);
    DetourAttach(&(PVOID&)realRegOpenKeyExA, HookedRegOpenKeyExA);
    DetourAttach(&(PVOID&)realRegOpenKeyExW, HookedRegOpenKeyExW);
    
    DetourAttach(&(PVOID&)realRegSetValueEx, HookedRegSetValueEx);
    DetourAttach(&(PVOID&)realRegSetValueExW, HookedRegSetValueExW);
    DetourAttach(&(PVOID&)realRegSetValueExA, HookedRegSetValueExA);


    DetourAttach(&(PVOID&)realRegSetKeyValue, HookedRegSetKeyValue);
    DetourAttach(&(PVOID&)realRegSetKeyValueA, HookedRegSetKeyValueA);
    DetourAttach(&(PVOID&)realRegSetKeyValueW, HookedRegSetKeyValueW);
    */
    LONG lError = DetourTransactionCommit(); // commit hook
  
    if (lError != NO_ERROR) {
        if (lError == ERROR_INVALID_DATA)
        {
            
            OutputDebugString(L"[-] ERROR_INVALID_DATA\n");
        }

        else if (lError == ERROR_INVALID_OPERATION)
        {
            
            OutputDebugString(L"[-] ERROR_INVALID_OPERATION\n");
        }
        else
        {
           
            OutputDebugString(L"[-] Other Error\n");
            if (status != NO_ERROR) 
            {
                if (status == ERROR_INVALID_BLOCK)
                {

                    OutputDebugString(L"[-] ERROR_INVALID_BLOCK ");
                }

                else if (status == ERROR_INVALID_HANDLE)
                {

                    OutputDebugString(L"[-] ERROR_INVALID_HANDLE ");
                }
                else if (status == ERROR_INVALID_OPERATION)
                {

                    OutputDebugString(L"[-] ERROR_INVALID_OPERATION ");
                }
                else {
                    OutputDebugString(L"[-] ERROR_NOT_ENOUGH_MEMORY  ");
                }
            }

        }
    }
}


void UninstallHook()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

   
//    DetourAttach(&(PVOID&)OrigRegSetValue, HookRegSetValue);
  
    DetourDetach(&(PVOID&)realNtCreateFile, HookedNtCreateFile);
    DetourDetach(&(PVOID&)realNtWriteFile, HookedNtWriteFile);
    DetourDetach(&(PVOID&)realNtOpenFile, HookedNtOpenFile);
    /*
    // Process APIs Functions
    DetourDetach(&(PVOID&)realCreateProcess, HookedCreateProcess);
    DetourDetach(&(PVOID&)realCreateProcessA, HookedCreateProcessA);
    DetourDetach(&(PVOID&)TrueOpenProcess, InterceptOpenProcess);
    DetourDetach(&(PVOID&)realShellExecuteA, HookedShellExecuteA);
    DetourDetach(&(PVOID&)realExitProcess, HookedExitProcess);
    DetourDetach(&(PVOID&)realGetCommandLine, HookedGetCommandLine);
    DetourDetach(&(PVOID&)realGetStartupInfo, HookedGetStartupInfo);
   
    
    //File APIs Functions
   // DetourDetach(&(PVOID&)realWriteFile, HookedWriteFile);
    DetourDetach(&(PVOID&)realCreateFile, HookedCreateFile);
    DetourDetach(&(PVOID&)realCreateFileA, HookedCreateFileA);
    DetourDetach(&(PVOID&)realCreateFileW, HookedCreateFileW);
    DetourDetach(&(PVOID&)realNtCreateFile, HookedNtCreateFile);

    DetourDetach(&(PVOID&)realDeleteFile, HookedDeleteFile);
    DetourDetach(&(PVOID&)realDeleteFileA, HookedDeleteFileA);

    DetourDetach(&(PVOID&)realCopyFile, HookedCopyFile);
    DetourDetach(&(PVOID&)realCopyFileA, HookedCopyFileA);
    DetourDetach(&(PVOID&)realCopyFileW, HookedCopyFileW);

    DetourDetach(&(PVOID&)realFindFirstFile, HookedFindFirstFile);
    DetourDetach(&(PVOID&)realFindFirstFileA, HookedFindFirstFileA);
    DetourDetach(&(PVOID&)realFindFirstFileW, HookedFindFirstFileW);

    DetourDetach(&(PVOID&)realOpenMutex, HookedOpenMutex);
    DetourDetach(&(PVOID&)realOpenMutexA, HookedOpenMutexA);
    DetourDetach(&(PVOID&)realOpenMutexW, HookedOpenMutexW);

    DetourDetach(&(PVOID&)realCreateMutex, HookedCreateMutex);
    DetourDetach(&(PVOID&)realCreateMutexA, HookedCreateMutexA);
    DetourDetach(&(PVOID&)realCreateMutexW, HookedCreateMutexW);

    DetourDetach(&(PVOID&)realReleaseMutex, HookedReleaseMutex);
   

   // DetourDetach(&(PVOID&)realRegOpenKey2, HookedRegOpenKey1);
    DetourDetach(&(PVOID&)realRegOpenKey, HookedRegOpenKey);
    DetourDetach(&(PVOID&)realRegOpenKeyW, HookedRegOpenKeyW);
    DetourDetach(&(PVOID&)realRegOpenKeyA, HookedRegOpenKeyA);
   
    DetourDetach(&(PVOID&)realRegCloseKey, HookedRegCloseKey);

    DetourDetach(&(PVOID&)realRegDeleteKey, HookedRegDeleteKey);
    DetourDetach(&(PVOID&)realRegDeleteKeyW, HookedRegDeleteKeyW);
    DetourDetach(&(PVOID&)realRegDeleteKeyA, HookedRegDeleteKeyA);

    DetourDetach(&(PVOID&)realRegDeleteKeyEx, HookedRegDeleteKeyEx);
    DetourDetach(&(PVOID&)realRegDeleteKeyExA, HookedRegDeleteKeyExA);
    DetourDetach(&(PVOID&)realRegDeleteKeyExW, HookedRegDeleteKeyExW);
    
    DetourDetach(&(PVOID&)realRegOpenKeyEx, HookedRegOpenKeyEx);
    DetourDetach(&(PVOID&)realRegOpenKeyExA, HookedRegOpenKeyExA);
    DetourDetach(&(PVOID&)realRegOpenKeyExW, HookedRegOpenKeyExW);

    DetourDetach(&(PVOID&)realRegSetValueEx, HookedRegSetValueEx);
    DetourDetach(&(PVOID&)realRegSetValueExW, HookedRegSetValueExW);
    DetourDetach(&(PVOID&)realRegSetValueExA, HookedRegSetValueExA);

    DetourDetach(&(PVOID&)realRegSetKeyValue, HookedRegSetKeyValue);
    DetourDetach(&(PVOID&)realRegSetKeyValueA, HookedRegSetKeyValueA);
    DetourDetach(&(PVOID&)realRegSetKeyValueW, HookedRegSetKeyValueW);
    */
    DetourTransactionCommit();
}


BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call,  LPVOID lpReserved )
{

    HANDLE currProc = GetCurrentProcess();
  

    auto start = std::chrono::system_clock::now();
    std::time_t end_time = std::chrono::system_clock::to_time_t(start);
    ofstream myfile;
    myfile.open("C:\\Windows\\Temp\\API_Calls_Monitor_Logs.txt");
    // myfile << "[+] DLLMain Entry.\n" << "[+] API Calls Monitor Started at: " << "[+] process ID: " << GetCurrentProcessId() << endl;
    myfile << "[+] DLLMain Entry.\n" << "[+] API Calls Monitor Started at: " << std::ctime(&end_time) << "[+] process ID: " << GetCurrentProcessId() << endl;
    myfile.close();
  
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
          //  ofstream myfile;
          //  myfile.open("C:\\Windows\\Temp\\API_Calls_Monitor_Logs.txt", std::ios_base::app);
          //  myfile << "[+] DLL is Attached.\n";
            

            OutputDebugString(L"[+] DLL is Attached \n");

            DisableThreadLibraryCalls(hModule);
           
            InstallHook();

            break;
        }
        case DLL_THREAD_ATTACH:
        {
            break;
        }
        case DLL_THREAD_DETACH:
        {
            break;
        }
        case DLL_PROCESS_DETACH:
        {

            
          //  printError("[+] DLL is Deattached.\n");

            UninstallHook();
            OutputDebugString(logCall.c_str());
            wofstream myfile1;
            flag = 1;

           


            myfile1.open("C:\\Windows\\Temp\\API_Calls_Monitor_Logs.txt", std::ios_base::app);
            myfile1 << logCall;
            myfile1.close();

            break;
        }
    }
    return TRUE;
}

