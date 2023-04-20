/*
    Author  => Abdallah Mohamed
    Email   => elsharifabdallah53@gmail.com
    Github  => @abdallah-elsharif
*/

#include "Hooker.hpp"

BOOL IsPath(PCHAR cpLine)
{
    for (; *cpLine; cpLine++)
        if ( *cpLine == '\\' ) return TRUE;

    return FALSE;
}

PCHAR GetBaseName(PCHAR cpLine)
{
    // Go to the end of the string
    cpLine += strlen(cpLine);

    // Go back until find backslash
    while ( *(--cpLine - 1) != '\\' );

    return cpLine;
}

BOOL InsensitveStrCmp(PCHAR cpStr1, PCHAR cpStr2, SIZE_T nSize)
{
    CHAR c1, c2;

    while ( nSize-- )
    {
        c1 = *cpStr1++;
        c2 = *cpStr2++;

        if ( !(c1 & (1 << 5)) ) // Check if not lowercase
            c1 += 20; // Convert to lowercase

        if ( !(c2 & (1 << 5)) ) // Check if not lowercase
            c2 += 20; // Convert to lowercase

        if ( c1 != c2 ) return FALSE;
    }

    return TRUE;
}

BOOL InitalizeHooker()
{
    HookerSink* pHooker;
    IWbemLocator* pLocator = NULL;
    IWbemServices* pSvc = NULL;
    BSTR bsQueryLang, bsQuery;

    // Intialize COM
    if ( FAILED(CoInitializeEx(0, COINIT_MULTITHREADED)) )
    {
#ifdef DEBUG
        PRINT_DEBUG("Failed to initialize COM library.");
#endif
        return FALSE;              // Program has failed.
    }

    // Initialize Security
    if (
        FAILED(
            CoInitializeSecurity(
                NULL,
                -1,      // COM negotiates service                  
                NULL,    // Authentication services
                NULL,    // Reserved
                RPC_C_AUTHN_LEVEL_DEFAULT,    // authentication
                RPC_C_IMP_LEVEL_IMPERSONATE,  // Impersonation
                NULL,             // Authentication info 
                EOAC_NONE,        // Additional capabilities
                NULL              // Reserved
            )
        )
        )
    {
#ifdef DEBUG
        PRINT_DEBUG("Failed to initialize security.");
#endif
        CoUninitialize();
        return FALSE;
    }

    if (
        FAILED(
            CoCreateInstance(
                CLSID_WbemLocator,
                0,
                CLSCTX_INPROC_SERVER,
                IID_IWbemLocator,
                (LPVOID*)&pLocator
            )
        )
        )
    {
#ifdef DEBUG
        PRINT_DEBUG("Failed to create IWbemLocator object.");
#endif
        CoUninitialize();
        return FALSE;
    }

    // Connect to namespace
    if (
        FAILED(
            pLocator->ConnectServer(
                _bstr_t(L"ROOT\\CIMV2"), // WMI namespace
                NULL,                    // User name
                NULL,                    // User password
                0,                       // Locale
                NULL,                    // Security flags                 
                0,                       // Authority       
                0,                       // Context object
                &pSvc                    // IWbemServices proxy
            )
        )
        )
    {
#ifdef DEBUG
        PRINT_DEBUG("Could not connect to namespace.");
#endif
        pLocator->Release();
        CoUninitialize();
        return FALSE;
    }

#ifdef DEBUG
    PRINT_DEBUG("Connected to ROOT\\CIMV2 WMI namespace");
#endif

    // Set the IWbemServices proxy so that impersonation
    // of the user (client) occurs.

    if (
        FAILED(
            CoSetProxyBlanket(
                pSvc,                         // the proxy to set
                RPC_C_AUTHN_WINNT,            // authentication service
                RPC_C_AUTHZ_NONE,             // authorization service
                NULL,                         // Server principal name
                RPC_C_AUTHN_LEVEL_CALL,       // authentication level
                RPC_C_IMP_LEVEL_IMPERSONATE,  // impersonation level
                NULL,                         // client identity 
                EOAC_NONE                     // proxy capabilities     
            )
        )
        )
    {
#ifdef DEBUG
        PRINT_DEBUG("Could not set proxy blanket.");
#endif
        pSvc->Release();
        pLocator->Release();
        CoUninitialize();
        return FALSE;
    }

    bsQueryLang = SysAllocString(L"WQL");
    bsQuery = SysAllocString(L"SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'");
    pHooker = new HookerSink;

    if (
        FAILED(
            pSvc->ExecNotificationQueryAsync(bsQueryLang, bsQuery, WBEM_FLAG_SEND_STATUS, NULL, pHooker)
        )
        )
    {
#ifdef DEBUG
        PRINT_DEBUG("Failed to register a sink.");
#endif
        pSvc->Release();
        pLocator->Release();
        pHooker->Release();
        CoUninitialize();
        return FALSE;
    }

    // Don't stop, stay running
    WaitForSingleObject(GetCurrentThread(), INFINITE);

    // Clear memory
    SysFreeString(bsQueryLang);
    SysFreeString(bsQuery);
    pSvc->CancelAsyncCall(pHooker);
    pSvc->Release();
    pLocator->Release();
    pHooker->Release();
    CoUninitialize();

    return TRUE;
}

BOOL IsHookingSucceed(HANDLE hProc)
{
    HMODULE hMods[1024];
    DWORD dwNeeded = 0, dwNumberOfModules;
    CHAR cModName[MAX_PATH];

    if ( EnumProcessModules(hProc, hMods, sizeof(hMods), &dwNeeded) )
    {
        dwNumberOfModules = dwNeeded / sizeof(HMODULE);

        while ( dwNumberOfModules-- )
        {
            if ( !GetModuleBaseNameA(hProc, hMods[dwNumberOfModules], cModName, MAX_PATH) )
                return FALSE;

            if ( InsensitveStrCmp((PCHAR)DLLNAME, cModName, strlen(DLLNAME)))
                return TRUE;

        }
    }

    return FALSE;
}

BOOL HookProcess(PCHAR cpProcName, INT nProcId)
{
    HANDLE hProc = NULL;
    LPVOID lpRemoteBuffer;
    LPSTR lpBuffer;
    DWORD dwSize, dwBytesRead = 0;
    BOOL bSuccess = FALSE;
    CHAR cFullPath[MAX_PATH];
    PTHREAD_START_ROUTINE pThreatStartRoutine;

    std::cout << " - " << cpProcName << " Process spawned procid = " << nProcId << ", try to hook it" << std::endl;

    // Get length of current directory
    if ( !(dwSize = GetCurrentDirectoryA(0, NULL)) )
        return FALSE;

    if ( !(lpBuffer = (LPSTR) HeapAlloc(GetProcessHeap(), 0, dwSize + 1)) )
        return FALSE;

    if ( !(dwSize = GetCurrentDirectoryA(dwSize + 1, lpBuffer)) )
        return FALSE;

    if ( !(PathCombineA(cFullPath, lpBuffer, DLLNAME)) )
        goto CLEANUP;

    if (!PathFileExistsA(cFullPath))
    {
#ifdef DEBUG
        PRINT_DEBUG("Our DLL doesn't exist at this path " << cFullPath);
#endif
        goto CLEANUP;
    }

    dwSize = (DWORD) strlen(cFullPath) + 1;

    if ( !(hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nProcId)) )
        goto CLEANUP;

    if ( !(lpRemoteBuffer = VirtualAllocEx(hProc, NULL, dwSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) )
        goto CLEANUP;

    if ( !WriteProcessMemory(hProc, lpRemoteBuffer, cFullPath, dwSize, NULL) )
        goto CLEANUP;

    if ( !(pThreatStartRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")) )
        goto CLEANUP;

    if ( !CreateRemoteThread(hProc, NULL, 0, pThreatStartRoutine, lpRemoteBuffer, 0, NULL) )
        goto CLEANUP;

    // Wait a few seconds 
    Sleep(2000);

    if ( !IsHookingSucceed(hProc) )
        goto CLEANUP;

    bSuccess = TRUE;
    std::cout << " - " << cpProcName << " Hooked successfully" << std::endl;

CLEANUP:
    HeapFree(GetProcessHeap(), 0, lpBuffer);
    if ( hProc ) CloseHandle(hProc);

    return bSuccess;
}

ULONG HookerSink::AddRef()
{
    return InterlockedIncrement(&m_lRef);
}

ULONG HookerSink::Release()
{
    LONG lRef;
    
    if ( !( lRef = InterlockedDecrement(&m_lRef) ) )
        delete this;

    return lRef;
}

HRESULT HookerSink::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink*)this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
     
    return E_NOINTERFACE;
}

HRESULT HookerSink::Indicate(long lObjCount, IWbemClassObject** pArray)
{
    IWbemClassObject* pObj;
    _variant_t vProperties, tProcName, tProcId;
    PCHAR cpProcName;
    SIZE_T nProcNameLength, nSize;

    while ( lObjCount-- )
    {
        pObj = *pArray++;

        if ( FAILED( pObj->Get(_bstr_t(L"TargetInstance"), 0, &vProperties, 0, 0) ) )
        {
#ifdef DEBUG
            PRINT_DEBUG("Failed to get a pointer to the object properties.");
#endif
            break;
        }

        if ( FAILED( ( (IUnknown*)vProperties )->QueryInterface(IID_IWbemClassObject, (LPVOID *)&pObj) ) )
        {
#ifdef DEBUG
            PRINT_DEBUG("Failed to query interface.");
#endif
            VariantClear(&vProperties);
            break;
        }

        if (FAILED(pObj->Get(L"Name", 0, &tProcName, NULL, NULL)) || tProcName.vt == VT_NULL || tProcName.vt == VT_EMPTY)
        {
#ifdef DEBUG
            PRINT_DEBUG("Failed to get process name.");
#endif
            VariantClear(&vProperties);
            break;
        }

        if (FAILED(pObj->Get(L"Handle", 0, &tProcId, NULL, NULL)) || tProcId.vt == VT_NULL || tProcId.vt == VT_EMPTY)
        {
#ifdef DEBUG
            PRINT_DEBUG("Failed to get process id.");
#endif
            VariantClear(&vProperties);
            VariantClear(&tProcName);
            break;
        }

        nSize = wcslen(tProcName.bstrVal) + 1;

        if (! (cpProcName = (PCHAR)HeapAlloc(GetProcessHeap(), 0, nSize)) )
        {
#ifdef DEBUG
            PRINT_DEBUG("Failed to allocate memory for process name.");
#endif
            VariantClear(&vProperties);
            VariantClear(&tProcName);
            VariantClear(&tProcId);
            break;
        }

        // Convert to ansi string
        if ( wcstombs_s(&nProcNameLength, cpProcName, nSize, tProcName.bstrVal, nSize - 1) != 0 )
        {
#ifdef DEBUG
            PRINT_DEBUG("Failed to convert process name from unicode to ansi.");
#endif
            VariantClear(&vProperties);
            VariantClear(&tProcName);
            VariantClear(&tProcId);
            break;
        }
        
        if ( RtlEqualMemory(g_cpProcName, cpProcName, strlen(g_cpProcName)) )
        {
            if ( !HookProcess(cpProcName, _wtoi(tProcId.bstrVal)) )
            {
#ifdef DEBUG
                PRINT_DEBUG("Failed to hook the process.");
#endif
            }
        }

        HeapFree(GetProcessHeap(), 0, cpProcName);
        VariantClear(&vProperties);
        VariantClear(&tProcName);
        VariantClear(&tProcId);
    }

    return WBEM_S_NO_ERROR;
}

HRESULT HookerSink::SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR* pObjParam)
{
    return WBEM_S_NO_ERROR;
}


INT main(INT argc, PCHAR argv[])
{
    BOOL bSuccess;

    if ( argc < 2 )
    {
        std::cout << "Usage :\n\t";
        std::cout << (IsPath(argv[0]) ? GetBaseName(argv[0]) : argv[0]);
        std::cout << " <ProgramName.exe>" << std::endl;
        std::cout << "\tNote -> " << DLLNAME << " should be in the same directory" << std::endl;
        return EXIT_FAILURE;
    }

    if ( !(g_cpProcName = (PCHAR)HeapAlloc(GetProcessHeap(), 1, strlen(argv[0]) + 1)) )
    {
#ifdef DEBUG
        PRINT_DEBUG("Could not allocate memory for process name.");
#endif
        return EXIT_FAILURE;
    }

    RtlCopyMemory(g_cpProcName, argv[1], strlen(argv[1]) + 1);
    bSuccess = InitalizeHooker();
    HeapFree(GetProcessHeap(), 0, g_cpProcName);

    return ( bSuccess ? EXIT_SUCCESS : EXIT_FAILURE );
}

