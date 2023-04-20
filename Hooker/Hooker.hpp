/*
    Author  => Abdallah Mohamed
    Email   => elsharifabdallah53@gmail.com
    Github  => @abdallah-elsharif
*/

#pragma once

// To disable printing extra info you should undefine DEBUG from Properties -> Configuration Properties -> C/C++ -> Preprocessor.

#include <Windows.h>
#include <Shlwapi.h>
#include <psapi.h>
#include <iostream>

#define _WIN32_DCOM

#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "wbemuuid.lib")

#if defined(DEBUG)
#define PRINT_DEBUG(x) std::cout << " - " << x << std::endl
#endif

#define DLLNAME "APICallsHooker.dll"

// Target process name
PCHAR g_cpProcName;


class HookerSink : public IWbemObjectSink
{
    LONG m_lRef;
    bool bDone;

public:
    HookerSink() { m_lRef = 0; this->AddRef(); }
    ~HookerSink() { bDone = TRUE; }

    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv);

    virtual HRESULT STDMETHODCALLTYPE Indicate(
        /* [in] */
        LONG lObjectCount,
        /* [size_is][in] */
        IWbemClassObject __RPC_FAR* __RPC_FAR* apObjArray
    );

    virtual HRESULT STDMETHODCALLTYPE SetStatus(
        /* [in] */ LONG lFlags,
        /* [in] */ HRESULT hResult,
        /* [in] */ BSTR strParam,
        /* [in] */ IWbemClassObject __RPC_FAR* pObjParam
    );
};