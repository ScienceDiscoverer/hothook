// dllmain.cpp : Defines the entry point for the DLL application.
#include "exports.h"

//#include <sstream>

//HMODULE my_exec_addr;

BOOL APIENTRY DllMain(
	_In_	HMODULE hm,			// "Handle" to "Module" in fact its base adress of DLL
	_In_	DWORD creason,		// Reason for calling this function by the OS
	_In_	LPVOID reserved)	// Dynamic/Statc link flag or FreeLibrary/Process term.
{
    switch(creason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hm);
        //my_exec_addr = hm;
        //CreateThread(NULL, 0, injectThread, 0, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
        //system("echo DLL_THREAD_ATTACH");
        break;
    case DLL_THREAD_DETACH:
        //system("echo DLL_THREAD_DETACH");
        break;
    case DLL_PROCESS_DETACH:
        //system("echo DLL_THREAD_DETACH");
        break;
    }
    return TRUE;
}

DWORD injectThread(LPVOID p)
{
    //AllowSetForegroundWindow(ASFW_ANY);
    //system("echo YOUR TOP-Z STATUS WAS NIKKED! HEUHUEHUEHU!");

    /*HMODULE exec_addr;
    GetModuleHandleEx
    (
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCTSTR)DllMain,
        &exec_addr
    );*/

    /*system("echo modfromdllmain:");
    system(std::to_string((uint64_t)my_exec_addr).c_str());

    system("echo getmodhandex:");
    system(std::to_string((uint64_t)exec_addr).c_str());*/

    /*DWORD res = WaitForSingleObject(p, INFINITE);

    DWORD last_err = GetLastError();

    system("echo wait finished res:");
    system(std::to_string((uint64_t)res).c_str());
    system("echo lasterr:");
    system(std::to_string((uint64_t)last_err).c_str());*/

    //Very important! Using just FreeLibrary will cause race condition
    //DLL might get unloaded before the thread exits!
    //Sleep(50);
    //FreeLibrary(exec_addr);
    //FreeLibraryAndExitThread(exec_addr, 0);
    //
    //system("echo injectThread execin ugh... will crash?");
    return 0;
}