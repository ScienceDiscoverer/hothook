#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define EXP extern "C" __declspec(dllexport)




EXP DWORD CALLBACK injectThread(LPVOID p);