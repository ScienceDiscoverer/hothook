#pragma once

typedef unsigned long long ui64;

//#define LDW 
//#define HDW

// All keys must have scan code in low DWORD and virtual code in high DWORD
// ACER PREDATOR TRITON 300 PT315-52-7337
#define K_PREDATOR 0xFF00000075 // VC0xFF SC0x75 Predator special key, opens PredatorSense
#define K_F1       0x700000003B // VC0x70 SC0x3B F1 key


#define NINJA

#ifndef NINJA
#define PLH(x) std::cout << std::hex << std::uppercase << x << std::endl
#define PLD(x) std::cout << std::dec << x << std::endl
#define WPLH(x) std::wcout << std::hex << std::uppercase << x << std::endl
#define WPLD(x) std::wcout << std::dec << x << std::endl
#define PERR perr()
#define SW_CREATE SdStopwatch sw
#define SW_SET sw.Set()
#define SW_STOP sw.Stop()
#define SW_STR sw.Str()
#else
#define PLH(x)
#define PLD(x)
#define WPLH(x)
#define WPLD(x)
#define PERR
#define SW_CREATE
#define SW_SET
#define SW_STOP
#define SW_STR
#endif