#pragma once
#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include "keys.h"

//using namespace std;

class SdStopwatch
{
public:
	SdStopwatch();

	void Set();
	void Stop();
	std::string Str();
	ui64 Ms();

private:
	LARGE_INTEGER freq;
	LARGE_INTEGER stime;
	LARGE_INTEGER etime;
	ui64 ns_per_tick;
};

inline void SdStopwatch::Set()
{
	QueryPerformanceCounter(&stime);
}

inline void SdStopwatch::Stop()
{
	QueryPerformanceCounter(&etime);
}

inline ui64 SdStopwatch::Ms()
{
	return (etime.QuadPart - stime.QuadPart)/(1000000/ns_per_tick);
}

void perr();