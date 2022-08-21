#include "stopwatch.h"

using namespace std;

SdStopwatch::SdStopwatch()
{
	etime.QuadPart = 0;
	stime.QuadPart = 0;

	// Freqency may be in 100/10/1 ns, depending on device
	// Get exect ns resolution by dividing 1 000 000 000 / freq
	QueryPerformanceFrequency(&freq);
	ns_per_tick = 1000000000/freq.QuadPart;
	//cout << "TIMER FREQ: " << dec << freq.QuadPart << " t/s" << endl;

	// Note: int64 can store up to 58 494 years, 88 days, 5 h, 36 m, 10 s, 955 ms, 161 us 600 ns
	// at 10 000 000 ticks per second freqency (100 ns)
}

std::string SdStopwatch::Str()
{

	ui64 timing = etime.QuadPart - stime.QuadPart;

	ui64 s = timing/freq.QuadPart;
	ui64 ms = timing/(1000000/ns_per_tick) - s * 1000;
	ui64 us = timing/(1000/ns_per_tick) - s * 1000000 - ms * 1000;
	ui64 ns = timing * ns_per_tick - s * 1000000000 - ms * 1000000 - us * 1000;
	// This math will overflow when timing reach 584.9424 years.
	// Should be totaly enough for profiling!

	std::stringstream ss;
	if(!s)
	{
		if(!ms)
		{
			if(!us)
			{
				ss << ns << " ns";
			}
			else
			{
				ss << us << '.' << ns << " us";
			}
		}
		else
		{
			ss << ms << '.' << us << '\'' << std::setw(3) << std::setfill('0') << ns << " ms";
		}
	}
	else
	{
		if(s < 60)
		{
			ss << s << '.' << ms << " s ";
		}
		else if(s < 3600)
		{
			ss << s/60 << ':' << s%60 << " m ";
		}
		else if(s < 86400)
		{
			ss << s/3600 << ':' << (s%3600)/60 << ':' << s%3600%60 << " h ";
		}
		else
		{
			ss << s/86400 << " d " << (s%86400)/3600 << " h ";
		}
	}

	return ss.str();
}

string err2s(LSTATUS res)
{
	char buff[300];

	FormatMessageA(
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		(DWORD)res,
		0,
		buff,
		300,
		NULL);

	return string("[E:") + to_string(res) + "] " + string(buff);
}

void perr()
{
	cout << err2s(GetLastError());
}