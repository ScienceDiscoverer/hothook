#include <windows.h>
#include "gui.h"
#include "data.h"
#include "keys.h"
#include "stopwatch.h"

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#ifdef UNICODE
#define TOWSTR(x) L ## x
#else
#define TOWSTR(x) x
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define CHECK_CALL(x) if((x) != S_OK) \
	{ MessageBox(NULL, TOWSTR(#x) ## " line: " TOSTRING(__LINE__), \
	TOWSTR("hothook error"), MB_OK); return -1; }

#define APP_GUID "-{C81F7F6D-F1B6-420C-A35C-0A043C6E8EFC}"
#define REGISTER_MESSAGE(n) \
	static const UINT n = RegisterWindowMessage(TOWSTR(#n APP_GUID))

// Supported hook types - -
#define HOOK_TASKBAR_MB 0x1
#define HOOK_GLOBAL_KB  0x2
// - - - - - - - - - - - -


typedef DWORD(__stdcall* MASTERPROC)(DWORD master_thread_id, UINT mb_msg, UINT mw_msg, UINT k_msg);
typedef void(__stdcall* FILTERPROC)(UINT virt, UINT scan);
typedef void(__stdcall* DISCARDPROC)(UINT discard);

REGISTER_MESSAGE(UWM_MBUTTON);     // WP: T:MD F:MU   | LP: LW: Mouse X HW: Mouse Y
REGISTER_MESSAGE(UWM_MWHEEL);	   // WP: Wheel Delta | LP: LW: Mouse X HW: Mouse Y
REGISTER_MESSAGE(UWM_KEYPRESS);    // WP: Key State   | LP: LW: Virt.C. HW: Scan C.
REGISTER_MESSAGE(UWM_NEWINSTANCE); // WP: Not Used    | LP: Not Used
REGISTER_MESSAGE(UWM_GUI_ACTION);  // WP: GUI_ACTION  | LP: New Value

// Config variables - -
bool autostart = false;
bool keyb_hook = false;
bool block_inp = true;
DWORD key_virtc = 0xFFFFFFFF;
DWORD key_scanc = 0xFFFFFFFF;
// - - - - - - - - - -

// Config variable names - - - - - -
LPCWSTR keyb_hook_n = L"keyb_hook";
LPCWSTR block_inp_n = L"block_inp";
LPCWSTR key_virtc_n = L"key_virtc";
LPCWSTR key_scanc_n = L"key_scanc";
// - - - - - - - - - - - - - - - - -

bool window_is_alive;
bool filter_is_setting_up; // User is choosing global key

HINSTANCE dll_start_addr; // A.K.A. "The Instance"
HHOOK mouse_hook;
HHOOK ll_kb_hook;

FILTERPROC setKbFilter;
DISCARDPROC setDiscardInp;

int respondToKeypress(WPARAM k_msg, LPARAM key);

/*___________________________________________________________________
|  respondToGUIaction:
|    Handles any possible GUI action taken
|
|   a_type: One of GUI_ACTION codes
|  new_val: New value of the global config passed by GUI
|
|  Return value:
|    Action handled successfully -> 0
|           Something went worng -> -1
|____________________________________________________________________*/
int respondToGUIaction(int a_type, int new_val);


/*___________________________________________________________________
|  startHooking:
|    Sets up Windows Hooks specified by input parameter
|
|  whats_hooking: One or multiple s. HOOK_ types (use | to combine)
|
|  Return value:
|    Hook(s) hooked -> 0
|    Hook(s) missed -> -1
|____________________________________________________________________*/
int startHooking(int whats_hooking);


/*___________________________________________________________________
|  stopHooking:
|    Unhooks one or more of the already running Windows Hooks
|
|  whats_unhooking: One or multiple s. HOOK_ types (use | to combine)
|
|  Return value:
|    Hook(s) unhooked -> 0
|       Hook(s) stuck -> -1
|____________________________________________________________________*/
int stopHooking(int whats_unhooking);

int spawnProc(LPCWSTR app, LPCWSTR cmd);

void stealFground();

DWORD gimpHelpMaxThread(LPVOID p);





// HINSTANCE -> "handle" to "instance" aka "module".
// It's NOT a handle. And not to "instance" or "module".
// I's all 16 bit Windows legacy backwards compatability nonsense.
// Since 16-bit Windows had a common address space, the GetInstanceData function was really
// nothing more than a hmemcpy, and many programs relied on this and just used raw hmemcpy
// instead of using the documented API.
// In Win32/Win64 it's actually executable (DLL or EXE) image.
// HINSTANCE points to actual virtual adress where first byte of
// executable's code is located: cout << (const char*)hinst ---> MZ? (? = 0x90/0x00)
int WINAPI wWinMain(
	_In_		HINSTANCE hinst,	// "Handle" to "instance"
	_In_opt_	HINSTANCE phinst,	// "Handle" to "previous instance", always NULL
	_In_		PWSTR cmd,			// Command line arguments
	_In_		int show)			// Default user preference for ShowWindow()
{
	// Seems that only local thread spesific hooks require this
	ChangeWindowMessageFilter(UWM_MBUTTON, MSGFLT_ADD);
	// I will still add other custom messages, just in case!
	ChangeWindowMessageFilter(UWM_KEYPRESS, MSGFLT_ADD);
	ChangeWindowMessageFilter(UWM_NEWINSTANCE, MSGFLT_ADD);
	ChangeWindowMessageFilter(UWM_MWHEEL, MSGFLT_ADD);
	ChangeWindowMessageFilter(UWM_GUI_ACTION, MSGFLT_ADD);


#ifndef NINJA
	AllocConsole();
	FILE* s = freopen("CONIN$", "r", stdin);
	s = freopen("CONOUT$", "w", stdout);
	s = freopen("CONOUT$", "w", stderr);
#endif

	PLH("HINST: " << hinst);

	// Check user settings and init GUI
	//autostart = regAutoStChk();
	autostart = taskAutoStChk();
	keyb_hook = regChk(keyb_hook_n);
	block_inp = !regChk(block_inp_n);

	setControls(autostart, keyb_hook, block_inp);

	key_virtc = regChk(key_virtc_n) ? regGet(key_virtc_n) : key_virtc;
	key_scanc = regChk(key_scanc_n) ? regGet(key_scanc_n) : key_scanc;

	setButtText(key_virtc, key_scanc);

	if(startHooking(HOOK_GLOBAL_KB) != 0)
	{
		return -1;
	}

	setKbFilter(key_virtc, key_scanc);
	setDiscardInp(block_inp);

#ifdef NINJA
	if(wcscmp(cmd, L"-silent"))
	{
		initGUI(hinst, UWM_GUI_ACTION);
		CHECK_CALL(!spawnMainWnd());
		window_is_alive = true;
	}
#endif



	//// debug
	//initGUI(hinst, UWM_GUI_ACTION);
	//stealFground();
	//CHECK_CALL(!spawnMainWnd());
	//window_is_alive = true;


	// Create Fake Window to get active monitor's DPI
	//initGUI(hinst, UWM_GUI_ACTION);
	////HWND hwnd = CreateWindowEx(0, L"Button", 0, 0,
	////	0, 0, 0, 0, 0, 0, hinst, 0);

	//HWND hwnd = spawnMainWnd();
	//stealFground();
	//SetForegroundWindow(hwnd);
	//SetCapture(hwnd); // Capture mouse
	//SetFocus(hwnd); // Capture keyboard
	//SetActiveWindow(hwnd);
	//EnableWindow(hwnd, TRUE);
	//SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	//SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
	////Sleep(100);
	//DestroyWindow(hwnd);









	ULONGLONG stime = 0, etime = 0;
	MSG msg;
	while(GetMessage(&msg, NULL, 0, 0) != 0)
	{
		if(msg.message == UWM_MBUTTON)
		{

		}
		else if(msg.message == UWM_MWHEEL)
		{

		}
		else if(msg.message == UWM_NEWINSTANCE)
		{
			/*if(MessageBoxA(NULL, "2ND INSTANCE ON!", "EXIT?!", MB_YESNO | MB_TOPMOST) == IDYES)
			{
				break;
			}*/
			
			/*AllocConsole();
			FILE* s = freopen("CONIN$", "r", stdin);
			s = freopen("CONOUT$", "w", stdout);
			s = freopen("CONOUT$", "w", stderr);*/
			
			if(!window_is_alive)
			{
				initGUI(hinst, UWM_GUI_ACTION);
				stealFground();
				CHECK_CALL(!spawnMainWnd());
				window_is_alive = true;
			}
		}
		else if(msg.message == UWM_KEYPRESS)
		{
			respondToKeypress(msg.wParam, msg.lParam);
		}
		else if(msg.message == UWM_GUI_ACTION)
		{
			respondToGUIaction((int)msg.wParam, (int)msg.lParam);
		}

		// Only needed when Edit input boxes are used
		//TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	stopHooking(HOOK_TASKBAR_MB | HOOK_GLOBAL_KB);

	return (int)msg.wParam;
}

int respondToKeypress(WPARAM k_msg, LPARAM key)
{
	bool kdown = k_msg == WM_KEYDOWN || k_msg == WM_SYSKEYDOWN;

	static SdStopwatch long_prs;
	//static SdStopwatch dbl_prs;
	bool dbprs = false;
	static int kdowns = 0;
	
	// TODO: Double Press needs async timer
	switch(key)
	{
	case K_PREDATOR:
		if(kdown)
		{
			if(++kdowns == 1)
			{
				long_prs.Set();
			}

			PLD("kdowns: " << kdowns);
			//dbl_prs.Stop();

			PLD("keydown");
		}
		else
		{
			long_prs.Stop();
			kdowns = 0;

			PLD("keyup");
			PLD(long_prs.Str());

			if(long_prs.Ms() < 350)
			{
				spawnProc(L"C:\\Windows\\regedit.exe", L"/m");
			}
			else
			{
				spawnProc(L"C:\\Windows\\System32\\cmd.exe", L"/q /k cd C:\\ & title CMD");
			}
			//dbl_prs.Set();
		}
		break;
	case K_F1:
		if(!kdown)
		{
			CreateThread(NULL, 0, gimpHelpMaxThread, NULL, 0, NULL);
		}
		break;
	default:
		break;
	}
	
	return 0;
}

int respondToGUIaction(int a_type, int new_val)
{
	switch(a_type)
	{
	case GUI_AUTOSTART_CHBX:
		if(new_val)
		{
			autostart = true;
			//regAutoStSet(true);
			taskAutoStSet(true);
		}
		else
		{
			autostart = false;
			//regAutoStSet(false);
			taskAutoStSet(false);
		}
		break;
	case GUI_GLOB_KEYB_CHBX:
		if(new_val)
		{
			//keyb_hook = true;
			//filter_is_setting_up = true;
			//regSet(keyb_hook_n);
			//startHooking(HOOK_GLOBAL_KB);
			//setButtAndDiscardStatus(true, false);
		}
		else
		{
			//keyb_hook = false;
			//regDel(keyb_hook_n);
			//regDel(key_virtc_n);
			//regDel(key_scanc_n);
			//key_virtc = key_scanc = 0xFFFFFFFF;
			//setButtText(key_virtc, key_scanc);
			//stopHooking(HOOK_GLOBAL_KB);
			//setKbFilter(0xFFFFFFFF, 0xFFFFFFFF); // Reset filter
			//setButtAndDiscardStatus(false, false);
		}
		break;
	case GUI_BLOCK_INP_CHBX:
		if(new_val)
		{
			/*block_inp = true;
			regDel(block_inp_n);
			setDiscardInp(TRUE);*/
		}
		else
		{
			/*block_inp = true;
			regSet(block_inp_n);
			setDiscardInp(FALSE);*/
		}
		break;
	case GUI_SAVE_KEYC_BUTT:
		/*setKbFilter(key_virtc, key_scanc);
		regSet(key_virtc_n, key_virtc);
		regSet(key_scanc_n, key_scanc);
		setButtAndDiscardStatus(false, true);
		filter_is_setting_up = false;
		break;*/
	case GUI_TERMINATE_BUTT:
		PostQuitMessage(0);
		break;
	case GUI_WINDOWWAS_DEST:
		window_is_alive = false;
		break;
	default:
		return -1;
	}

	return 0;
}

int startHooking(int whats_hooking)
{
	bool first = true; // First hook setup after launch of the instance
	if(dll_start_addr != NULL)
	{
		first = false;
	}
	
	// HACKERMAN MODE: ON
	// Obtain taskbar thread_id by class name
	HWND taskb_hwnd = FindWindow(L"Shell_TrayWnd", NULL);
	DWORD proc_id = NULL;
	DWORD thread_id = GetWindowThreadProcessId(taskb_hwnd, &proc_id);

	// Load hooking DLL, get function pointers
	MASTERPROC setMasterThreadId = NULL;
	HOOKPROC mouseHookCback = NULL;
	HOOKPROC llKbHookCback = NULL;

	if(first)
	{
		dll_start_addr = LoadLibrary(L"hook");
	}

	if(dll_start_addr != NULL)
	{
		setMasterThreadId = (MASTERPROC)GetProcAddress(dll_start_addr, "setMasterThreadId");
		mouseHookCback = (HOOKPROC)GetProcAddress(dll_start_addr, "MouseHookProc");
		llKbHookCback = (HOOKPROC)GetProcAddress(dll_start_addr, "llKbHookProc");
		setKbFilter = (FILTERPROC)GetProcAddress(dll_start_addr, "setKbFilter");
		setDiscardInp = (DISCARDPROC)GetProcAddress(dll_start_addr, "setDiscardInp");
	}
	else
	{
		MessageBox(NULL, L"GetProcAddress(dll_inst, \"mouseHookProc\") line: 65", L"hothook error", MB_OK);
		return -1;
	}

	if(mouseHookCback != NULL)
	{
		// Will this multi-instance check work with shared memory? No idea (._. )
		// YES, IT ACTUALLY DOES! ( o_0 )
		DWORD res = setMasterThreadId(GetCurrentThreadId(), UWM_MBUTTON, UWM_MWHEEL, UWM_KEYPRESS);
		if(first && res) // Only check for multi-instance at first hooking
		{
			//MessageBox(NULL, L"2NDINSTANCE!!", L"hothook error", MB_OK);
			PostThreadMessage(res, UWM_NEWINSTANCE, 0, 0);
			return -1;
		}

		if(whats_hooking & HOOK_TASKBAR_MB)
		{
			mouse_hook = SetWindowsHookEx(WH_MOUSE, mouseHookCback, dll_start_addr, thread_id);
		}
		// Oh boi, here it goes... The real hackin begins! Hook em' up, ladies'!
		if(whats_hooking & HOOK_GLOBAL_KB)
		{
			ll_kb_hook = SetWindowsHookEx(WH_KEYBOARD_LL, llKbHookCback, dll_start_addr, 0);
		}
		// But will the global hook work?..
		// Yes it does!
	}
	else
	{
		MessageBox(NULL, L"SetWindowsHookEx", L"hothook error", MB_OK);
		return -1;
	}

	return 0;
}

int stopHooking(int whats_unhooking)
{
	bool res = true;
	if(whats_unhooking & HOOK_TASKBAR_MB)
	{
		res = (bool)UnhookWindowsHookEx(mouse_hook);
	}
	if(whats_unhooking & HOOK_GLOBAL_KB)
	{
		res = (bool)UnhookWindowsHookEx(ll_kb_hook);
	}

	return !res;
}

int spawnProc(LPCWSTR app, LPCWSTR cmd)
{
	// NEVER QUOTE lpApplicationName IT SCREWS UP PARSING RESULTING IN ACESS_DENIED (ERR5)
	LPWSTR cmd_out = NULL;
	if(cmd != NULL)
	{
		static wchar_t cmd_out_buff[MAX_PATH + 40];
		std::wstringstream wss;
		wss << L'"' << app << L"\" " << cmd;
		wcscpy(cmd_out_buff, wss.str().c_str());
		cmd_out = cmd_out_buff;


		WPLD(L'|' << cmd_out << L'|');

	}

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOWNORMAL;
	memset(&pi, 0, sizeof(pi));

	stealFground();

	// Create Process ============================================================================
	BOOL res = CreateProcess(
		app,		//  [I|O]  Name of the module to be executed, that's it
		cmd_out,	// [IO|O]  Command line to be exectued, searches PATH, adds extention
		NULL,		//  [I|O]  Sec. Attrib. for inhereting new process by child processes
		NULL,		//  [I|O]  Sec. Attrib. for inhereting new thread by child processes
		FALSE,		//    [I]  New proc. inherits each inheritable handle
		0,			//    [I]  Process creation flags
		NULL,		//  [I|O]  Ptr to environment block of new process (inherit if NULL)
		NULL,		//  [I|O]  Full path to current directory for the process
		&si,		//    [I]  Ptr to STARTUPINFO struct, if dwFlags = 0, def. values used
		&pi);		//    [O]  Ptr to PROCESS_INFORMATION struct with new proc identification info
	// ===========================================================================================

	PERR;
	PLD("RES: " << res);

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return res == 0;
}

/*___________________________________________________________________
|  injectDllFgThief:
|    Injects DLL into target process, which steals foreground status
|    by calling AllowSetForegroundWindow(ASFW_ANY)
|
|  victim_pid: Unique Process Identifier of the victim
|
|  TODO: In case of unexpected crashes improve this function's
|    reliability by using shared global variable in DLL to pass
|    base DLL address and injectThread function address in case
|    unreliable Windows API maps this DLL into different virtual
|    address than in the host program. The chance should be small.
|____________________________________________________________________*/
void injectDllFgThief(DWORD victim_pid)
{
	BOOL res = 0;

	const char* inj_path = "C:\\Users\\pc\\source\\repos\\hothook\\x64\\Debug\\fground_injector.dll";
	// Get process handle to victim
	HANDLE victim = OpenProcess(PROCESS_ALL_ACCESS, FALSE, victim_pid);
	PLH("victim: " << victim);

	// Find exact adress of LoadLibraryA function from text space of kernel32.dll loaded by the OS
	// and used by victim
	PVOID llib = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	//PVOID flib = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "FreeLibrary");
	PLH("llib: " << llib);
	//PLH("flib: " << flib);

	// Allocate memory inside victim's address space
	LPVOID inj_path_victim = (LPVOID)VirtualAllocEx(victim, NULL, strlen(inj_path)+1,
		MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	PLH("inj_path_victim: " << inj_path_victim);

	// Write inject dll's adress into victim
	SIZE_T written;
	res = WriteProcessMemory(victim, inj_path_victim, inj_path, strlen(inj_path)+1, &written);
	PLD("wreiteprocmem res: " << res << " written: " << written);

	// Finally, inject DLL into victim!
	// Spawn thread in remote process ================================================================
	HANDLE inj_llib_thread = CreateRemoteThread(
		victim,								//   [I]  Handle to process where thread will be created
		NULL,								//   [I]  SECURITY_ATTRIBUTES for new thread
		0,									//   [I]  Initial stacks size, bytes. 0 -> default size
		(LPTHREAD_START_ROUTINE)llib,		//   [I]  User defined callback LPTHREAD_START_ROUTINE
		inj_path_victim,					//   [I]  Ptr to variable to be sent as func parameter
		0,									//   [I]  Creation control flags. 0 -> immediate start
		NULL);								// [O|O]  Ptr to variable that recieves thread ID
	// ===============================================================================================

	// CANNOT WAIT FOR THREAD IN OTHER PROCESS.... OR CAN I?! I CAN!
	// Wait for DLL to get properly injected into victim
	SW_CREATE;
	SW_SET;
	res = WaitForSingleObject(inj_llib_thread, INFINITE);
	SW_STOP;
	PERR;
	PLD("inj_llib_thread wait res:" << res);
	// Get executable base address of the loaded DLL
	DWORD llib_exit;
	res = GetExitCodeThread(inj_llib_thread, &llib_exit);
	PLH("llib exit code: " << llib_exit);

	PLD("inj_thread: " << inj_llib_thread);
	PLD(SW_STR);

	// Free previously allocated remote memory
	res = VirtualFreeEx(victim, inj_path_victim, 0, MEM_RELEASE);
	PLD("Victim memory release result: " << res);


	// Call injected DLL's function
	//HMODULE fg_inj = GetModuleHandle(L"fground_injector.dll");
	static HMODULE fg_inj = LoadLibraryA(inj_path);
	PERR;
	PLH("fg_injmodhznd: " << fg_inj);

	PVOID inj_t_proc = (LPVOID)GetProcAddress(fg_inj, "injectThread");
	PVOID ulib = NULL;
	PLH("inj_t_proc: " << inj_t_proc);
#ifdef boob
	// Spawn thread in remote process ================================================================
	HANDLE inj_thread = CreateRemoteThread(
		victim,								//   [I]  Handle to process where thread will be created
		NULL,								//   [I]  SECURITY_ATTRIBUTES for new thread
		0,									//   [I]  Initial stacks size, bytes. 0 -> default size
		(LPTHREAD_START_ROUTINE)inj_t_proc,	//   [I]  User defined callback LPTHREAD_START_ROUTINE
		NULL,								//   [I]  Ptr to variable to be sent as func parameter
		0,									//   [I]  Creation control flags. 0 -> immediate start
		NULL);								// [O|O]  Ptr to variable that recieves thread ID
	// ===============================================================================================

	// Wait before injected DLL's thread finishes before extraction
	//sw.Set();
	res = WaitForSingleObject(inj_thread, INFINITE);
	//sw.Stop();
	PERR;
	PLD("inj_thread wait res:" << res);

	PLD("inj_thread: " << inj_thread);
#endif
	//PLD(sw.Str());

	//Sleep(5000);

	// For some esoteric reason Windows API refuse to function according to documentation.
	// Because of this, trying to unload DLL that is not longer needed crashes the victim process
	// OK, Windows, I'll let useless DLLs just sit in memory if you want this so much! No problems.
	// Extract injected DLL from victim
	// Spawn thread in remote process ================================================================
	//HANDLE inj_flib_thread = CreateRemoteThread(
	//	victim,								//   [I]  Handle to process where thread will be created
	//	NULL,								//   [I]  SECURITY_ATTRIBUTES for new thread
	//	0,									//   [I]  Initial stacks size, bytes. 0 -> default size
	//	(LPTHREAD_START_ROUTINE)flib,		//   [I]  User defined callback LPTHREAD_START_ROUTINE
	//	//(LPVOID)llib_exit,				//   [I]  Ptr to variable to be sent as func parameter
	//			fg_inj,
	//	0,									//   [I]  Creation control flags. 0 -> immediate start
	//	NULL);								// [O|O]  Ptr to variable that recieves thread ID
	// ===============================================================================================

	//PLD("FLIB THREAD CREATED!");

	// Wait untill injected DLL is fully extracted from the victim
	//sw.Set();
	//res = WaitForSingleObject(inj_flib_thread, INFINITE);
	//sw.Stop();
	//PERR;
	//PLD("inj_flib_thread wait res:" << res);


	//DWORD flib_exit;
	//res = GetExitCodeThread(inj_flib_thread, &flib_exit);
	//PLD("inj_flib_thread getexit res: " << res);
	//PLH("inj_flib_thread exit code: " << flib_exit);

	//PLD("inj_flib_thread: " << inj_flib_thread);
	//PLD(sw.Str());

	// Extract injection DLL from host
	// This ***** does not works anyways. Stupid Windows API
	// That fail to function according to documentation
	//PLD("FREE LIB 0: " << FreeLibrary(fg_inj));
	//PLD("FREE LIB 1: " << FreeLibrary(fg_inj));
	//PLD("FREE LIB 2: " << FreeLibrary(fg_inj));

	// Clean up by closing all utilised handles
	CloseHandle(victim);
	CloseHandle(inj_llib_thread);
#ifdef boob
	CloseHandle(inj_thread);
#endif
	//CloseHandle(inj_flib_thread);

	PLD("injection completed!");
}

#define LIF(x) if ((x)) { __leave; } // Leave If true

typedef BOOL (WINAPI *ALLOWSETFGWND)(DWORD);
typedef HANDLE (WINAPI *GETSTDHANDLE)(DWORD);
typedef BOOL (WINAPI *WRITECONSOLEA)(HANDLE, LPVOID, DWORD, LPDWORD, LPVOID);

typedef struct
{
	ALLOWSETFGWND allowSetFgWnd;
	GETSTDHANDLE getStdHand;
	WRITECONSOLEA writeConA;

	char heuheu_msg[42];
} INJDAT;


// Must remove the /GZ compiler switch for this to work; it is set by default in debug builds.
// /GZ is deprecated since Visual Studio 2005; use /RTC(Run-Time Error Checks) instead.
// /RTCs Enables stack frame run-time error checking


static DWORD WINAPI remThread(INJDAT *dat) // Nicks Foreground status from any process
{
	//dat->allowSetFgWnd(ASFW_ANY);
	dat->writeConA(dat->getStdHand(STD_OUTPUT_HANDLE), dat->heuheu_msg, 0, NULL, NULL);

	return 0;
}

static void endOfRemThread() {} // Marks memory address right after remThread


int injectDirectFgThief(DWORD victim_pid)
{
	HANDLE victim = OpenProcess(
		PROCESS_CREATE_THREAD |
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ |
		PROCESS_VM_WRITE, FALSE, victim_pid);
	PLH("==============INJECTING-CODE-INTO-" << victim << "==============");

	HINSTANCE u32, k32;			// Base addresses of system DLLs
	INJDAT *rem_data = NULL;	// Remote memory address of injected data struct
	DWORD *rem_code = NULL;		// Remote memory address of injected code
	HANDLE rem_thread = NULL;	// Handle to injected thread

	SIZE_T rem_b_written = 0;	// Number of bytes written into remote process
	DWORD rem_thread_exit = -1;	// Return value of the injected thread

	__try
	{
		// Get API funciton addresses that are required in Injection Data Structure
		u32 = GetModuleHandle(L"User32.dll");
		k32 = GetModuleHandle(L"Kernel32.dll");
		PLH("U32: " << u32 << " K32: " << k32);
		LIF(u32 == NULL || k32 == NULL);
		
		// Initialise Injection Data Structure
		INJDAT ldat;
		ldat.allowSetFgWnd = (ALLOWSETFGWND)GetProcAddress(u32, "AllowSetForegroundWindow");
		ldat.getStdHand = (GETSTDHANDLE)GetProcAddress(k32, "GetStdHandle");
		ldat.writeConA = (WRITECONSOLEA)GetProcAddress(k32, "WriteConsoleA");
		strcpy(ldat.heuheu_msg, "YOUR TOP-Z STATUS WAS NIKKED!HEUHUEHUEHU!");
		PLH("APIFUNCS: " << ldat.allowSetFgWnd << "|" << ldat.getStdHand << "|"  << ldat.writeConA);
		LIF(ldat.allowSetFgWnd == NULL);

		// Allocate remote virtual memory and copy Injection Data Structure into it
		rem_data = (INJDAT *)VirtualAllocEx(victim, NULL, sizeof(INJDAT), MEM_COMMIT, PAGE_READWRITE);
		PLH("REM_DATA: " << rem_data);
		LIF(rem_data == NULL);
		WriteProcessMemory(victim, rem_data, &ldat, sizeof(INJDAT), &rem_b_written);
		PLD("DATA WRITTEN IN REMOTE MEMORY. TOTAL OF " << rem_b_written << " BYTES.");

		// Calculate size of the remThread's code
		const ULONGLONG txt_size = (LPBYTE)endOfRemThread - (LPBYTE)remThread;

		// Allocate remote virtual memory and copy Injection Code into it
		rem_code = (PDWORD)VirtualAllocEx(victim, NULL, txt_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		PLH("REM_CODE: " << rem_code);
		LIF(rem_code == NULL);
		WriteProcessMemory(victim, rem_code, remThread, txt_size, &rem_b_written);
		PLD("CODE WRITTEN IN REMOTE MEMORY. TOTAL OF " << rem_b_written << " BYTES.");

		// Execute injected code =========================================================================
		rem_thread = CreateRemoteThread(
			victim,								//   [I]  Handle to process where thread will be created
			NULL,								//   [I]  SECURITY_ATTRIBUTES for new thread
			0,									//   [I]  Initial stacks size, bytes. 0 -> default size
			(LPTHREAD_START_ROUTINE)rem_code,	//   [I]  User defined callback LPTHREAD_START_ROUTINE
			rem_data,							//   [I]  Ptr to variable to be sent as func parameter
			0,									//   [I]  Creation control flags. 0 -> immediate start
			NULL);								// [O|O]  Ptr to variable that recieves thread ID
		// ===============================================================================================
		PLH("REM_THREAD: " << rem_thread);
		LIF(rem_thread == NULL);

		// Wait untill injected thread successfully finishes it's job
		LARGE_INTEGER stime, etime;
		QueryPerformanceCounter(&stime);
		WaitForSingleObject(rem_thread, INFINITE);
		QueryPerformanceCounter(&etime);
		LARGE_INTEGER freq;
		QueryPerformanceFrequency(&freq);
		ui64 ns_per_tick = 1000000000/freq.QuadPart;
		ui64 us = (etime.QuadPart - stime.QuadPart) * ns_per_tick;
		PLD("INJECTED THREAD TIME : " << us << " NS");
	}
	__finally // Cleanup
	{
		if(rem_data != NULL)
		{
			VirtualFreeEx(victim, rem_data, 0, MEM_RELEASE);
		}
		if(rem_code != NULL)
		{
			VirtualFreeEx(victim, rem_code, 0, MEM_RELEASE);
		}
		if(rem_thread != NULL)
		{
			GetExitCodeThread(rem_thread, &rem_thread_exit);
			PLD("REM_THREAD_EXIT: " << rem_thread_exit);
			CloseHandle(rem_thread);
		}
		if(victim != NULL)
		{
			CloseHandle(victim);
		}
	}
	PLD("==============INJECTION-COMPLEATED-SUCCESSFULLY!==============");

	return 0; // Profit!!!
}

void stealFground()
{
	
	// DEBUG
	return;
	// DEBUG
	
	
	
	
	HWND fgwnd = GetForegroundWindow();

	DWORD cur_thread = GetCurrentThreadId();
	DWORD fg_pid = 0;
	DWORD fg_thread = GetWindowThreadProcessId(fgwnd, &fg_pid);

	PLD("cur_thread: " << cur_thread);
	PLD("fg_thread: " << fg_thread);

	if(AttachThreadInput(cur_thread, fg_thread, TRUE))
	{
		PLD("AttachThreadInput worked.");
		// WILL THIS CALL WORK FROM ATTACHED THREAD? YES!
		AllowSetForegroundWindow(ASFW_ANY);
		AttachThreadInput(cur_thread, fg_thread, FALSE);
	}
	else // INJECT NON GUI PROGRAMS DIRECTLY AND STEAL FOREGROUND!
	{
		PERR;
		PLD("AttachThreadInput failed. Injecting The Foreground Thief!");
		//injectDllFgThief(fg_pid);
		injectDirectFgThief(fg_pid);

		/*DWORD fg_lock_ms = -1;
		BOOL res = SystemParametersInfoA(
			SPI_GETFOREGROUNDLOCKTIMEOUT,
			NULL,
			&fg_lock_ms,
			0
		);
		PERR;
		PLD("SYSPAR RES: " << res << " FG_LOCK_TIMEOUT: " << fg_lock_ms << " MS");*/



	}

	// Possible actions todo when the window was brought into focus:
	//SetForegroundWindow(fake_wnd);
	//SetCapture(fake_wnd); // Capture mouse
	//SetFocus(fake_wnd); // Capture keyboard
	//SetActiveWindow(fake_wnd);
	//EnableWindow(fake_wnd, TRUE);
}

DWORD gimpHelpMaxThread(LPVOID p)
{
	int iter = 0;
	while(iter < 10)
	{
		Sleep(50);

		HWND fgwnd = GetForegroundWindow();
		char buff[256];
		SendMessageTimeoutA(fgwnd, WM_GETTEXT, 256, (LPARAM)buff, SMTO_ABORTIFHUNG, 25, NULL);

		const char *s = "GIMP Help Browser";
		--s;
		SIZE_T l = strlen(buff);
		const char *bs = buff + l - 17 - 1;
		const char *be = buff + l;

		if(bs < buff)
		{
			continue;
		}

		bool gotcha = true;
		while(bs != be)
		{
			if(*(++bs) != *(++s))
			{
				gotcha = false;
				break;
			}
		}

		if(gotcha)
		{
			SetWindowPos(fgwnd, HWND_TOP, 278, 175, 1260, 830, 0);
			//Sleep(20);
			//ShowWindow(fgwnd, SW_MAXIMIZE);
			break;
		}

		++iter;
	}

	return 0;
}