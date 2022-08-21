#include <iostream>
#include <windows.h>
#include <taskschd.h>
#include <stdio.h>
#include <comdef.h>
#include "data.h"
#include "keys.h"

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")

HKEY app_root = HKEY_CURRENT_USER;
LPCWSTR app_key = L"SOFTWARE\\HotHook";
LPCWSTR app_ar_key = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
LPCWSTR app_ar_val = L"HotkeyHooker";
LPCWSTR app_task_val = L"Hotkey Hooker Autorun";




/*___________________________________________________________________
|  regKeyCrOp:
|    Attempts to create new registry key, if already exists, opens it
|
|  sub_k: Path to the new key from application root key
|
|  Return value:
|    Handle to created or opened key
|____________________________________________________________________*/
HKEY regKeyCrOp(LPCWSTR sub_k);


/*___________________________________________________________________
|  regKeyOp:
|    Opens already exising key
|
|  sub_k: Path to the key from application root key
|
|  Return value:
|            Key exists -> Handle to the key
|    Key does not exist -> NULL
|____________________________________________________________________*/
HKEY regKeyOp(LPCWSTR sub_k);


/*___________________________________________________________________
|  regKeyOp:
|    Destroys registry key and all it's sub-keys/values
|
|  sub_k: Path to the key from application root key
|____________________________________________________________________*/
void regKeyDel(LPCWSTR sub_k);




bool regChk(LPCWSTR name)
{
	HKEY key = regKeyOp(app_key);

	// Get Registry Value ============================================================================
	LSTATUS res = RegGetValue(
		key,							//    [I]  Handle to opened key (KEY_QUERY_VALUE  acc. req.)
		NULL,							//  [I|O]  Name of the registry subkey to be retrieved
		name,							//  [I|O]  Name of the value (if NULL or "" get def. value)
		RRF_RT_ANY,						//  [I|O]  Flags comb. of data types to set filter (+ opt.)
		NULL,							//  [O|O]  Ptr to variable that recieves value type
		NULL,							//  [O|O]  Ptr to var that receive data of the value || NULL
		NULL);							// [IO|O]  Ptr sz. B -> N. of B cop. (NULL only pvData = NULL)
	// ===============================================================================================

	RegCloseKey(key);
	return !res;
}

DWORD regGet(LPCWSTR name)
{
	HKEY key = regKeyOp(app_key);
	DWORD dat = 0, sz = sizeof(dat);

	// Get Registry Value ============================================================================
	RegGetValue(
		key,							//    [I]  Handle to opened key (KEY_QUERY_VALUE  acc. req.)
		NULL,							//  [I|O]  Name of the registry subkey to be retrieved
		name,							//  [I|O]  Name of the value (if NULL or "" get def. value)
		RRF_RT_REG_DWORD,				//  [I|O]  Flags comb. of data types to set filter (+ opt.)
		NULL,							//  [O|O]  Ptr to variable that recieves value type
		(PVOID)&dat,					//  [O|O]  Ptr to var that receive data of the value || NULL
		&sz);							// [IO|O]  Ptr sz. B -> N. of B cop. (NULL only pvData = NULL)
	// ===============================================================================================

	RegCloseKey(key);
	return dat;
}

void regSet(LPCWSTR name)
{
	HKEY key = regKeyCrOp(app_key);

	// Set Registry Value ============================================================================
	RegSetValueEx(
		key,							//   [I]  Handle to opened key (KEY_SET_VALUE acc. req.)
		name,							// [I|O]  Value name (if not exist, will be created)
		0,								//        Reserved, must be 0
		REG_SZ,							//   [I]  Type of value beeing set
		NULL,							//   [I]  Ptr to the data that will be stored
		NULL);							//   [I]  Sizeof data in bytes (for strings must include \0)
	// ===============================================================================================

	RegCloseKey(key);
}

void regSet(LPCWSTR name, DWORD data)
{
	HKEY key = regKeyCrOp(app_key);

	// Set Registry Value ============================================================================
	RegSetValueEx(
		key,							//   [I]  Handle to opened key (KEY_SET_VALUE acc. req.)
		name,							// [I|O]  Value name (if not exist, will be created)
		0,								//        Reserved, must be 0
		REG_DWORD,						//   [I]  Type of value beeing set
		(const BYTE*)&data,				//   [I]  Ptr to the data that will be stored
		sizeof(data));					//   [I]  Sizeof data in bytes (for strings must include \0)
	// ===============================================================================================

	RegCloseKey(key);
}

void regSet(LPCWSTR name, LPCWSTR data)
{
	HKEY key = regKeyCrOp(app_key);
	DWORD s = DWORD(wcslen(data)+1) * sizeof(wchar_t);

	// Set Registry Value ============================================================================
	RegSetValueEx(
		key,							//   [I]  Handle to opened key (KEY_SET_VALUE acc. req.)
		name,							// [I|O]  Value name (if not exist, will be created)
		0,								//        Reserved, must be 0
		REG_SZ,							//   [I]  Type of value beeing set
		(const BYTE*)data,				//   [I]  Ptr to the data that will be stored
		s);								//   [I]  Sizeof data in bytes (for strings must include \0)
	// ===============================================================================================

	RegCloseKey(key);
}

void regDel(LPCWSTR name)
{
	HKEY key = regKeyOp(app_key);
	
	// Delete Registry Value =========================================================================
	RegDeleteValue(
		key,							//   [I]  Handle to opened key (KEY_SET_VALUE acc. req.)
		name);							// [I|O]  Value name to be removed
	// ===============================================================================================

	RegCloseKey(key);
}

bool regAutoStChk()
{
	HKEY key = regKeyOp(app_ar_key);

	// Get Registry Value ============================================================================
	LSTATUS res = RegGetValue(
		key,							//    [I]  Handle to opened key (KEY_QUERY_VALUE  acc. req.)
		NULL,							//  [I|O]  Name of the registry subkey to be retrieved
		app_ar_val,						//  [I|O]  Name of the value (if NULL or "" get def. value)
		RRF_RT_ANY,						//  [I|O]  Flags comb. of data types to set filter (+ opt.)
		NULL,							//  [O|O]  Ptr to variable that recieves value type
		NULL,							//  [O|O]  Ptr to var that receive data of the value || NULL
		NULL);							// [IO|O]  Ptr sz. B -> N. of B cop. (NULL only pvData = NULL)
	// ===============================================================================================

	RegCloseKey(key);
	return !res;
}

void regAutoStSet(bool state)
{
	HKEY key = regKeyCrOp(app_ar_key);

	if(state)
	{
		wchar_t data[309];
		data[0] = L'\"';
		data[308] = L'\0';
		GetModuleFileName(NULL, data+1, 300-1);
		DWORD s = (DWORD)wcslen(data)+1;

		data[s-1] = L'\"';
		wcscpy(data+s, L" -silent");
		// What? I don't want to include <string> and <sstream> here, OK?

		// Set Registry Value ============================================================================
		RegSetValueEx(
			key,						//   [I]  Handle to opened key (KEY_SET_VALUE acc. req.)
			app_ar_val,					// [I|O]  Value name (if not exist, will be created)
			0,							//        Reserved, must be 0
			REG_SZ,						//   [I]  Type of value beeing set
			(const BYTE*)data,			//   [I]  Ptr to the data that will be stored
			(s+10) * sizeof(wchar_t));	//   [I]  Sizeof data in bytes (for strings must include \0)
		// ===============================================================================================

		RegCloseKey(key);
	}
	else
	{
		// Delete Registry Value =========================================================================
		RegDeleteValue(
			key,						//   [I]  Handle to opened key (KEY_SET_VALUE acc. req.)
			app_ar_val);					// [I|O]  Value name to be removed
		// ===============================================================================================
	}

	RegCloseKey(key);
}

HKEY regKeyCrOp(LPCWSTR sub_k)
{
	REGSAM sam = KEY_SET_VALUE | KEY_QUERY_VALUE;
	HKEY key = NULL;

	// Create Registry Key ===========================================================================
	RegCreateKeyEx(
		app_root,						//   [I]  Handle to open reg key, or root key
		sub_k,							//   [I]  Subkey name relative to 1st param (32 lvl deep)
		0,								//        Reserved, must be 0
		NULL,							// [I|O]  Class type of this key (OOP shenenigans?)
		REG_OPTION_NON_VOLATILE,		//   [I]  Key options (0 -> std non-volatile key)
		sam,							//   [I]  Security and Access Mask
		NULL,							// [I|O]  Ptr to SECURITY_ATTRIBUTES (handle inheritability)
		&key,							//   [O]  Ptr to HKEY variable that will hold returned handle
		NULL);							// [O|O]  Dis-pos -> CREATED_NEW_KEY | OPENED_EXISTING_KEY
	// ===============================================================================================

	return key;
}

HKEY regKeyOp(LPCWSTR sub_k)
{
	REGSAM sam = KEY_SET_VALUE | KEY_QUERY_VALUE;
	HKEY key = NULL;

	// Open Registry Key =============================================================================
	RegOpenKeyEx(
		app_root,						//   [I]  Handle to open reg key, or root key
		sub_k, 							// [I|O]  Name of the registry subkey to be opened
		0, 								//   [I]  Options -> 0 || REG_OPTION_OPEN_LINK
		sam,							//   [I]  Security and Access Mask
		&key);							//   [O]  Ptr to variable that receives opened key handle
	// ===============================================================================================

	return key;
}

void regKeyDel(LPCWSTR sub_k)
{
	// Delete Registry Key ===========================================================================
	RegDeleteKeyEx(
		HKEY_CLASSES_ROOT,				// [I]  Handle to open reg key, or root key
		sub_k,							// [I]  Subkey name to be deleted, relative to 1st param
		KEY_WOW64_64KEY, 				// [I]  Key platform -> KEY_WOW64_32KEY | KEY_WOW64_64KEY
		0);								//      Reserved, must be 0
	// ===============================================================================================
}

bool taskAutoStChk()
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if(FAILED(hr))
	{
		PLH("CoInitializeEx failed: " << hr);
		return false;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if(FAILED(hr))
	{
		PLH("CoInitializeSecurity failed: " << hr);
		CoUninitialize();
		return false;
	}

	//  ------------------------------------------------------
	//  Create a name for the task.
	LPCWSTR wszTaskName = app_task_val;

	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if(FAILED(hr))
	{
		PLH("Failed to create an instance of ITaskService: " << hr);
		CoUninitialize();
		return false;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if(FAILED(hr))
	{
		PLH("ITaskService::Connect failed: " << hr);
		pService->Release();
		CoUninitialize();
		return false;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.  
	//  This folder will hold the new task that is registered.
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if(FAILED(hr))
	{
		PLH("Cannot get Root Folder pointer: " << hr);
		pService->Release();
		CoUninitialize();
		return false;
	}

	// Check if task exist
	IRegisteredTask* pRegTask = NULL;
	hr = pRootFolder->GetTask(_bstr_t(wszTaskName), &pRegTask);
	//pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);
	if(FAILED(hr))
	{
		PLH("No task found: " << hr);
		pService->Release();
		CoUninitialize();
		return false;
	}

	pService->Release();
	pRegTask->Release();
	CoUninitialize();
	return true;
}

int taskAutoStSet(bool state)
{
	//  ------------------------------------------------------
	//  Initialize COM.
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if(FAILED(hr))
	{
		PLH("CoInitializeEx failed: " << hr);
		return 1;
	}

	//  Set general COM security levels.
	hr = CoInitializeSecurity(
		NULL,
		-1,
		NULL,
		NULL,
		RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		0,
		NULL);

	if(FAILED(hr))
	{
		PLH("CoInitializeSecurity failed: " << hr);
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Create a name for the task.
	LPCWSTR wszTaskName = app_task_val;

	wchar_t data[301];
	data[0] = L'\"';
	data[300] = L'\0';
	GetModuleFileName(NULL, data+1, 300-1);
	DWORD s = (DWORD)wcslen(data)+1;

	data[s-1] = L'\"';
	data[s] = L'\0';

	//  Set mcbookdel.exe directory.
	std::wstring wstrExecutablePath = data;


	//  ------------------------------------------------------
	//  Create an instance of the Task Service. 
	ITaskService* pService = NULL;
	hr = CoCreateInstance(CLSID_TaskScheduler,
		NULL,
		CLSCTX_INPROC_SERVER,
		IID_ITaskService,
		(void**)&pService);
	if(FAILED(hr))
	{
		PLH("Failed to create an instance of ITaskService: " << hr);
		CoUninitialize();
		return 1;
	}

	//  Connect to the task service.
	hr = pService->Connect(_variant_t(), _variant_t(),
		_variant_t(), _variant_t());
	if(FAILED(hr))
	{
		PLH("ITaskService::Connect failed: " << hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Get the pointer to the root task folder.  
	//  This folder will hold the new task that is registered.
	ITaskFolder* pRootFolder = NULL;
	hr = pService->GetFolder(_bstr_t(L"\\"), &pRootFolder);
	if(FAILED(hr))
	{
		PLH("Cannot get Root Folder pointer: " << hr);
		pService->Release();
		CoUninitialize();
		return 1;
	}

	//  If the same task exists, remove it.
	pRootFolder->DeleteTask(_bstr_t(wszTaskName), 0);

	if(!state)
	{
		//  Clean up.
		pRootFolder->Release();
		CoUninitialize();
		PLH("Success! Task successfully removed.");
		return 0;
	}

	//  Create the task builder object to create the task.
	ITaskDefinition* pTask = NULL;
	hr = pService->NewTask(0, &pTask);

	pService->Release();  // COM clean up.  Pointer is no longer used.
	if(FAILED(hr))
	{
		PLH("Failed to create a task definition: " << hr);
		pRootFolder->Release();
		CoUninitialize();
		return 1;
	}

	// Ensure that program will run as admin
	IPrincipal* pPrincipal = NULL;
	hr = pTask->get_Principal(&pPrincipal);
	if(FAILED(hr))
	{
		PLH("Cannot get principal pointer: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	hr = pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);
	hr = pPrincipal->put_RunLevel(TASK_RUNLEVEL_HIGHEST);
	hr = pPrincipal->put_GroupId(_bstr_t(L"Administrators"));
	pPrincipal->Release();
	if(FAILED(hr))
	{
		PLH("Cannot put principal settings: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Get the registration info for setting the identification.
	IRegistrationInfo* pRegInfo = NULL;
	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if(FAILED(hr))
	{
		PLH("Cannot get identification pointer: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	hr = pRegInfo->put_Author(_bstr_t(L"SciInvent"));
	pRegInfo->Release();
	if(FAILED(hr))
	{
		PLH("Cannot put identification info: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	//  ------------------------------------------------------
	//  Create the settings for the task
	ITaskSettings* pSettings = NULL;
	hr = pTask->get_Settings(&pSettings);
	if(FAILED(hr))
	{
		PLH("Cannot get settings pointer: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	//  Set setting values for the task. 
	hr = pSettings->put_StartWhenAvailable(VARIANT_TRUE);
	hr = pSettings->put_ExecutionTimeLimit(_bstr_t(L"PT0S"));
	hr = pSettings->put_DisallowStartIfOnBatteries(VARIANT_FALSE);
	pSettings->Release();
	if(FAILED(hr))
	{
		PLH("Cannot put setting info: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}


	//  ------------------------------------------------------
	//  Get the trigger collection to insert the boot trigger.
	ITriggerCollection* pTriggerCollection = NULL;
	hr = pTask->get_Triggers(&pTriggerCollection);
	if(FAILED(hr))
	{
		PLH("Cannot get trigger collection: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	//  Add the logon trigger to the task.
	ITrigger* pTrigger = NULL;
	hr = pTriggerCollection->Create(TASK_TRIGGER_LOGON, &pTrigger);
	pTriggerCollection->Release();
	if(FAILED(hr))
	{
		PLH("Cannot create the trigger: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	/*IBootTrigger* pBootTrigger = NULL;
	hr = pTrigger->QueryInterface(
		IID_IBootTrigger, (void**)&pBootTrigger);
	pTrigger->Release();
	if(FAILED(hr))
	{
		PLH("QueryInterface call failed for IBootTrigger: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	hr = pBootTrigger->put_Id(_bstr_t(L"Trigger1"));
	if(FAILED(hr))
		PLH("Cannot put the trigger ID: " << hr);*/

	//  Set the task to start at a certain time. The time 
	//  format should be YYYY-MM-DDTHH:MM:SS(+-)(timezone).
	//  For example, the start boundary below
	//  is January 1st 2005 at 12:05
	/*hr = pBootTrigger->put_StartBoundary(_bstr_t(L"2005-01-01T12:05:00"));
	if(FAILED(hr))
		PLH("Cannot put the start boundary: " << hr);

	hr = pBootTrigger->put_EndBoundary(_bstr_t(L"2015-05-02T08:00:00"));
	if(FAILED(hr))
		PLH("Cannot put the end boundary: " << hr);*/

	// Delay the task to start 30 seconds after system start. 
	/*hr = pBootTrigger->put_Delay((BSTR)L"PT30S");
	pBootTrigger->Release();
	if(FAILED(hr))
	{
		PLH("Cannot put delay for boot trigger: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}*/


	//  ------------------------------------------------------
	//  Add an Action to the task. This task will execute mcbookdel.exe.     
	IActionCollection* pActionCollection = NULL;

	//  Get the task action collection pointer.
	hr = pTask->get_Actions(&pActionCollection);
	if(FAILED(hr))
	{
		PLH("Cannot get Task collection pointer: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	//  Create the action, specifying it as an executable action.
	IAction* pAction = NULL;
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	pActionCollection->Release();
	if(FAILED(hr))
	{
		PLH("Cannot create the action: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	IExecAction* pExecAction = NULL;
	//  QI for the executable task pointer.
	hr = pAction->QueryInterface(
		IID_IExecAction, (void**)&pExecAction);
	pAction->Release();
	if(FAILED(hr))
	{
		PLH("QueryInterface call failed for IExecAction: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	//  Set the path of the executable to mcbookdel.exe.
	hr = pExecAction->put_Path(_bstr_t(wstrExecutablePath.c_str()));
	hr = pExecAction->put_Arguments(_bstr_t(L"-silent"));
	pExecAction->Release();
	if(FAILED(hr))
	{
		PLH("Cannot set path of executable: " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}


	//  ------------------------------------------------------
	//  Save the task in the root folder.
	IRegisteredTask* pRegisteredTask = NULL;
	VARIANT varPassword, varUserid;
	varPassword.vt = VT_EMPTY;
	varUserid.vt = VT_EMPTY;
	hr = pRootFolder->RegisterTaskDefinition(
		_bstr_t(wszTaskName),
		pTask,
		TASK_CREATE_OR_UPDATE,
		/*_variant_t(L"SYSTEM"),*/
		varUserid,
		varPassword,
		TASK_LOGON_SERVICE_ACCOUNT,
		_variant_t(L""),
		&pRegisteredTask);
	if(FAILED(hr))
	{
		PLH("Error saving the Task : " << hr);
		pRootFolder->Release();
		pTask->Release();
		CoUninitialize();
		return 1;
	}

	PLH("Success! Task successfully registered.");

	//  Clean up.
	pRootFolder->Release();
	pTask->Release();
	pRegisteredTask->Release();
	CoUninitialize();
	return 0;
}