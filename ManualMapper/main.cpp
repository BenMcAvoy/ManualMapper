#include "injection.h"

bool Equals(WCHAR* a, std::string_view b);
DWORD GetProcID(std::string_view procName) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		LERR("CreateToolhelp32Snapshot failed. Error: " << GetLastError());
		return 0;
	}

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnap, &procEntry)) {
		LERR("Process32First failed. Error: " << GetLastError());
		CloseHandle(hSnap);
		return 0;
	}

	do {
		if (Equals(procEntry.szExeFile, procName)) {
			DWORD pid = procEntry.th32ProcessID;
			CloseHandle(hSnap);
			return pid;
		}
	} while (Process32Next(hSnap, &procEntry));

	CloseHandle(hSnap);
	return 0;
}

bool Equals(WCHAR* a, std::string_view b) {
	size_t len = wcslen(a);
	if (len != b.length()) return false;
	for (size_t i = 0; i < len; i++) {
		if (towlower(a[i]) != tolower(b[i])) return false;
	}
	return true;
}

int main() {
	// Find DummyApp.exe process
	DWORD pid = GetProcID("cs2.exe");
	if (!pid) {
		LERR("Could not find DummyApp.exe process.");
		return 1;
	}

	LINF("Found cs2.exe with PID: " << pid);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc || hProc == INVALID_HANDLE_VALUE) {
		LERR("OpenProcess failed. Error: " << GetLastError());
		return 1;
	}

	auto target =
#ifdef _DEBUG
		"Debug"
#else
		"Release"
#endif
	;

	auto dir = std::format("..\\x64\\{}\\", target);
	std::filesystem::current_path(dir);

	auto absPath = std::filesystem::absolute("DummyDLL.dll").string();
	manualMap(hProc, absPath);
}