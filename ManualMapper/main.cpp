#include "injection.h"

#include "xorstr.h"

bool Equals(WCHAR* a, std::string_view b);
DWORD GetProcID(std::string_view procName) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		LERR(xorstr_("CreateToolhelp32Snapshot failed. Error: ") << GetLastError());
		return 0;
	}

	PROCESSENTRY32 procEntry;
	procEntry.dwSize = sizeof(PROCESSENTRY32);
	if (!Process32First(hSnap, &procEntry)) {
		LERR(xorstr_("Process32First failed. Error: ") << GetLastError());
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
	DWORD pid = GetProcID(xorstr_("cs2.exe"));
	if (!pid) {
		LERR(xorstr_("Could not find DummyApp.exe process."));
		return 1;
	}

	LINF(xorstr_("Found cs2.exe with PID: ") << pid);

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc || hProc == INVALID_HANDLE_VALUE) {
		LERR(xorstr_("OpenProcess failed. Error: ") << GetLastError());
		return 1;
	}

	auto target =
#ifdef _DEBUG
		xorstr_("Debug")
#else
		xorstr_("Release")
#endif
	;

	auto dir = std::format("..\\x64\\{}\\", target);
	std::filesystem::current_path(dir);

	auto absPath = std::filesystem::absolute(xorstr_("DummyDLL.dll")).string();
	manualMap(hProc, absPath);
}