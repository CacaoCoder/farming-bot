#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <vector>

uint32_t GetPID(const wchar_t* processName);
uint64_t GetModuleBaseAddrByName(HANDLE hProc, const char* moduleName);
uint32_t GetNthProcessThreadID(HANDLE hProc, int n);
uint64_t Addr(HANDLE hProc, uint64_t ptr, std::vector<unsigned int> offsets);
void ShellcodeFunc(ArgToShellcodeFunc* arg);

typedef uint64_t(*func_1)(uint64_t *param_1, bool param_2);
typedef void(*func_2)(int64_t param_1);
typedef int64_t(*func_3)(uint64_t param_1, uint32_t param_2, uint32_t param_3, uint32_t param_4, uint64_t param_5);
typedef int64_t*(*func_4)(int64_t param_1);
typedef void(*func_5)(int64_t param_1, int64_t param_2, int64_t param_3, uint32_t param_4);
typedef void(*func_6)(uint64_t param_1, uint64_t param_2);
typedef uint64_t(*func_7)(int64_t *param_1, int64_t param_2, int64_t param_3);
typedef uint64_t(*func_8)(int64_t param_1, int64_t param_2);
typedef void(*func_9)(uint64_t param_1, uint32_t param_2);
typedef void(*func_10)(uint64_t param_1);
typedef void(*func_11)(int64_t* param_1, uint32_t param_2);
typedef void(*func_12)(uint64_t param_1, uint32_t param_2);
typedef uint64_t(*func_13)(int64_t param_1);
typedef uint64_t(*func_14)();
typedef void(*func_15)(int64_t param_1, uint64_t param_2);
typedef void(*func_16)(uint64_t param_1, uint64_t param_2, uint32_t param_3);

struct ArgToShellcodeFunc
{
    uint64_t field_1;
    func_1 func_1;
    func_2 func_2; 
    uint64_t field_2;
    uint64_t baseAddrGameAssemblyDLL;
    func_3 func_3;
    uint64_t field_3;
    uint64_t field_4;
    func_4 func_4;
    uint64_t field_5;
    uint64_t field_6;
    func_5 func_5;
    uint64_t field_7;
    func_6 func_6;
    func_7 func_7;
    func_8 func_8;
    uint64_t field_8;
    uint64_t field_9;
    func_9 func_9;
    func_10 func_10;
    func_11 func_11;
    uint64_t field_10;
    func_12 func_12;
    uint64_t field_11;
    func_13 func_13;
    uint64_t field_12;
    uint64_t field_13;
    func_14 func_14;
    uint64_t field_14;
    func_15 func_15;
    uint64_t field_15;
    func_16 func_16;
};

int main()
{
    uint32_t PID = GetPID(L"hidden.exe");
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    uint64_t baseAddrGameAssemblyDLL = GetModuleBaseAddrByName(hProc, "GameAssembly.dll");

    BYTE shellcodeSkeleton[] = // 107th byte is beginning of argument to the function (8 bytes). 117th byte is beginning of a function address (8 bytes).
        // 248th byte is a placeholder for the saved RIP to jump back to (8 bytes)
    { 
        0x9C, 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x49, 0x89, 0xE7, 0x48, 0x83, 0xE4, 
        0xF0, 0x48, 0x81, 0xEC, 0xA0, 0x00, 0x00, 0x00, 0x0F, 0x29, 0x34, 0x24, 0x0F, 0x29, 0x7C, 0x24, 0x10, 0x44, 0x0F, 0x29, 0x44, 0x24, 0x20, 0x44, 0x0F, 0x29, 0x4C, 0x24, 0x30, 0x44, 
        0x0F, 0x29, 0x54, 0x24, 0x40, 0x44, 0x0F, 0x29, 0x5C, 0x24, 0x50, 0x44, 0x0F, 0x29, 0x64, 0x24, 0x60, 0x44, 0x0F, 0x29, 0x6C, 0x24, 0x70, 0x44, 0x0F, 0x29, 0xB4, 0x24, 0x80, 0x00, 
        0x00, 0x00, 0x44, 0x0F, 0x29, 0xBC, 0x24, 0x90, 0x00, 0x00, 0x00, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xB9, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0xB8, 0xBB, 0xBB, 0xBB, 
        0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x20, 0x44, 0x0F, 0x28, 0xBC, 0x24, 0x90, 0x00, 0x00, 0x00, 0x44, 0x0F, 0x28, 0xB4, 0x24, 0x80, 0x00, 0x00, 0x00, 0x44, 
        0x0F, 0x28, 0x6C, 0x24, 0x70, 0x44, 0x0F, 0x28, 0x64, 0x24, 0x60, 0x44, 0x0F, 0x28, 0x5C, 0x24, 0x50, 0x44, 0x0F, 0x28, 0x54, 0x24, 0x40, 0x44, 0x0F, 0x28, 0x4C, 0x24, 0x30, 0x44, 
        0x0F, 0x28, 0x44, 0x24, 0x20, 0x0F, 0x28, 0x7C, 0x24, 0x10, 0x0F, 0x28, 0x34, 0x24, 0x48, 0x81, 0xC4, 0xA0, 0x00, 0x00, 0x00, 0x4C, 0x89, 0xFC, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D,
        0x41, 0x5C, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5F, 0x5E, 0x5D, 0x5B, 0x5A, 0x59, 0x58, 0x9D, 0xFF, 0x25, 0x0E, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA 
    };

    ArgToShellcodeFunc arg;
    arg.field_1 = 0xC0036017;
    arg.func_1 = (func_1) (baseAddrGameAssemblyDLL + 0x003d8cc0);
    arg.func_2 = (func_2)(baseAddrGameAssemblyDLL + 0x00428a40);
    arg.field_2 = 0x20015641;
    arg.baseAddrGameAssemblyDLL = baseAddrGameAssemblyDLL;
    arg.func_3 = (func_3)(baseAddrGameAssemblyDLL + 0x0067ca70);
    arg.field_3 = 0xC0035B6B;
    arg.field_4 = 0xC0035C9F;
    arg.func_4 = (func_4)(baseAddrGameAssemblyDLL + 0x003b0f80);
    arg.field_5 = 0x20019EF1;
    arg.field_6 = 0x2001832F;
    arg.func_5 = (func_5)(baseAddrGameAssemblyDLL + 0x00a71590);
    arg.field_7 = 0x6000904D;
    arg.func_6 = (func_6)(baseAddrGameAssemblyDLL + 0x0039bf80);
    arg.func_7 = (func_7)(baseAddrGameAssemblyDLL + 0x00660ed0);
    arg.func_8 = (func_8)(baseAddrGameAssemblyDLL + 0x006663b0);
    arg.field_8 = Addr(hProc, baseAddrGameAssemblyDLL + 0x02F14390, std::vector<unsigned int> {0x268, 0xD0, 0xB8, 0x0, 0x228, 0x80, 0x90});
    arg.field_9 = 0x20016FC7;
    arg.func_9 = (func_9)(baseAddrGameAssemblyDLL + 0x0147ba80);
    arg.func_10 = (func_10)(baseAddrGameAssemblyDLL + 0x0039bf80);
    arg.func_11 = (func_11)(baseAddrGameAssemblyDLL + 0x0153f520);
    arg.field_10 = 0x20016FC5;
    arg.func_12 = (func_12)(baseAddrGameAssemblyDLL + 0x0146e1e0);
    arg.field_11 = 0xC00362A9;
    arg.func_13 = (func_13)(baseAddrGameAssemblyDLL + 0x00df5a90);
    arg.field_13 = 0xC00344B3;
    arg.func_14 = (func_14)(baseAddrGameAssemblyDLL + 0x01f76f50);
    arg.field_14 = 0x200135F9;
    arg.func_15 = (func_15)(baseAddrGameAssemblyDLL + 0x01f7af20);
    arg.field_15 = Addr(hProc, baseAddrGameAssemblyDLL + 0x02EF30F0, std::vector<unsigned int> {0x88, 0x20, 0xB8, 0x0, 0x70, 0x78, 0x0});
    arg.func_16 = (func_16)(baseAddrGameAssemblyDLL + 0x015b0bd0);

    void* pArgToShellcodeFunc = VirtualAllocEx(hProc, nullptr, sizeof(ArgToShellcodeFunc), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, pArgToShellcodeFunc, &arg, sizeof(arg), nullptr);

    void* pShellcodeFunc = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, pShellcodeFunc, ShellcodeFunc, 0x1000, nullptr);

    uint32_t threadID = GetNthProcessThreadID(hProc, 10);

    HANDLE hThread = OpenThread((THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT), false, threadID);
    SuspendThread(hThread);
    
    CONTEXT threadContext;
    threadContext.ContextFlags = CONTEXT_CONTROL; 
    GetThreadContext(hThread, &threadContext);
    uint64_t RIP = threadContext.Rip;

    memcpy(&shellcodeSkeleton[107], &pArgToShellcodeFunc, 8);
    memcpy(&shellcodeSkeleton[117], &pShellcodeFunc, 8);
    memcpy(&shellcodeSkeleton[248], &RIP, 8);

    void* pFilledShellcode = VirtualAllocEx(hProc, nullptr, sizeof(shellcodeSkeleton), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, pFilledShellcode, &shellcodeSkeleton, sizeof(shellcodeSkeleton), nullptr);

    threadContext.Rip = (uint64_t)pFilledShellcode;
    SetThreadContext(hThread, &threadContext);
    ResumeThread(hThread);
}

void ShellcodeFunc(ArgToShellcodeFunc* arg)
{
    arg->func_1(&(arg->field_1), 1);
    arg->func_1(&(arg->field_9), 1);
    arg->func_1(&(arg->field_2), 1);
    arg->func_1(&(arg->field_5), 1);
    arg->func_1(&(arg->field_7), 1);

    if (*(int*)(arg->field_2 + 0xe0) == 0) {
        arg->func_2(arg->field_2);
    }

    BYTE* var_1 = (BYTE*)(arg->baseAddrGameAssemblyDLL + 0x030dee5c);
    *var_1 = 1;

    auto var_2 = *(int64_t*)(**(int64_t**)(arg->field_2 + 0xb8) + 0x28);
    
    auto var_3 = arg->func_3(var_2, 0, 0, 0, arg->field_1);

    arg->func_1(&(arg->field_3), 1);
    arg->func_1(&(arg->field_4), 1);
    arg->func_1(&(arg->field_6), 1);

    auto var_4 = arg->func_4(arg->field_5);

    if (*(int*)(arg->field_6 + 0xe0) == 0) {
        arg->func_2(arg->field_6);
    }
    volatile auto var_5 = **(uint64_t**)(arg->field_6 + 0xb8);

    arg->func_5((int64_t)var_4, var_5, arg->field_7, 0);

    *(int64_t*) (*(int64_t*)(arg->field_6 + 0xb8) + 8) = (int64_t)var_4;

    arg->func_6(*(int64_t*)(arg->field_6 + 0xb8) + 8, (uint64_t)var_4);
    
    var_5 = arg->func_7((int64_t*)var_3, (int64_t)var_4, arg->field_3);

    var_5 = arg->func_8(var_5, arg->field_4);

    int64_t var_6 = (int64_t)(arg->func_4(arg->field_9));

    arg->func_9((uint64_t)var_6, 0);

    *(uint64_t*)(var_6 + 0x48) = arg->field_8;

    arg->func_10(var_6 + 0x48);

    *(uint64_t*)(var_6 + 0x40) = var_5;

    arg->func_6(var_6 + 0x40, var_5);

    arg->func_11((int64_t*)var_6, 0);
}
 
uint32_t GetPID(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32FirstW(snapshot, &entry) == TRUE) {
        do {
            std::wstring binPath = entry.szExeFile;
            if (binPath.find(processName) != std::wstring::npos) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry) == TRUE);
    }
    CloseHandle(snapshot);
    return 0;
}

uint64_t GetModuleBaseAddrByName(HANDLE hProc, const char* moduleName) {
    HMODULE hMods[1024];
    DWORD cbNeeded;

    if (EnumProcessModulesEx(hProc, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        uint32_t modulesCount = cbNeeded / sizeof(HMODULE);

        if (modulesCount > (sizeof(hMods) / sizeof(HMODULE))) {
            modulesCount = sizeof(hMods) / sizeof(HMODULE);
        }

        for (uint32_t i = 0; i < modulesCount; i++) {
            char currentModuleName[MAX_PATH];

            if (GetModuleFileNameExA(hProc, hMods[i], currentModuleName, MAX_PATH)) {
                const char* baseName = PathFindFileNameA(currentModuleName);

                if (_stricmp(baseName, moduleName) == 0) {
                    return (uint64_t)hMods[i];
                }
            }
        }
    }
    return 0;
}

uint32_t GetNthProcessThreadID(HANDLE hProc, int n) {
    THREADENTRY32 entry;
    entry.dwSize = sizeof(THREADENTRY32);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    uint32_t PID = GetProcessId(hProc);
    int threadCount = 0;

    if (Thread32First(snapshot, &entry) == TRUE) {
        do {
            if (entry.th32OwnerProcessID == PID) {
                if (threadCount == n) {
                    CloseHandle(snapshot);
                    return entry.th32ThreadID;
                }
                threadCount++;
            }
        } while (Thread32Next(snapshot, &entry) == TRUE);
    }

    CloseHandle(snapshot);
    return NULL;
}

uint64_t Addr(HANDLE hProc, uint64_t ptr, std::vector<unsigned int> offsets)
{
    uint64_t addr = ptr;
    for (uint32_t i = 0; i < offsets.size(); ++i)
    {
        ReadProcessMemory(hProc, (BYTE*)addr, &addr, sizeof(addr), 0);
        addr += offsets[i];
    }
    return addr;
}