#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

//find specific process
DWORD findProc(const char *proc_search) {
    //const char *target_proc = proc_search[1];
    DWORD pID[1024], processCount, i;
    char procName[MAX_PATH] = "<unknown>";

    if (!EnumProcesses(pID, sizeof(pID), &processCount)) {
        printf("Enum failed\n");
        return -1;
    }

    processCount /= sizeof(DWORD);

    for (i = 0; i < processCount; i++) {
        if (pID[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pID[i]);
            if (hProcess) {
                HMODULE hMod;
                DWORD cbNeeded;

                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    GetModuleBaseName(hProcess, hMod, procName, sizeof(procName) / sizeof(char));
                    if (strcmp(procName, proc_search) == 0) {
                        DWORD re_pID = pID[i];
                        CloseHandle(hProcess);
                        return re_pID;
                    }
                }
                CloseHandle(hProcess);
            }
        }
    }
    return -1;
}
//get the handle of the injected dll
HMODULE getDLLhandle(DWORD pID, const char *dll_name) {
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pID);
    if (hProcess == NULL) {
        printf("Open process failed\n");
        return NULL;
    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        printf("Modules in target process:\n");
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                printf("\t%s\n", szModName);
                if (strstr(szModName, dll_name) != NULL) {
                    CloseHandle(hProcess);
                    return hMods[i];
                }
            }
        }
    }
    CloseHandle(hProcess);
    return NULL;
}
//uninject dll
int uninjectDLL(DWORD pID, const char *dll_name) {
    HMODULE hModule = getDLLhandle(pID, dll_name);
    if (hModule == NULL) {
        printf("DLL not found in target process\n");
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (hProcess == NULL) {
        printf("Open process failed\n");
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, hModule, 0, NULL);
    if (hThread == NULL) {
        printf("Create remote thread failed\n");
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("DLL uninjected successfully\n");
    return 0;
}
//inject dll
int injectdll(DWORD pID, const char *dll_path) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (hProcess == NULL) {
        printf("Failed to open process\n");
    }

    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (pDllPath == NULL) {
        printf("Alloc failed\n");
        CloseHandle(hProcess);
        return 1;
    }
    if (!WriteProcessMemory(hProcess, pDllPath, dll_path, strlen(dll_path) + 1, NULL)) {
        printf("Write proc memory failed\n");
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pDllPath, 0, NULL);
    if (hThread == NULL) {
        printf("Create remote thread failed\n");
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    printf("DLL injected successfully\n");
    return 0;
}

int main() {
    const char *search_Query = "CrossCode.exe";
    const char *dll_path = "E:\\C Files\\TestDll.dll";
    const char *dll_name = "TestDll.dll";
    DWORD pID = findProc(search_Query);

    if (pID != -1) {
        printf("Found process %s with pID %u\n", search_Query, pID);
    } else {
        printf("no process found\n");
    }

    if (uninjectDLL(pID, dll_name) != 0) {
        printf("DLL uninjection failed\n");
        if (injectdll(pID, dll_path) != 0) {
        printf("DLL injection failed\n");
        return 1;
        }
    }
    
    return 0;
}