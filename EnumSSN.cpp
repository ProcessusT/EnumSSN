#include <iostream>
#include <Windows.h>
#include <winternl.h>


// Static functions definitions

/**
* Credits to MALDEVACADEMY
* Compares two strings (case insensitive)
*/
BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {
    WCHAR   lStr1[MAX_PATH],
        lStr2[MAX_PATH];

    int		len1 = lstrlenW(Str1),
        len2 = lstrlenW(Str2);

    int		i = 0,
        j = 0;
    // Checking length. We dont want to overflow the buffers
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;
    // Converting Str1 to lower case string (lStr1)
    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; // null terminating
    // Converting Str2 to lower case string (lStr2)
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating
    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;
    return FALSE;
}




/**
* Credits to MALDEVACADEMY
* Retrieves the base address of a module from the PEB
* and enumerates the linked list of modules to find the correct one.
*/
HMODULE CustomGetModuleHandle(IN char szModuleName[]) {
    // convert char to LPCWSTR
    int wideStrLen = MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, nullptr, 0);
    wchar_t* wideStr = new wchar_t[wideStrLen];
    MultiByteToWideChar(CP_UTF8, 0, szModuleName, -1, wideStr, wideStrLen);
    LPCWSTR lpWideStr = wideStr;
    // Getting PEB
#ifdef _WIN64 // if compiling as x64
    PPEB			pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
    PPEB			pPeb = (PEB*)(__readfsdword(0x30));
#endif// Getting Ldr
    PPEB_LDR_DATA		    pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
    // Getting the first element in the linked list which contains information about the first module
    PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    while (pDte) {
        // If not null
        if (pDte->FullDllName.Length != NULL) {
            // Check if both equal
            if (IsStringEqual(pDte->FullDllName.Buffer, lpWideStr)) {
                //wprintf(L"[+] Module found from PEB : \"%s\" \n", pDte->FullDllName.Buffer);
                return(HMODULE)pDte->Reserved2[0];
            }
        }
        else {
            break;
        }
        // Next element in the linked list
        pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
    }
    wprintf(L"[+] Module not found in PEB");
    return NULL;
}



/**
* Credits to MALDEVACADEMY
* Retrieves the address of an exported function from a specified module handle.
* The function returns NULL if the function name is not found in the specified module handle.
*/
FARPROC CustomGetProcAddress(IN HMODULE hModule, IN char* lpApiName) {
    if (hModule == NULL)
        return NULL;
    // We do this to avoid casting at each time we use 'hModule'
    PBYTE pBase = (PBYTE)hModule;
    // Getting the dos header and doing a signature check
    PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;
    // Getting the nt headers and doing a signature check
    PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;
    // Getting the optional header
    IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
    // Getting the image export table
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    // Getting the function's names array pointer
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    // Getting the function's addresses array pointer
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    // Getting the function's ordinal array pointer
    PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
    // Looping through all the exported functions
    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        // Getting the name of the function
        char* pFunctionName = (char*)(pBase + FunctionNameArray[i]);

        // Getting the address of the function through its ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // Searching for the function specified
        if ( strcmp(lpApiName,pFunctionName)==0) {
            printf("[+] Function %s found at address 0x%p with ordinal %d\n", pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return (FARPROC)pFunctionAddress;
        }
    }
    printf("\n\t[!] Function %s not found\n", lpApiName);
    return NULL;
}







int main()
{
    // Getting handle on ntdll module
    char _ntdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
    printf("[+] Getting handle on ntdll module\n");
    HMODULE hNtdll = CustomGetModuleHandle(_ntdll);
    
    
    // Getting address of NtAllocateVirtualMemory
    char _NtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    printf("\n[+] Getting address of NtAllocateVirtualMemory\n");
    FARPROC pNtAllocateVirtualMemory = CustomGetProcAddress(hNtdll, _NtAllocateVirtualMemory);
    // Getting syscall value of NtAllocateVirtualMemory
    UINT_PTR pNtAllocateVirtualMemorySyscallID = (UINT_PTR)pNtAllocateVirtualMemory + 4; // The syscall ID is typically located at the 4th byte of the function
    UINT_PTR wNtAllocateVirtualMemory = ((unsigned char*)(pNtAllocateVirtualMemorySyscallID))[0];
    printf("[+] Syscall value of NtAllocateVirtualMemory : 0x%04x\n", wNtAllocateVirtualMemory);
    DWORD sysAddrNtAllocateVirtualMemory = (UINT_PTR)pNtAllocateVirtualMemory + 0x12; // (18 in decimal)
    printf("[+] Address of NtAllocateVirtualMemory syscall instruction in ntdll memory : 0x%p\n", sysAddrNtAllocateVirtualMemory);

    // Getting address of NtProtectVirtualMemory
    char _NtProtectVirtualMemory[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    printf("\n[+] Getting address of NtProtectVirtualMemory\n");
    FARPROC pNtProtectVirtualMemory = CustomGetProcAddress(hNtdll, _NtProtectVirtualMemory);
    // Getting syscall value of NtProtectVirtualMemory
    UINT_PTR pNtProtectVirtualMemorySyscallID = (UINT_PTR)pNtProtectVirtualMemory + 4; // The syscall ID is typically located at the 4th byte of the function
    UINT_PTR wNtProtectVirtualMemory = ((unsigned char*)(pNtProtectVirtualMemorySyscallID))[0];
    printf("[+] Syscall value of NtProtectVirtualMemory : 0x%04x\n", wNtProtectVirtualMemory);
    DWORD sysAddrNtProtectVirtualMemory = (UINT_PTR)pNtProtectVirtualMemory + 0x12; // (18 in decimal)
    printf("[+] Address of NtProtectVirtualMemory syscall instruction in ntdll memory : 0x%p\n", sysAddrNtProtectVirtualMemory);

    // Getting address of NtWriteVirtualMemory
    char _NtWriteVirtualMemory[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };
    printf("\n[+] Getting address of NtWriteVirtualMemory\n");
    FARPROC pNtWriteVirtualMemory = CustomGetProcAddress(hNtdll, _NtWriteVirtualMemory);
    // Getting syscall value of NtWriteVirtualMemory
    UINT_PTR pNtWriteVirtualMemorySyscallID = (UINT_PTR)pNtWriteVirtualMemory + 4; // The syscall ID is typically located at the 4th byte of the function
    UINT_PTR wNtWriteVirtualMemory = ((unsigned char*)(pNtWriteVirtualMemorySyscallID))[0];
    printf("[+] Syscall value of NtWriteVirtualMemory : 0x%04x\n", wNtWriteVirtualMemory);
    DWORD sysAddrNtWriteVirtualMemory = (UINT_PTR)pNtWriteVirtualMemory + 0x12; // (18 in decimal)
    printf("[+] Address of NtWriteVirtualMemory syscall instruction in ntdll memory : 0x%p\n", sysAddrNtWriteVirtualMemory);

    // Getting address of NtCreateThread
    char _NtCreateThread[] = { 'N','t','C','r','e','a','t','e','T','h','r','e','a','d',0 };
    printf("\n[+] Getting address of NtCreateThread\n");
    FARPROC pNtCreateThread = CustomGetProcAddress(hNtdll, _NtCreateThread);
    // Getting syscall value of NtCreateThread
    UINT_PTR pNtCreateThreadSyscallID = (UINT_PTR)pNtCreateThread + 4; // The syscall ID is typically located at the 4th byte of the function
    UINT_PTR wNtCreateThread = ((unsigned char*)(pNtCreateThreadSyscallID))[0];
    printf("[+] Syscall value of NtCreateThread : 0x%04x\n", wNtCreateThread);
    DWORD sysAddrNtCreateThread = (UINT_PTR)pNtCreateThread + 0x12; // (18 in decimal)
    printf("[+] Address of NtCreateThread syscall instruction in ntdll memory : 0x%p\n", sysAddrNtCreateThread);


	return 0;   
}