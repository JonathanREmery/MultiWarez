#pragma once

#include <Windows.h>
#include <Imagehlp.h>

#pragma comment(lib, "Imagehlp.lib")

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL(WINAPI* pDllMain)(HMODULE, DWORD, PVOID);

typedef struct _DllData {
    PVOID baseAddress;

    PIMAGE_NT_HEADERS ntHeaders;
    PIMAGE_BASE_RELOCATION reloc;
    PIMAGE_IMPORT_DESCRIPTOR importDescriptors;
    pLoadLibraryA loadLibraryA;
    pGetProcAddress getProcAddress;
    pDllMain dllMain;
} DllData;

DWORD WINAPI LoadDll(PVOID address) {


    DllData* dllData = (DllData*)address;

    PIMAGE_BASE_RELOCATION reloc = dllData->reloc;

    DWORD delta = (DWORD)((BYTE*)dllData->baseAddress - dllData->ntHeaders->OptionalHeader.ImageBase);

    while (reloc->VirtualAddress) {
        if (reloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            DWORD numPointers = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            PWORD pointerList = (PWORD)(reloc + 1);

            for (int i = 0; i < numPointers; i++) {
                if (pointerList[i]) {
                    PDWORD pointer = (PDWORD)((BYTE*)dllData->baseAddress + (reloc->VirtualAddress + (pointerList[i] & 0xFFF)));
                    *pointer += delta;
                }
            }
        }

        reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptors = dllData->importDescriptors;

    while (importDescriptors->Characteristics) {
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)dllData->baseAddress + importDescriptors->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)dllData->baseAddress + importDescriptors->FirstThunk);

        HMODULE hModule = dllData->loadLibraryA((LPCSTR)dllData->baseAddress + importDescriptors->Name);

        if (!hModule) {
            return 0;
        }

        while (originalFirstThunk->u1.AddressOfData) {
            if (originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                DWORD procAddr = (DWORD)dllData->getProcAddress(hModule, (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF));

                if (!procAddr) {
                    return 0;
                }

                firstThunk->u1.Function = procAddr;
            }
            else {
                PIMAGE_IMPORT_BY_NAME nameImport = (PIMAGE_IMPORT_BY_NAME)((BYTE*)dllData->baseAddress + originalFirstThunk->u1.AddressOfData);
                DWORD procAddr = (DWORD)dllData->getProcAddress(hModule, (LPCSTR)nameImport->Name);

                if (!procAddr) {
                    return 0;
                }

                firstThunk->u1.Function = procAddr;
            }

            originalFirstThunk++;
            firstThunk++;
        }

        importDescriptors++;
    }

    if (dllData->ntHeaders->OptionalHeader.AddressOfEntryPoint) {
        return dllData->dllMain((HMODULE)dllData->baseAddress, DLL_PROCESS_ATTACH, 0);
    }

    return 1;
}

DWORD WINAPI LoadDllEnd() {
    return 0;
}

class Dll {

public:

	const char* name;

	PVOID data;

	PIMAGE_DOS_HEADER dosHeader;
	PIMAGE_NT_HEADERS ntHeaders;
	PIMAGE_SECTION_HEADER sectionHeader;

	DWORD size;

	Dll(const char* dllName) {

		this->name = dllName;

		HANDLE dllHandle = CreateFileA(this->name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);

		if (!dllHandle) {
			std::cout << "Error opening DLL file!" << std::endl;
			*this = Dll(dllName);
		}

		this->size = GetFileSize(dllHandle, 0);

		this->data = VirtualAlloc(NULL, this->size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (!this->data) {
			std::cout << "Could not allocate memory for DLL!" << std::endl;
		}

        data = VirtualAlloc(0, this->size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (!ReadFile(dllHandle, this->data, this->size, 0, 0)) {
			std::cout << "Error reading file - " << GetLastError() << std::endl;
		}

		CloseHandle(dllHandle);

		this->dosHeader = (PIMAGE_DOS_HEADER)this->data;

		if (this->dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			std::cout << "Invalid DOS header!" << std::endl;
		}

		this->ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)this->data + this->dosHeader->e_lfanew);

		if (this->ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
			std::cout << "Invalid NT headers!" << std::endl;
		}

		this->sectionHeader = (PIMAGE_SECTION_HEADER)(this->ntHeaders + 1);
	}

	~Dll() {
		VirtualFree(this->data, 0, MEM_RELEASE);
	}

};