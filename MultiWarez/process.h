#pragma once

#include <string>

#include <Windows.h>
#include <TlHelp32.h>

#include "dll.h"

class Module {

public:

    PVOID address;
    std::string name;
    MODULEENTRY32 mod;

    Module(PVOID address, std::string name, MODULEENTRY32 mod) {
        this->address = address;
        this->name = name;
        this->mod = mod;
    }

};

class Process {

public:

    std::string name = "";
    DWORD processID = 0;
    PVOID baseAddress = 0;
    HANDLE handle = 0;

    std::vector<Module> modules;

    Process(std::string processName) {
        name = processName;
        processID = getProcessID(processName);

        if (processID)
            handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

        if (!handle) {
            *this = Process(processName);
        }

        modules = getModules(processID);

    }

    Process(DWORD processID_) {
        name = getProcessName(processID_);
        processID = processID_;

        if (processID)
            handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

        if (!handle)
            *this = Process(processID_);

        modules = getModules(processID_);
    }

    ~Process() {
        if (this->handle && this->handle != INVALID_HANDLE_VALUE)
            CloseHandle(this->handle);
    }

    PVOID pointerToAddress(PVOID base, int offsets[]) {

        PVOID r = 0x0;

        if (handle) {

            r = base;

            for (int i = 0; i < (sizeof(offsets) / 4) - 1; i++) {
                r = (PVOID)readDword(r);
                r = (PVOID)((BYTE*)r+offsets[i]);
            }

        } else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    return pointerToAddress(base, offsets);
                }

            }
        }

        return r;

    }

    BYTE readByte(PVOID address) {
        if (handle) {
            BYTE r = -0xff;
            ReadProcessMemory(handle, (LPCVOID)address, &r, sizeof(BYTE), 0);
            return r;
        } else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    return readByte(address);
                }

            }
        }
    }

    std::vector<BYTE> readBytes(PVOID address, int size) {

        std::vector<BYTE> bytes = {};

        for (int i = 0; i < size; i += sizeof(BYTE))
            bytes.push_back(this->readByte((PVOID)((BYTE*)address + i)));

        return bytes;
    }

    int readInt(PVOID address) {
        if (handle) {
            int r = 0;
            ReadProcessMemory(handle, (LPCVOID)address, &r, sizeof(int), 0);
            return r;
        } else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    return readInt(address);
                }

            }
        }
    }

    std::vector<int> readInts(PVOID address, int size) {

        std::vector<int> ints = {};

        for (int i = 0; i < size; i += sizeof(int))
            ints.push_back(this->readInt((PVOID)((BYTE*)address + i)));

        return ints;
    }

    DWORD readDword(PVOID address) {
        if (handle) {
            DWORD r = 0;
            ReadProcessMemory(handle, (LPCVOID)address, &r, sizeof(DWORD), 0);
            return r;
        } else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    return readDword(address);
                }

            }
        }
    }

    std::vector<DWORD> readDwords(PVOID address, int size) {

        std::vector<DWORD> dwords = {};

        for (int i = 0; i < size; i += sizeof(DWORD))
            dwords.push_back(this->readDword((PVOID)((BYTE*)address + i)));

        return dwords;
    }

    std::string readString(PVOID address) {

        std::string r = "";

        if (handle) {
            char c = 0xFF;
            int i = 0;
            while (c != 0x0) {
                ReadProcessMemory(handle, (LPCVOID)((BYTE*)address+i), &c, sizeof(char), 0);
                r += c;
                i += 1;
            }

            return r;
        }
        else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    return readString(address);
                }

            }
        }
    }

    std::vector<std::string> readStrings(PVOID address, int size) {

        std::vector<std::string> strings = {};
        
        std::string temp = "";

        int charsRead = 0;
        BYTE c = 0x1;

        for (int j = 0; j < size; j++) {

            while (c != 0x0) {
                c = this->readByte((PVOID)((BYTE*)address + charsRead));
                temp += c;
                charsRead++;
            }

            strings.push_back(temp);

            charsRead = 0;
            c = 0x1;

        }

        return strings;

    }

    void writeByte(PVOID address, BYTE b) {
        
        if (handle) {

            if (address != 0) {

                DWORD oldProtect;
                if (!VirtualProtectEx(handle, address, sizeof(BYTE), PAGE_EXECUTE_READWRITE, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeByte(address, b);
                }

                if (!WriteProcessMemory(handle, address, &b, sizeof(BYTE), 0))
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                if (!VirtualProtectEx(handle, address, sizeof(BYTE), oldProtect, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

            } else {
                writeByte(address, b);
            }

        } else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    writeByte(address, b);
                }

            }
        }
    }

    void writeBytes(PVOID address, BYTE bytes[]) {

        for (int i = 0; i < sizeof(bytes); i++)
            this->writeByte((PVOID)((BYTE*)address + i), bytes[i]);

    }

    void writeInt(PVOID address, int i) {

        if (handle) {

            if (address != 0) {

                DWORD oldProtect;
                if (!VirtualProtectEx(handle, address, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeInt(address, i);
                }

                if (!WriteProcessMemory(handle, address, &i, sizeof(int), 0))
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                if (!VirtualProtectEx(handle, address, sizeof(int), oldProtect, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

            } else {
                writeInt(address, i);
            }

        } else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    writeInt(address, i);
                }

            }
        }

    }

    void writeInts(PVOID address, int ints[]) {

        for (int i = 0; i < sizeof(ints)/sizeof(int); i += sizeof(int))
            this->writeInt(address, ints[i]);

    }

    void writeDword(PVOID address, DWORD d) {

        if (handle) {

            if (address != 0) {

                DWORD oldProtect;
                if (!VirtualProtectEx(handle, address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;
                
                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeDword(address, d);
                }

                if (!WriteProcessMemory(handle, address, &d, sizeof(DWORD), 0))
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                if (!VirtualProtectEx(handle, address, sizeof(DWORD), oldProtect, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;
            
            } else {
                writeDword(address, d);
            }

        } else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    writeDword(address, d);
                }

            }
        }
    }

    void writeDwords(PVOID address, DWORD dwords[]) {

        for (int i = 0; i < sizeof(dwords) / sizeof(DWORD); i += sizeof(DWORD))
            this->writeDword(address, dwords[i]);

    }

    void writeString(PVOID address, std::string str) {

        if (handle) {

            if (address != 0) {

                DWORD oldProtect;
                if (!VirtualProtectEx(handle, address, str.length()+1, PAGE_EXECUTE_READWRITE, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeString(address, str);
                }

                if (!WriteProcessMemory(handle, address, str.c_str(), str.length()+1, 0))
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                
                if (!VirtualProtectEx(handle, address, str.length()+1, oldProtect, &oldProtect))
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

            } else {
                writeString(address, str);
            }

        }
        else {
            processID = getProcessID(name);

            if (processID != 0) {

                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                if (handle) {
                    writeString(address, str);
                }

            }
        }

    }

    void writeStrings(PVOID address, std::vector<std::string> strings) {

        int strlens = 0;

        for (int i = 0; i < strings.size(); i++) {
            this->writeString((PVOID)((char*)address+strlens), strings[i]);
            strlens += strings[i].length()+1;
        }

    }

    // Original scan 370 bytes/second 
    // Optimized scan 8,520 bytes/second
    // Ultra optimized scan 11,003 bytes/second

    BYTE* aobScan(std::vector<BYTE> bytes) {

        BYTE* address = 0x0;

        std::vector<BYTE> read;

        std::vector<BYTE> subBytes;
        std::vector<BYTE> subRead;

        for (BYTE* dw = (BYTE*)getModuleAddress(); dw < (BYTE*)0xFFFFFFFF; dw+=0) {

            read = this->readBytes(dw, bytes.size());

            if (read == bytes) {
                address = dw;
                break;
            }

            int index = byteIndexInVector(read, bytes[0]);

            if (index != -1) {

                int offset = read.size() - 1 - index;

                subBytes = firstBytesInVector(lastBytesInVector(bytes, offset+1), offset);
                subRead = lastBytesInVector(read, offset);

                if (subBytes == subRead)
                    dw += read.size() - 1 - offset;
                else
                    dw += bytes.size();

            } else {
                dw += bytes.size();
            }

        }

        return address;
    }

    PVOID allocMemory(SIZE_T size) {

        void* address = 0;

        if (handle) {

            address = VirtualAllocEx(handle, 0, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (!address)
                std::cout << "Error allocating memory in remote process - " << GetLastError() << std::endl;
        }
        else {

            if (processID != 0)
                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
            else
                *this = Process(name);

            return this->allocMemory(size);
        }
        
        return address;
    }

    void freeMemory(PVOID address) {

        if (handle) {
            if (address != 0)
                    if (!VirtualFreeEx(handle, address, 0, MEM_RELEASE))
                        std::cout << "Error freeing memory in remote process - " << GetLastError() << std::endl;
        } else {

            if (processID != 0)
                handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);
            else
                *this = Process(name);

            this->freeMemory(address);

        }

    }

    BOOL basicInject(Dll dll) {

        char* dllNameAddress = (char*)this->allocMemory(MAX_PATH);

        if (dllNameAddress == 0x0) {
            std::cout << "Error allocating memory for DLL name" << std::endl;
            return false;
        }

        this->writeString(dllNameAddress, dll.name);


        PVOID pLoadLibraryA = this->getProcAddress("KERNEL32.DLL", "LoadLibraryA");

        if (!this->handle) {
            std::cout << "Error no handle!" << std::endl;
            *this = Process(this->name);
        }

        HANDLE remoteThread = CreateRemoteThread(this->handle, 0, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllNameAddress, 0, 0);

        Sleep(1); // This magically fixes everything. Without this sleep the program crashes... I hate programming sometimes

        if (!remoteThread) {
            std::cout << "Error creating remote thread in process" << std::endl;
            return false;
        }

        this->freeMemory(dllNameAddress);

        return true;
    }

    BOOL manualInject(Dll dll) {

        if (!this->handle) {
            std::cout << "Invalid handle!" << std::endl;
            return false;
        }

        if (!dll.size) {
            std::cout << "Invalid DLL size!" << std::endl;
            return false;
        }

        if (!dll.dosHeader) {
            std::cout << "Invalid DLL DOS Header!" << std::endl;
            return false;
        }

        if (!dll.ntHeaders) {
            std::cout << "Invalid DLL NT Headers!" << std::endl;
            return false;
        }

        if (!dll.sectionHeader) {
            std::cout << "Invalid DLL Section Header!" << std::endl;
            return false;
        }

        PVOID image = VirtualAllocEx(this->handle, 0, (SIZE_T)dll.ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (!image) {
            std::cout << "Error allocating memory in remote process for DLL!" << std::endl;
            return false;
        }

        if (!WriteProcessMemory(this->handle, image, dll.data, dll.ntHeaders->OptionalHeader.SizeOfHeaders, 0)) {
            std::cout << "Error writing DLL headers to remote process!" << std::endl;
        }

        for (int i = 0; i < dll.ntHeaders->FileHeader.NumberOfSections; i++) {
            if (!WriteProcessMemory(this->handle, (PVOID)((BYTE*)image + dll.sectionHeader[i].VirtualAddress),
                (PVOID)((BYTE*)dll.data + dll.sectionHeader[i].PointerToRawData), dll.sectionHeader[i].SizeOfRawData, 0)) {
                std::cout << "Error writing DLL section header to remote process!" << std::endl;
            }
        }

        PVOID loader = VirtualAllocEx(this->handle, 0, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        if (!loader) {
            std::cout << "Error allocating memory for loader code!" << std::endl;
        }

        DllData dllData;

        memset(&dllData, 0, sizeof(DllData));

        dllData.baseAddress = image;
        dllData.ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)image + dll.dosHeader->e_lfanew);
        dllData.reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)image + dll.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        dllData.importDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)image + dll.ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        dllData.loadLibraryA = LoadLibraryA;
        dllData.getProcAddress = GetProcAddress;
        dllData.dllMain = (pDllMain)((PVOID)((BYTE*)image + dll.ntHeaders->OptionalHeader.AddressOfEntryPoint));

        if (!WriteProcessMemory(this->handle, loader, &dllData, sizeof(DllData), 0)) {
            std::cout << "Error writing DllData struct to process memory!" << std::endl;
        }

        if (!WriteProcessMemory(this->handle, (PVOID)((DllData*)loader + 1), LoadDll, (DWORD)LoadDllEnd - (DWORD)LoadDll, 0)) {
            std::cout << "Error writing loader code to process memory!" << std::endl;
        }

        HANDLE hThread = CreateRemoteThread(this->handle, 0, 0, (LPTHREAD_START_ROUTINE)((DllData*)loader + 1), loader, 0, 0);

        if (!hThread) {
            std::cout << "Error creating remote thread in process!" << std::endl;
        }

        DWORD exitCode;

        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &exitCode);

        if (!exitCode) {
            std::cout << "Thread did not exit properly!" << std::endl;
        }

        CloseHandle(hThread);
        
        VirtualFreeEx(this->handle, loader, 0, MEM_RELEASE);

        return true;
    }

    PVOID getModuleAddress(std::string moduleName) {

        for (Module module : this->modules)
            if (module.name == moduleName)
                return module.address;

        return 0x0;

    }

    FARPROC getProcAddress(std::string moduleName, std::string procName) {
        return GetProcAddress(this->getModuleHandle(moduleName), procName.c_str());
    }

    FARPROC getProcAddress(std::string procName) {
        return GetProcAddress(this->getModuleHandle(), procName.c_str());
    }

    HMODULE getModuleHandle(std::string moduleName) {

        for (Module module : this->modules)
            if (module.name == moduleName)
                return module.mod.hModule;

        return 0x0;

    }

    PVOID getModuleAddress() {

        for (Module module : this->modules)
            if (module.name == name)
                return module.address;

        return 0x0;

    }

    HMODULE getModuleHandle() {

        for (Module module : this->modules)
            if (module.name == name)
                return module.mod.hModule;

        return 0x0;

    }

private:

    DWORD getProcessID(std::string processName) {

        DWORD processID = 0;

        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

        if (Process32First(snapshot, &entry))
            do {
                if (_stricmp(entry.szExeFile, processName.c_str()) == 0)
                    processID = entry.th32ProcessID;
            } while (Process32Next(snapshot, &entry));
    
        return processID;
    }

    std::string getProcessName(DWORD processID) {

        std::string processName = "";
        
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

        if (Process32First(snapshot, &entry))
            while (Process32Next(snapshot, &entry))
                if (entry.th32ProcessID == processID)
                    processName = entry.szExeFile;

        return processName;

    }

    std::vector<Module> getModules(DWORD processID) {

        std::vector<Module> modules;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processID);

        MODULEENTRY32 mod;
        mod.dwSize = sizeof(MODULEENTRY32);

        if (snapshot)
            if (Module32First(snapshot, &mod))
                do {
                    Module module(mod.modBaseAddr, mod.szModule, mod);
                    modules.push_back(module);
                } while (Module32Next(snapshot, &mod));

        
        return modules;
    }

    int byteIndexInVector(std::vector<BYTE> vec, BYTE byte) {

        int index = -1;

        for (int i = 0; i < vec.size(); i++)
            if (vec[i] == byte) {
                index = i;
                break;
            }
                
        return index;
    }

    std::vector<BYTE> firstBytesInVector(std::vector<BYTE> vec, int num) {

        std::vector<BYTE> r;

        for (int i = 0; i < num; i++)
            r.push_back(vec[i]);

        return r;

    }

    std::vector<BYTE> lastBytesInVector(std::vector<BYTE> vec, int num) {

        std::vector<BYTE> r;

        for (int i = vec.size() - num; i < vec.size(); i++)
            r.push_back(vec[i]);

        return r;

    }

};