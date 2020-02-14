#pragma once

#include <string>

#include <Windows.h>
#include <TlHelp32.h>

#include "dll.h"

bool debugMode = false;

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

        if (!handle && debugMode) {
            std::cout << "Failed to open process: " << name << std::endl;
            *this = Process(processName);
        } else if (!handle) {
            *this = Process(processName);
        }

        modules = getModules(processID);

    }

    Process(DWORD processID_) {
        name = getProcessName(processID_);
        processID = processID_;

        if (processID)
            handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

        if (!handle && debugMode)
            std::cout << "Failed to open process: " << name << std::endl;
        else if (!handle)
            *this = Process(processID_);
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
                if (!VirtualProtectEx(handle, address, sizeof(BYTE), PAGE_EXECUTE_READWRITE, &oldProtect) && debugMode)
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeByte(address, b);
                }

                if (!WriteProcessMemory(handle, address, &b, sizeof(BYTE), 0) && debugMode)
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                if (!VirtualProtectEx(handle, address, sizeof(BYTE), oldProtect, &oldProtect) && debugMode)
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
                if (!VirtualProtectEx(handle, address, sizeof(int), PAGE_EXECUTE_READWRITE, &oldProtect) && debugMode)
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeInt(address, i);
                }

                if (!WriteProcessMemory(handle, address, &i, sizeof(int), 0) && debugMode)
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                if (!VirtualProtectEx(handle, address, sizeof(int), oldProtect, &oldProtect) && debugMode)
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
                if (!VirtualProtectEx(handle, address, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtect) && debugMode)
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;
                
                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeDword(address, d);
                }

                if (!WriteProcessMemory(handle, address, &d, sizeof(DWORD), 0) && debugMode)
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                if (!VirtualProtectEx(handle, address, sizeof(DWORD), oldProtect, &oldProtect) && debugMode)
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
                if (!VirtualProtectEx(handle, address, str.length()+1, PAGE_EXECUTE_READWRITE, &oldProtect) && debugMode)
                    std::cout << "Error modifying process memory access - " << GetLastError() << std::endl;

                if (GetLastError() == 0x5) {
                    this->processID = getProcessID(name);

                    if (processID != 0)
                        this->handle = OpenProcess(PROCESS_ALL_ACCESS, false, processID);

                    if (this->handle)
                        this->writeString(address, str);
                }

                if (!WriteProcessMemory(handle, address, str.c_str(), str.length()+1, 0) && debugMode)
                    std::cout << "Error writing to process memory - " << GetLastError() << std::endl;
                
                if (!VirtualProtectEx(handle, address, str.length()+1, oldProtect, &oldProtect) && debugMode)
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

        this->writeString(dllNameAddress, dll.image->ModuleName);


        PVOID pLoadLibraryA = this->getProcAddress("KERNEL32.DLL", "LoadLibraryA");

        if (!this->handle) {
            std::cout << "Error no handle!" << std::endl;
        }

        HANDLE remoteThread = CreateRemoteThread(this->handle, 0, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllNameAddress, 0, 0);

        std::cout << remoteThread << std::endl;

        if (!remoteThread) {
            std::cout << "Error creating remote thread in process" << std::endl;
            return false;
        }

        this->freeMemory(dllNameAddress);

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