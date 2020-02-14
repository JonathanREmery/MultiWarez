#pragma once

#include <Windows.h>
#include <Imagehlp.h>

#pragma comment(lib, "Imagehlp.lib")

class Dll {

public:

	PLOADED_IMAGE image;

	Dll(const char* dllName) {
		image = ImageLoad(dllName, NULL);
	}

};