/*
 * Copyright (c) 2010 .SE (The Internet Infrastructure Foundation)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 library.cpp

 Support function for handling PKCS#11 libraries
 *****************************************************************************/

#include <config.h>
#include "library.h"

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>
#if defined(HAVE_LOADLIBRARY)
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <unistd.h>
#else
#include <unistd.h>
#endif
#if defined(HAVE_DLOPEN)
#include <dlfcn.h>
#endif

static bool libraryExists(const std::string& path)
{
#if defined(HAVE_LOADLIBRARY)
	DWORD attributes = GetFileAttributesA(path.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
	return access(path.c_str(), R_OK) == 0;
#endif
}

static std::string executableDirectory()
{
	char path[4096];
#if defined(HAVE_LOADLIBRARY)
	DWORD length = GetModuleFileNameA(NULL, path, sizeof(path));
	if (length == 0 || length >= sizeof(path)) return std::string();
	path[length] = '\0';
#elif defined(__APPLE__)
	uint32_t size = sizeof(path);
	if (_NSGetExecutablePath(path, &size) != 0) return std::string();
#else
	ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
	if (length <= 0) return std::string();
	path[length] = '\0';
#endif
	std::string result(path);
	size_t slash = result.find_last_of("/\\");
	return slash == std::string::npos ? std::string() : result.substr(0, slash);
}

const char* defaultLibraryPath()
{
#if defined(SOFTHSM2_PORTABLE_TOOL)
	static std::string resolved;
	if (!resolved.empty()) return resolved.c_str();

#if defined(HAVE_LOADLIBRARY)
	const char* moduleName = "softhsm2.dll";
	const char separator = '\\';
#elif defined(__APPLE__)
	const char* moduleName = "libsofthsm2.dylib";
	const char separator = '/';
#else
	const char* moduleName = "libsofthsm2.so";
	const char separator = '/';
#endif
	std::string directory = executableDirectory();
	if (!directory.empty())
	{
		std::vector<std::string> candidates;
		candidates.push_back(directory + separator + moduleName);
		candidates.push_back(directory + separator + ".." + separator + moduleName);
		for (std::vector<std::string>::const_iterator it = candidates.begin();
			it != candidates.end(); ++it)
		{
			if (libraryExists(*it))
			{
				resolved = *it;
				return resolved.c_str();
			}
		}
	}
#endif
	return DEFAULT_PKCS11_LIB;
}

// Load the PKCS#11 library
CK_C_GetFunctionList loadLibrary(char* module, void** moduleHandle,
				char **pErrMsg)
{
	CK_C_GetFunctionList pGetFunctionList = NULL;

#if defined(HAVE_LOADLIBRARY)
	HINSTANCE hDLL = NULL;
	DWORD dw = NULL;
	static char errMsg[100];

	// Load PKCS #11 library
	hDLL = LoadLibraryA(module ? module : defaultLibraryPath());

	if (hDLL == NULL)
	{
		// Failed to load the PKCS #11 library
		dw = GetLastError();
		snprintf((char*)errMsg, sizeof(errMsg), "LoadLibraryA failed: 0x%08X", dw);
		*pErrMsg = errMsg;
		return NULL;
	}
	else
	{
		*pErrMsg = NULL;
	}

	// Retrieve the entry point for C_GetFunctionList
	pGetFunctionList = (CK_C_GetFunctionList) GetProcAddress(hDLL, "C_GetFunctionList");
	if (pGetFunctionList == NULL)
	{
		dw = GetLastError();
		snprintf((char*)errMsg, sizeof(errMsg), "getProcAddress failed: 0x%08X", dw);
		*pErrMsg = errMsg;
		FreeLibrary(hDLL);
		return NULL;
	}

	// Store the handle so we can FreeLibrary it later
	*moduleHandle = hDLL;

#elif defined(HAVE_DLOPEN)
	void* pDynLib = NULL;

	// Load PKCS #11 library
	pDynLib = dlopen(module ? module : defaultLibraryPath(), RTLD_NOW | RTLD_LOCAL);

	*pErrMsg = dlerror();
	if (pDynLib == NULL || *pErrMsg != NULL)
	{
		if (pDynLib != NULL) dlclose(pDynLib);

		// Failed to load the PKCS #11 library
		return NULL;
	}

	// Retrieve the entry point for C_GetFunctionList
	pGetFunctionList = (CK_C_GetFunctionList) dlsym(pDynLib, "C_GetFunctionList");

	// Store the handle so we can dlclose it later
	*pErrMsg = dlerror();
	if (*pErrMsg != NULL)
	{
		dlclose(pDynLib);

		// An error occured during dlsym()
		return NULL;
	}

	*moduleHandle = pDynLib;
#else
	fprintf(stderr, "ERROR: Not compiled with library support.\n");

	return NULL;
#endif

	return pGetFunctionList;
}

void unloadLibrary(void* moduleHandle)
{
	if (moduleHandle)
	{
#if defined(HAVE_LOADLIBRARY)
		FreeLibrary((HMODULE) moduleHandle);
#elif defined(HAVE_DLOPEN)
		dlclose(moduleHandle);
#endif
	}
}
