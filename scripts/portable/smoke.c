#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
# include <windows.h>
#else
# include <dlfcn.h>
#endif

typedef unsigned long CK_RV;
typedef CK_RV (*initialize_fn)(void*);
typedef CK_RV (*finalize_fn)(void*);

int main(int argc, char** argv)
{
	initialize_fn initialize;
	finalize_fn finalize;

	if (argc != 2)
	{
		fprintf(stderr, "usage: portable-smoke <module>\n");
		return 2;
	}

#ifdef _WIN32
	HMODULE module = LoadLibraryA(argv[1]);
	if (module == NULL)
	{
		fprintf(stderr, "LoadLibrary failed: %lu\n", GetLastError());
		return 1;
	}
	initialize = (initialize_fn)GetProcAddress(module, "C_Initialize");
	finalize = (finalize_fn)GetProcAddress(module, "C_Finalize");
#else
	void* module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
	if (module == NULL)
	{
		fprintf(stderr, "dlopen failed: %s\n", dlerror());
		return 1;
	}
	initialize = (initialize_fn)dlsym(module, "C_Initialize");
	finalize = (finalize_fn)dlsym(module, "C_Finalize");
#endif

	if (initialize == NULL || finalize == NULL)
	{
		fprintf(stderr, "PKCS #11 entry points are missing\n");
		return 1;
	}
	if (initialize(NULL) != 0)
	{
		fprintf(stderr, "C_Initialize failed\n");
		return 1;
	}
	if (finalize(NULL) != 0)
	{
		fprintf(stderr, "C_Finalize failed\n");
		return 1;
	}

#ifdef _WIN32
	FreeLibrary(module);
#else
	dlclose(module);
#endif
	return 0;
}
