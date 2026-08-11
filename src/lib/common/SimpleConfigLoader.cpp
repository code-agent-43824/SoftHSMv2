/*
 * Copyright (c) 2010 .SE, The Internet Infrastructure Foundation
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
 SimpleConfigLoader.cpp

 Loads the configuration from the configuration file.
 *****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <limits.h>
#include <sstream>
#include <vector>
#ifdef _WIN32
# include <direct.h>
# include <fcntl.h>
# include <io.h>
# include <process.h>
# include <sys/stat.h>
# include <windows.h>
#else
# include <dlfcn.h>
# include <fcntl.h>
# include <sys/stat.h>
# include <unistd.h>
#endif
#include "config.h"
#if defined(HAVE_GETPWUID_R)
# include <sys/types.h>
# include <pwd.h>
#endif
#include "SimpleConfigLoader.h"
#include "log.h"
#include "Configuration.h"

// Initialise the one-and-only instance
#ifdef HAVE_CXX11
std::unique_ptr<SimpleConfigLoader> SimpleConfigLoader::instance(nullptr);
#else
std::auto_ptr<SimpleConfigLoader> SimpleConfigLoader::instance(NULL);
#endif

// Return the one-and-only instance
SimpleConfigLoader* SimpleConfigLoader::i()
{
	if (instance.get() == NULL)
	{
		instance.reset(new SimpleConfigLoader());
	}

	return instance.get();
}

// Constructor
SimpleConfigLoader::SimpleConfigLoader()
{
}

#define PORTABLE_CONFIG_FILE "softhsm.conf"
#define LEGACY_PORTABLE_CONFIG_FILE "softhsm2.conf"
#ifdef SOFTHSM2_PORTABLE_USER_CONFIG
# define USER_CONFIG_FILE "softhsm.conf"
# define CONFIG_DIRECTORY "softhsm"
#else
# define USER_CONFIG_FILE "softhsm2.conf"
# define CONFIG_DIRECTORY ".config/softhsm2"
#endif

static const char DEFAULT_USER_CONFIGURATION[] =
	"# SoftHSM v2 configuration file\n"
	"# Relative paths are resolved from this configuration file.\n"
	"directories.tokendir = tokens\n"
	"objectstore.backend = file\n"
	"objectstore.umask = 0077\n"
	"log.level = ERROR\n"
	"slots.removable = false\n"
	"slots.mechanisms = ALL\n"
	"library.reset_on_fork = false\n"
	"FAKE_RUTOKEN_ECP = false\n";

namespace
{
#ifndef SOFTHSM2_PORTABLE_USER_CONFIG
	static int moduleAnchor;
#endif

	static bool isPathSeparator(char c)
	{
		return c == '/' || c == '\\';
	}

	static std::string parentDirectory(const std::string& path)
	{
		const std::string::size_type separator = path.find_last_of("/\\");
		if (separator == std::string::npos)
		{
			return ".";
		}
		if (separator == 0)
		{
			return path.substr(0, 1);
		}
#ifdef _WIN32
		if (separator == 2 && path.size() >= 3 && path[1] == ':')
		{
			return path.substr(0, 3);
		}
#endif
		return path.substr(0, separator);
	}

	static std::string joinPath(const std::string& directory, const std::string& name)
	{
		if (directory.empty() || directory == ".")
		{
#ifdef _WIN32
			return std::string(".\\") + name;
#else
			return std::string("./") + name;
#endif
		}
		if (isPathSeparator(directory[directory.size() - 1]))
		{
			return directory + name;
		}
#ifdef _WIN32
		return directory + "\\" + name;
#else
		return directory + "/" + name;
#endif
	}

	static bool isAbsolutePath(const std::string& path)
	{
		if (path.empty())
		{
			return false;
		}
#ifdef _WIN32
		if (isPathSeparator(path[0]))
		{
			return true;
		}
		return path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) &&
		       path[1] == ':' && isPathSeparator(path[2]);
#else
		return path[0] == '/';
#endif
	}

	static bool isReadableFile(const std::string& path)
	{
#ifdef _WIN32
		return _access(path.c_str(), 4) == 0;
#else
		return access(path.c_str(), R_OK) == 0;
#endif
	}

	static bool isDirectory(const std::string& path)
	{
#ifdef _WIN32
		struct _stat status;
		return _stat(path.c_str(), &status) == 0 && (status.st_mode & _S_IFDIR) != 0;
#else
		struct stat status;
		return stat(path.c_str(), &status) == 0 && S_ISDIR(status.st_mode);
#endif
	}

	static bool createDirectory(const std::string& path)
	{
		if (isDirectory(path))
		{
			return true;
		}

		const std::string parent = parentDirectory(path);
		if (parent != path && parent != "." && !isDirectory(parent) && !createDirectory(parent))
		{
			return false;
		}

#ifdef _WIN32
		return _mkdir(path.c_str()) == 0 || (errno == EEXIST && isDirectory(path));
#else
		return mkdir(path.c_str(), S_IRWXU) == 0 || (errno == EEXIST && isDirectory(path));
#endif
	}

	static bool readFile(const std::string& path, std::vector<unsigned char>& contents)
	{
		FILE* stream = fopen(path.c_str(), "rb");
		if (stream == NULL)
		{
			return false;
		}

		unsigned char buffer[4096];
		for (;;)
		{
			const size_t length = fread(buffer, 1, sizeof(buffer), stream);
			contents.insert(contents.end(), buffer, buffer + length);
			if (length < sizeof(buffer))
			{
				const bool success = feof(stream) != 0;
				fclose(stream);
				return success;
			}
		}
	}

	static bool writeAll(int descriptor, const unsigned char* data, size_t length)
	{
		while (length != 0)
		{
#ifdef _WIN32
			const unsigned int chunk = length > static_cast<size_t>(INT_MAX) ? INT_MAX :
			                          static_cast<unsigned int>(length);
			const int written = _write(descriptor, data, chunk);
#else
			const ssize_t written = write(descriptor, data, length);
#endif
			if (written <= 0)
			{
				return false;
			}
			data += written;
			length -= static_cast<size_t>(written);
		}
		return true;
	}

	static bool installFileAtomically(const std::string& path,
	                                  const std::vector<unsigned char>& contents)
	{
		if (isReadableFile(path))
		{
			return true;
		}
		if (!createDirectory(parentDirectory(path)))
		{
			return false;
		}

		for (unsigned int attempt = 0; attempt < 100; ++attempt)
		{
			std::ostringstream name;
#ifdef _WIN32
			name << path << ".tmp." << _getpid() << "." << attempt;
			const std::string temporary = name.str();
			const int descriptor = _open(temporary.c_str(),
			                             _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY,
			                             _S_IREAD | _S_IWRITE);
#else
			name << path << ".tmp." << getpid() << "." << attempt;
			const std::string temporary = name.str();
			const int descriptor = open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
#endif
			if (descriptor < 0)
			{
				if (errno == EEXIST)
				{
					continue;
				}
				return isReadableFile(path);
			}

			const bool written = contents.empty() ||
			                     writeAll(descriptor, &contents[0], contents.size());
#ifdef _WIN32
			const bool closed = _close(descriptor) == 0;
			bool installed = written && closed &&
			                 MoveFileExA(temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH) != 0;
			if (!installed)
			{
				DeleteFileA(temporary.c_str());
			}
#else
			const bool closed = close(descriptor) == 0;
			const bool installed = written && closed && link(temporary.c_str(), path.c_str()) == 0;
			unlink(temporary.c_str());
#endif
			if (installed || isReadableFile(path))
			{
				return true;
			}
			return false;
		}

		return isReadableFile(path);
	}

	static bool materializeUserConfig(const std::string& userPath, const char* templatePath)
	{
		std::vector<unsigned char> contents;
		if (templatePath != NULL)
		{
			if (!readFile(templatePath, contents))
			{
				return false;
			}
		}
		else
		{
			contents.assign(DEFAULT_USER_CONFIGURATION,
			                DEFAULT_USER_CONFIGURATION + strlen(DEFAULT_USER_CONFIGURATION));
		}
		return installFileAtomically(userPath, contents);
	}

#ifndef SOFTHSM2_PORTABLE_USER_CONFIG
	static std::string moduleFilePath()
	{
#ifdef _WIN32
		HMODULE module = NULL;
		if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
		                        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		                        reinterpret_cast<LPCSTR>(&moduleAnchor), &module))
		{
			return std::string();
		}

		std::vector<char> path(512);
		for (;;)
		{
			const DWORD length = GetModuleFileNameA(module, &path[0], static_cast<DWORD>(path.size()));
			if (length == 0)
			{
				return std::string();
			}
			if (length < path.size() - 1)
			{
				return std::string(&path[0], length);
			}
			path.resize(path.size() * 2);
		}
#else
		Dl_info info;
		if (dladdr(static_cast<void*>(&moduleAnchor), &info) == 0 || info.dli_fname == NULL)
		{
			return std::string();
		}

		char resolved[PATH_MAX];
		if (realpath(info.dli_fname, resolved) != NULL)
		{
			return std::string(resolved);
		}
		return std::string(info.dli_fname);
#endif
	}

	static char* getPortableConfigPath()
	{
		const std::string modulePath = moduleFilePath();
		if (modulePath.empty())
		{
			return NULL;
		}

		const std::string directory = parentDirectory(modulePath);
		const char* candidates[] = { PORTABLE_CONFIG_FILE, LEGACY_PORTABLE_CONFIG_FILE };
		for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i)
		{
			const std::string candidate = joinPath(directory, candidates[i]);
			if (isReadableFile(candidate))
			{
				return strdup(candidate.c_str());
			}
		}
		return NULL;
	}
#endif
}

// Load the configuration
bool SimpleConfigLoader::loadConfiguration()
{
	char* configPath = getConfigPath();
	if (configPath == NULL)
	{
		ERROR_MSG("Could not determine or create the per-user SoftHSM configuration path");
		return false;
	}
	const std::string configDirectory = parentDirectory(configPath);

	FILE* fp = fopen(configPath,"r");

	if (fp == NULL)
	{
		ERROR_MSG("Could not open the config file: %s", configPath);
		free(configPath);
		return false;
	}
	free(configPath);

	char fileBuf[1024];

	// Format in config file
	//
	// <name> = <value>
	// # Line is ignored

	size_t line = 0;
	while (fgets(fileBuf, sizeof(fileBuf), fp) != NULL)
	{
		line++;

		// End the string at the first comment or newline
		fileBuf[strcspn(fileBuf, "#\n\r")] = '\0';

		// Skip empty lines
		if (fileBuf[0] == '\0')
		{
			continue;
		}

		// Get the first part of the line
		char* name = strtok(fileBuf, "=");
		if (name == NULL)
		{
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			continue;
		}

		// Trim the name
		char* trimmedName = trimString(name);
		if (trimmedName == NULL)
		{
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			continue;
		}

		// Get the second part of the line
		char* value = strtok(NULL, "=");
		if(value == NULL) {
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			free(trimmedName);
			continue;
		}

		// Trim the value
		char* trimmedValue = trimString(value);
		if (trimmedValue == NULL)
		{
			WARNING_MSG("Bad format on line %lu, skip", (unsigned long)line);
			free(trimmedName);
			continue;
		}

		// Save name,value
		std::string stringName(trimmedName);
		std::string stringValue(trimmedValue);
		free(trimmedName);
		free(trimmedValue);

		switch (Configuration::i()->getType(stringName))
		{
			case CONFIG_TYPE_STRING:
				if (stringName == "directories.tokendir" && !isAbsolutePath(stringValue))
				{
					stringValue = joinPath(configDirectory, stringValue);
				}
				Configuration::i()->setString(stringName, stringValue);
				break;
			case CONFIG_TYPE_INT:
				Configuration::i()->setInt(stringName, atoi(stringValue.c_str()));
				break;
			case CONFIG_TYPE_INT_OCTAL:
				Configuration::i()->setInt(stringName, strtol(stringValue.c_str(), NULL, 8));
				break;
			case CONFIG_TYPE_BOOL:
				bool boolValue;
				if (string2bool(stringValue, &boolValue))
				{
					Configuration::i()->setBool(stringName, boolValue);
				}
				else
				{
					WARNING_MSG("The value %s is not a boolean", stringValue.c_str());
				}
				break;
			case CONFIG_TYPE_UNSUPPORTED:
			default:
				WARNING_MSG("The following configuration is not supported: %s = %s",
					stringName.c_str(), stringValue.c_str());
				break;
		}
	}

	fclose(fp);

	return true;
}

// Get the boolean value from a string
bool SimpleConfigLoader::string2bool(std::string stringValue, bool* boolValue)
{
	// Convert to lowercase
	std::transform(stringValue.begin(), stringValue.end(), stringValue.begin(), tolower);

	if (stringValue.compare("true") == 0)
	{
		*boolValue = true;
		return true;
	}

	if (stringValue.compare("false") == 0)
	{
		*boolValue = false;
		return true;
	}

	return false;
}

/* Returns a user-specific path for configuration.
 */
static char *get_user_path(void)
{
#ifdef _WIN32
	char path[512];
	const char *user_profile = getenv("USERPROFILE");
	const char *home_drive = getenv("HOMEDRIVE");
	const char *home_path = getenv("HOMEPATH");

	if (user_profile && user_profile[0] != 0) {
# ifdef SOFTHSM2_PORTABLE_USER_CONFIG
		snprintf(path, sizeof(path), "%s\\" CONFIG_DIRECTORY "\\%s", user_profile, USER_CONFIG_FILE);
# else
		snprintf(path, sizeof(path), "%s\\%s", user_profile, USER_CONFIG_FILE);
# endif
		return strdup(path);
	}

	if (home_drive && home_path) {
# ifdef SOFTHSM2_PORTABLE_USER_CONFIG
		snprintf(path, sizeof(path), "%s%s\\" CONFIG_DIRECTORY "\\%s", home_drive, home_path, USER_CONFIG_FILE);
# else
		snprintf(path, sizeof(path), "%s%s\\%s", home_drive, home_path, USER_CONFIG_FILE);
# endif
		return strdup(path);
	}
	return NULL;
#else
	char path[_POSIX_PATH_MAX];
	const char *home_dir = getenv("HOME");

	if (home_dir != NULL && home_dir[0] != 0) {
		snprintf(path, sizeof(path), "%s/" CONFIG_DIRECTORY "/" USER_CONFIG_FILE, home_dir);
		return strdup(path);
	}

# if defined(HAVE_GETPWUID_R)
	if (home_dir == NULL || home_dir[0] == '\0') {
		struct passwd *pwd;
		struct passwd _pwd;
		int ret;
		char tmp[512];

		ret = getpwuid_r(getuid(), &_pwd, tmp, sizeof(tmp), &pwd);
		if (ret == 0 && pwd != NULL) {
			snprintf(path, sizeof(path), "%s/" CONFIG_DIRECTORY "/" USER_CONFIG_FILE, pwd->pw_dir);
			return strdup(path);
		}
	}
# endif
#endif

	return NULL;
}

#ifndef SOFTHSM2_PORTABLE_USER_CONFIG
static char *get_env_var_path(void)
{
#ifdef _WIN32

	LPSTR value = NULL;
	DWORD size = 0;

	size = GetEnvironmentVariableA("SOFTHSM2_CONF", value, size);
	if (size == 0) {
		return NULL;
	}

	value = (LPSTR) malloc(size);
	if (NULL == value) {
		return NULL;
	}

	if (GetEnvironmentVariableA("SOFTHSM2_CONF", value, size) != (size - 1)) {
		free(value);
		return NULL;
	}

	return value;

#else

	char *value = getenv("SOFTHSM2_CONF");

	if (value == NULL) {
		return value;
	} else {
		return strdup(value);
	}

#endif
}
#endif

char* SimpleConfigLoader::getConfigPath()
{
#ifdef SOFTHSM2_PORTABLE_USER_CONFIG
	char* userPath = get_user_path();
	if (userPath == NULL)
	{
		return NULL;
	}
	if (!isReadableFile(userPath) && !materializeUserConfig(std::string(userPath), NULL))
	{
		free(userPath);
		return NULL;
	}
	return userPath;
#else
	char* configPath = get_env_var_path();

	if (configPath != NULL)
	{
		return configPath;
	}

	char* userPath = get_user_path();
	if (userPath != NULL && isReadableFile(userPath))
	{
		return userPath;
	}

	char* portablePath = getPortableConfigPath();
	if (userPath != NULL && materializeUserConfig(std::string(userPath), portablePath))
	{
		free(portablePath);
		return userPath;
	}

	free(userPath);
	if (portablePath != NULL)
	{
		return portablePath;
	}
	return strdup(DEFAULT_SOFTHSM2_CONF);
#endif
}

char* SimpleConfigLoader::trimString(char* text)
{
	if (text == NULL)
	{
		return NULL;
	}

	int startPos = 0;
	int endPos = strlen(text) - 1;

	// Find the first position without a space
	while (startPos <= endPos && isspace((int)*(text + startPos)))
	{
		startPos++;
	}
	// Find the last position without a space
	while (startPos <= endPos && isspace((int)*(text + endPos)))
	{
		endPos--;
	}

	// We must have a valid string
	int length = endPos - startPos + 1;
	if (length <= 0)
	{
		return NULL;
	}

	// Create the trimmed text
	char* trimmedText = (char*)malloc(length + 1);
	if (trimmedText == NULL)
	{
		return NULL;
	}
	trimmedText[length] = '\0';
	memcpy(trimmedText, text + startPos, length);

	return trimmedText;
}
