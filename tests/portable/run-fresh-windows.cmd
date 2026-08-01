@echo off
setlocal

if not defined PORTABLE_ARCH (
  echo PORTABLE_ARCH is required 1>&2
  exit /b 2
)

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo vswhere.exe was not found 1>&2
  exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -property installationPath`) do set "VSINSTALL=%%i"
if not defined VSINSTALL (
  echo Visual Studio was not found 1>&2
  exit /b 1
)

if /i "%PORTABLE_ARCH%"=="arm64" (
  set "VCVARS_ARCH=arm64"
) else (
  set "VCVARS_ARCH=amd64"
)
call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" %VCVARS_ARCH%
if errorlevel 1 exit /b %errorlevel%

for /f "delims=" %%i in ('where openssl.exe 2^>nul') do if not defined OPENSSL_EXE set "OPENSSL_EXE=%%i"
if not defined OPENSSL_EXE if exist "C:\Program Files\OpenSSL\bin\openssl.exe" set "OPENSSL_EXE=C:\Program Files\OpenSSL\bin\openssl.exe"
if not defined OPENSSL_EXE if exist "C:\Program Files\OpenSSL-Win64\bin\openssl.exe" set "OPENSSL_EXE=C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
if not defined OPENSSL_EXE (
  echo openssl.exe was not found 1>&2
  exit /b 1
)

powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-fresh-integration.ps1" "%~1" softhsm2.dll "%OPENSSL_EXE%"
exit /b %errorlevel%
