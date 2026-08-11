@echo off
setlocal

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

if /i "%PORTABLE_ARCH%"=="x86" (
  set "VCVARS_ARCH=x86"
) else if /i "%PORTABLE_ARCH%"=="x64" (
  set "VCVARS_ARCH=amd64"
) else if /i "%PORTABLE_ARCH%"=="arm64" (
  set "VCVARS_ARCH=arm64"
) else (
  echo unsupported PORTABLE_ARCH: %PORTABLE_ARCH% 1>&2
  exit /b 2
)

call "%VSINSTALL%\VC\Auxiliary\Build\vcvarsall.bat" %VCVARS_ARCH%
if errorlevel 1 exit /b %errorlevel%

powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0build-windows.ps1"
exit /b %errorlevel%
