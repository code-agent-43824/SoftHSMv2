@echo off
setlocal
powershell -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0run-test.ps1" %*
exit /b %errorlevel%
