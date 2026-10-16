@echo off
rem Initialize the installed VS 2022 C++ toolchain. VSCDEV_BAT overrides discovery.
setlocal
if not "%VSCDEV_BAT%"=="" goto ready
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo Visual Studio Installer vswhere.exe not found. Set VSCDEV_BAT.
  exit /b 1
)
for /f "delims=" %%i in ('call "%VSWHERE%" -latest -products * -version "[17.0,18.0)" -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do set "VSCDEV_BAT=%%i\Common7\Tools\VsDevCmd.bat"
:ready
if not exist "%VSCDEV_BAT%" (
  echo VS 2022 C++ tools missing. Install Desktop development with C++.
  exit /b 1
)
call "%VSCDEV_BAT%" -arch=x64 || exit /b 1
set "CMAKE_GENERATOR=Visual Studio 17 2022"
set "CMAKE_GENERATOR_PLATFORM=x64"
%*
