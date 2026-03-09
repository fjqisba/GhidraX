@echo off
setlocal enabledelayedexpansion

:: ============================================================
::  Build sleigh_native.pyd -- One-Click Build Script
:: ============================================================
::
::  Prerequisites:
::    1. Visual Studio 2022 (Community/Professional/Enterprise)
::    2. CMake  (>= 3.15)  in PATH  or  set CMAKE=<path>
::    3. Ninja  in PATH  or  set NINJA=<path>
::    4. Python with pybind11:  pip install pybind11
::    5. zlib via vcpkg:        vcpkg install zlib:x64-windows-static
::       OR set ZLIB_ROOT=<prefix>
::
::  Optional overrides (environment variables):
::    PYTHON_EXE        Path to python.exe
::    PYBIND11_DIR      pybind11 CMake config directory
::    VCPKG_ROOT        vcpkg installation root
::    ZLIB_ROOT         zlib prefix (include/ + lib/)
::    VS_YEAR           Visual Studio year (default: 2022)
::    VS_EDITION        Visual Studio edition (default: auto-detect)
::
:: ============================================================

set "SCRIPT_DIR=%~dp0"

echo.
echo ========================================
echo   sleigh_native.pyd Builder
echo ========================================
echo.

:: ---- Step 1: Find MSVC ----
where cl.exe >nul 2>&1
if not errorlevel 1 goto :msvc_ok

echo [1/5] Setting up MSVC environment...
set "VS_YEAR_=%VS_YEAR%"
if "%VS_YEAR_%"=="" set "VS_YEAR_=2022"

:: Auto-detect VS edition
set "_VCVARS="
for %%E in (Community Professional Enterprise BuildTools) do (
    if exist "C:\Program Files\Microsoft Visual Studio\%VS_YEAR_%\%%E\VC\Auxiliary\Build\vcvars64.bat" (
        set "_VCVARS=C:\Program Files\Microsoft Visual Studio\%VS_YEAR_%\%%E\VC\Auxiliary\Build\vcvars64.bat"
        goto :found_vs
    )
)
if exist "C:\Program Files (x86)\Microsoft Visual Studio\%VS_YEAR_%\BuildTools\VC\Auxiliary\Build\ .bat" (
    set "_VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\%VS_YEAR_%\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
    goto :found_vs
)
echo [ERROR] Cannot find Visual Studio %VS_YEAR_%. Install VS or run from Developer Command Prompt.
goto :fail

:found_vs
echo        Using: !_VCVARS!
call "!_VCVARS!" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] vcvars64.bat failed.
    goto :fail
)

:msvc_ok
echo [1/5] MSVC ... OK

:: ---- Step 2: Find CMake ----
where cmake.exe >nul 2>&1
if not errorlevel 1 goto :cmake_ok
if defined CMAKE (
    set "PATH=%CMAKE%;%PATH%"
    goto :cmake_ok
)
echo [ERROR] cmake not found. Install CMake and add to PATH.
goto :fail
:cmake_ok
echo [2/5] CMake ... OK

:: ---- Step 3: Find Ninja ----
where ninja.exe >nul 2>&1
if not errorlevel 1 goto :ninja_ok
if defined NINJA (
    set "PATH=%NINJA%;%PATH%"
    goto :ninja_ok
)
:: Try common locations
for %%P in (
    "%LOCALAPPDATA%\Microsoft\WinGet\Packages"
    "C:\Tools\ninja"
    "D:\App\ninja"
) do (
    if exist "%%~P\ninja.exe" (
        set "PATH=%%~P;%PATH%"
        goto :ninja_ok
    )
)
echo [WARN] Ninja not found, falling back to NMake.
set "GENERATOR=NMake Makefiles"
set "BUILD_CMD=nmake"
goto :generator_set
:ninja_ok
set "GENERATOR=Ninja"
set "BUILD_CMD=ninja -j%NUMBER_OF_PROCESSORS%"
echo [3/5] Ninja ... OK
:generator_set

:: ---- Step 4: Find Python + pybind11 ----
set "_PYTHON="
if defined PYTHON_EXE (
    set "_PYTHON=%PYTHON_EXE%"
) else (
    :: Find python but skip WindowsApps stub
    for /f "delims=" %%i in ('where python.exe 2^>nul') do (
        echo %%i | findstr /i "WindowsApps" >nul
        if errorlevel 1 (
            if "!_PYTHON!"=="" set "_PYTHON=%%i"
        )
    )
)
:: Try common locations if not found
if "!_PYTHON!"=="" (
    for %%P in (
        "D:\MyLib\Python314\python.exe"
        "C:\Python314\python.exe"
        "C:\Python313\python.exe"
        "C:\Python312\python.exe"
        "C:\Python311\python.exe"
        "C:\Python310\python.exe"
    ) do (
        if exist "%%~P" (
            if "!_PYTHON!"=="" set "_PYTHON=%%~P"
        )
    )
)
if "!_PYTHON!"=="" (
    echo [ERROR] Python not found. Set PYTHON_EXE or add python to PATH.
    goto :fail
)
echo [4/5] Python ... !_PYTHON!

:: Resolve pybind11 cmake dir
set "_PYBIND11_DIR="
if defined PYBIND11_DIR (
    set "_PYBIND11_DIR=%PYBIND11_DIR%"
) else (
    :: Write a helper script to avoid batch quoting hell
    > "%TEMP%\_pb11.py" echo import pybind11; print(pybind11.get_cmake_dir())
    > "%TEMP%\_pb11.txt" "!_PYTHON!" "%TEMP%\_pb11.py" 2>nul
    set /p _PYBIND11_DIR=<"%TEMP%\_pb11.txt"
    del "%TEMP%\_pb11.py" 2>nul
    del "%TEMP%\_pb11.txt" 2>nul
)
if "!_PYBIND11_DIR!"=="" (
    echo [ERROR] pybind11 not found. Run: "!_PYTHON!" -m pip install pybind11
    goto :fail
)
echo        pybind11: !_PYBIND11_DIR!

:: ---- Step 5: Find zlib ----
set "_CMAKE_EXTRA="
if defined ZLIB_ROOT (
    set "_CMAKE_EXTRA=-DZLIB_ROOT=%ZLIB_ROOT%"
    echo [5/5] zlib ... %ZLIB_ROOT%
) else if defined VCPKG_ROOT (
    set "_CMAKE_EXTRA=-DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%\scripts\buildsystems\vcpkg.cmake -DVCPKG_TARGET_TRIPLET=x64-windows-static"
    echo [5/5] zlib ... via vcpkg
) else (
    :: Try common vcpkg locations
    for %%V in (
        "D:\App\vcpkg"
        "C:\vcpkg"
        "%USERPROFILE%\vcpkg"
    ) do (
        if exist "%%~V\installed\x64-windows-static\lib\zlib.lib" (
            set "_CMAKE_EXTRA=-DZLIB_ROOT=%%~V\installed\x64-windows-static"
            echo [5/5] zlib ... %%~V (auto-detected)
            goto :zlib_ok
        )
    )
    echo [WARN] zlib not auto-detected. CMake will try system search.
)
:zlib_ok

:: ---- Configure ----
echo.
echo ---- Configuring ----
set "BUILD_DIR=%SCRIPT_DIR%build"
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

cmake -S "%SCRIPT_DIR%." -B "%BUILD_DIR%" -G "%GENERATOR%" ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DPython_EXECUTABLE="!_PYTHON!" ^
    -Dpybind11_DIR="!_PYBIND11_DIR!" ^
    !_CMAKE_EXTRA!

if errorlevel 1 (
    echo.
    echo [ERROR] CMake configure failed.
    goto :fail
)

:: ---- Build ----
echo.
echo ---- Building ----
cmake --build "%BUILD_DIR%" --config Release -- %BUILD_CMD_ARGS%
if errorlevel 1 (
    echo.
    echo [ERROR] Build failed.
    goto :fail
)

:: ---- Copy output ----
echo.
echo ---- Copying sleigh_native to python package ----
set "DST=%SCRIPT_DIR%..\python\ghidra\sleigh"
copy /Y "%BUILD_DIR%\sleigh_native*.pyd" "%DST%\" 2>nul
copy /Y "%BUILD_DIR%\sleigh_native*.so"  "%DST%\" 2>nul
copy /Y "%BUILD_DIR%\Release\sleigh_native*.pyd" "%DST%\" 2>nul

echo.
echo ========================================
echo   BUILD SUCCEEDED
echo ========================================
echo   Output: %DST%\sleigh_native*.pyd
echo ========================================
echo.
goto :done

:fail
echo.
echo ========================================
echo   BUILD FAILED -- see errors above
echo ========================================
echo.
pause
exit /b 1

:done
pause
exit /b 0
