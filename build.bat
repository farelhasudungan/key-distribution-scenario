@echo off
REM Build untuk Windows (MinGW/winlibs GCC dengan POSIX threads)
g++ -std=c++11 -O2 -Wall -Wextra -o kdc.exe kdc.cpp -lws2_32
if errorlevel 1 exit /b 1
g++ -std=c++11 -O2 -Wall -Wextra -o peer.exe peer.cpp -lws2_32
if errorlevel 1 exit /b 1
echo Build selesai: kdc.exe dan peer.exe
