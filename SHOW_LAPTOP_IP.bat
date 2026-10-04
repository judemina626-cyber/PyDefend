@echo off
ipconfig | findstr /R /C:"IPv4 Address" /C:"IPv4"
echo.
echo Use the IPv4 address of the Wi-Fi adapter, for example:
echo http://192.168.1.10:5000
pause
