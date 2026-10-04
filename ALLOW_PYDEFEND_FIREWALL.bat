@echo off
netsh advfirewall firewall add rule name="PyDefend Flask 5000" dir=in action=allow protocol=TCP localport=5000
if errorlevel 1 echo Run this file as Administrator if Windows blocks the firewall rule.
echo Firewall rule attempted for TCP port 5000.
pause
