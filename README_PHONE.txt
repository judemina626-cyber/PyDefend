PYDEFEND - PHONE DEBUG GUIDE

1. On the laptop, run START_PYDEFEND.bat.
2. If Windows Firewall asks, allow Python on your PRIVATE network.
3. Run SHOW_LAPTOP_IP.bat and note the Wi-Fi IPv4 address, e.g. 192.168.1.10.
4. Connect the phone and laptop to the SAME Wi-Fi.
5. On the phone open: http://192.168.1.10:5000
6. If the phone cannot connect, run ALLOW_PYDEFEND_FIREWALL.bat as Administrator and try again.
7. Picture Scan has a mobile camera-picker fallback. If browser camera preview is blocked on HTTP, the phone camera picker can still open.

Do not use 127.0.0.1 on the phone. That address points back to the phone itself.

The project is an educational prototype and uses safe simulated threat markers; it is not a real antivirus.
