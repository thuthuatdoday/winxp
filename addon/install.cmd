@echo off
cls

rem Update Root Cert
WindowsUpdateAgent.exe /wuforce /quiet /norestart
rootsupd.exe /Q
rvkroots.exe /Q

rem Update Hotfix
KB932716.exe /quiet /norestart /nobackup
KB942288.exe /quiet /norestart /nobackup
KB943729.exe /quiet /norestart /nobackup
KB952287.exe /quiet /norestart /nobackup
KB953839.exe /quiet /norestart /nobackup
KB956391.exe /quiet /norestart /nobackup
KB969084.exe /quiet /norestart /nobackup
KB973525.exe /quiet /norestart /nobackup
KB978262.exe /quiet /norestart /nobackup
KB982316.exe /quiet /norestart /nobackup
KB2419632.exe /quiet /norestart /nobackup
KB2660649.exe /quiet /norestart /nobackup
KB2686509.exe /quiet /norestart /nobackup
KB2698365.exe /quiet /norestart /nobackup
KB2813347.exe /quiet /norestart /nobackup
KB2835364.exe /quiet /norestart /nobackup
KB2900986.exe /quiet /norestart /nobackup
reg add "HKLM\SYSTEM\WPA\POSReady" /v Installed /t REG_DWORD /d 1 /f 1>nul 2>nul
KB4034044.exe /quiet /norestart /nobackup
reg delete "HKLM\SYSTEM\WPA\POSReady" /f 1>nul 2>nul

rem Enable CredSSP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" /t REG_MULTI_SZ /d "tspkg\0kerberos\0msv1_0\0schannel\0wdigest" /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders" /v SecurityProviders /t REG_SZ /d "credssp.dll, msapsspc.dll, schannel.dll, digest.dll, msnsspc.dll" /f 1>nul 2>nul

rem Disable SSLv2
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f 1>nul 2>nul

rem Disable SSLv3
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /v DisabledByDefault /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /v DisabledByDefault /t REG_DWORD /d 1 /f 1>nul 2>nul

rem Enable TLSv1.0
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v Enabled /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v Enabled /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f 1>nul 2>nul

rem Enable TLSv1.1
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v Enabled /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v Enabled /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f 1>nul 2>nul

rem Enable TLSv1.2
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v Enabled /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" /v DisabledByDefault /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v Enabled /t REG_DWORD /d 1 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" /v DisabledByDefault /t REG_DWORD /d 0 /f 1>nul 2>nul

rem Disable DES
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul

rem Disable RC4
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /v Enabled /t REG_DWORD /d 0 /f 1>nul 2>nul

rem Enable DefaultSecureProtocols (TLSv1.0 TLSv1.1 TLSv1.2)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v DefaultSecureProtocols /t REG_DWORD /d 2688 /f 1>nul 2>nul

rem Show TextBox TLSv1.1 - TLSv1.2
reg delete "HKLM\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CRYPTO\TLS1.1" /v OSVersion /f 1>nul 2>nul
reg delete "HKLM\SOFTWARE\Microsoft\Internet Explorer\AdvancedOptions\CRYPTO\TLS1.2" /v OSVersion /f 1>nul 2>nul

rem Remove Compress Old Files
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Compress old files" /f 1>nul 2>nul

rem Remove More Theme Online
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\DownloadSites" /f 1>nul 2>nul

rem Remove Start Menu Internet Explorer Click-Right Content Menu naom 
reg delete "HKLM\SOFTWARE\Clients\StartMenuInternet\IEXPLORE.EXE\shell\naom" /f 1>nul 2>nul

rem Sync Hotfix
qchain.exe
