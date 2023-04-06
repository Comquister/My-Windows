@echo off
REM Desativar Windows Defender

REM Desativar Windows Defender usando o regedit
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBlockAtFirstSeen /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center" /v AntiVirusDisableNotify /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Security Center" /v FirewallDisableNotify /t REG_DWORD /d 1 /f

REM Desativar Windows Defender usando o PowerShell
powershell -c "Set-MpPreference -DisableRealtimeMonitoring $true"
powershell -c "Set-MpPreference -DisableBehaviorMonitoring $true"
powershell -c "Set-MpPreference -DisableBlockAtFirstSeen $true"
powershell -c "Set-MpPreference -DisableIOAVProtection $true"
powershell -c "Set-MpPreference -DisablePrivacyMode $true"
powershell -c "Set-MpPreference -PUAProtection 0"
powershell -c "Set-MpPreference -SubmitSamplesConsent NeverSend"
powershell -c "Set-MpPreference -MAPSReporting 0"
powershell -c "Set-MpPreference -DisableArchiveScanning $true"
powershell -c "Set-MpPreference -DisableIntrusionPreventionSystem $true"
