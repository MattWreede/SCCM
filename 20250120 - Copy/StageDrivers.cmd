
@ECHO OFF & CLS
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: SysNative Redirect
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:: Purpose: SysNative is a virtual folder visible to 32-Bit applications but not
:: visible to 64-Bit applications. This script uses SysNative to redirect scripts 
:: to use native executables on when run on a 64-Bit Operating System.
:: Version: 2.1
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

REM OS Run architecture check and redirect if needed:
If "%PROCESSOR_ARCHITEW6432%"=="" (GOTO :_STANDARD) ELSE (GOTO :_SYSNATIVE)

:_STANDARD
powershell.exe -executionpolicy bypass -Command "& { & '.\Deploy-Application-StageDrivers.ps1' -DeploymentType 'Install' -DeployMode 'Silent'; Exit $LastExitCode }"
GOTO :_END

:_SYSNATIVE
%WINDIR%\sysnative\WindowsPowerShell\v1.0\powershell.exe -executionpolicy bypass -Command "& { & '.\Deploy-Application-StageDrivers.ps1' -DeploymentType 'Install' -DeployMode 'Silent'; Exit $LastExitCode }"
GOTO :_END

:_END
EXIT




