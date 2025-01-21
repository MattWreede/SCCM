<#
.SYNOPSIS
	This script performs the installation or uninstallation of an application(s).
.DESCRIPTION
	The script is provided as a template to perform an install or uninstall of an application(s).
	The script either performs an "Install" deployment type or an "Uninstall" deployment type.
	The install deployment type is broken down into 3 main sections/phases: Pre-Install, Install, and Post-Install.
	The script dot-sources the AppDeployToolkitMain.ps1 script which contains the logic and functions required to install or uninstall an application.
.PARAMETER DeploymentType
	The type of deployment to perform. Default is: Install.
.PARAMETER DeployMode
	Specifies whether the installation should be run in Interactive, Silent, or NonInteractive mode. Default is: Interactive. Options: Interactive = Shows dialogs, Silent = No dialogs, NonInteractive = Very silent, i.e. no blocking apps. NonInteractive mode is automatically set if it is detected that the process is not user interactive.
.PARAMETER AllowRebootPassThru
	Allows the 3010 return code (requires restart) to be passed back to the parent process (e.g. SCCM) if detected from an installation. If 3010 is passed back to SCCM, a reboot prompt will be triggered.
.PARAMETER TerminalServerMode
	Changes to "user install mode" and back to "user execute mode" for installing/uninstalling applications for Remote Destkop Session Hosts/Citrix servers.
.PARAMETER DisableLogging
	Disables logging to file for the script. Default is: $false.
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeployMode 'Silent'; Exit $LastExitCode }"
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -AllowRebootPassThru; Exit $LastExitCode }"
.EXAMPLE
    powershell.exe -Command "& { & '.\Deploy-Application.ps1' -DeploymentType 'Uninstall'; Exit $LastExitCode }"
.EXAMPLE
    Deploy-Application.exe -DeploymentType "Install" -DeployMode "Silent"
.NOTES
	Toolkit Exit Code Ranges:
	60000 - 68999: Reserved for built-in exit codes in Deploy-Application.ps1, Deploy-Application.exe, and AppDeployToolkitMain.ps1
	69000 - 69999: Recommended for user customized exit codes in Deploy-Application.ps1
	70000 - 79999: Recommended for user customized exit codes in AppDeployToolkitExtensions.ps1
.LINK 
	http://psappdeploytoolkit.com
#>
[CmdletBinding()]
Param (
	[Parameter(Mandatory=$false)]
	[ValidateSet('Install','Uninstall')]
	[string]$DeploymentType = 'Install',
	[Parameter(Mandatory=$false)]
	[ValidateSet('Interactive','Silent','NonInteractive')]
	[string]$DeployMode = 'Interactive',
	[Parameter(Mandatory=$false)]
	[switch]$AllowRebootPassThru = $false,
	[Parameter(Mandatory=$false)]
	[switch]$TerminalServerMode = $false,
	[Parameter(Mandatory=$false)]
	[switch]$DisableLogging = $false,
    
    #CUSTOM Parameter - update BIOS settings
    [Parameter(Mandatory=$false)]
    [switch] $updateSetting = $false

)

Try {
	## Set the script execution policy for this process
	Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}
	
    ## Variables: Environment
	If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
	[string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent

	## Dot source some custom Functions
	Try {		
		[string]$module = "$scriptDirectory\SupportFiles\CustomFunctions.ps1"
		If (-not (Test-Path -LiteralPath $module -PathType 'Leaf')) { Throw "Module does not exist at the specified location [$module]." }
        . $module
	}
	Catch {
		If ($mainExitCode -eq 0){ [int32]$mainExitCode = 60008 }
		Write-Error -Message "Module [$module] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
		## Exit the script, returning the exit code to SCCM
		If (Test-Path -LiteralPath 'variable:HostInvocation') { $script:ExitCode = $mainExitCode; Exit } Else { Exit $mainExitCode }
	}

    # Load package specific variables - so we don't have to update this file each time we have a new package - just update the xml
    LoadConfig -path "$scriptDirectory\config.xml"

	##*===============================================
	##* VARIABLE DECLARATION
	##*===============================================
	## Variables: Application

    [string]$appVersion	= $appSettings['Version'].Split('.') # info comes out of config.xml
    [string]$appName    = "Driver Update for $($appSettings['Manufacturer']) $($appSettings['Model'])"# info comes out of config.xml
    [string]$appVendor  = $appSettings['Manufacturer']# info comes out of config.xml
    [boolean]$rebootRequired = $false
    If($appSettings['RebootRequired']) {
        [Boolean]::TryParse($appSettings['RebootRequired'], [ref]$rebootRequired) | Out-Null
    }
    $IgnoreVersionRestriction = $false
    If($appSettings['IgnoreVersionRestriction']) {
        [Boolean]::TryParse($appSettings['IgnoreVersionRestriction'], [ref]$IgnoreVersionRestriction) | Out-Null
    }


   
	[string]$appArch = $($appSettings['ProcArchitecture'])
	[string]$appLang = 'EN'
	[string]$appRevision = '01'
	[string]$appScriptVersion = '1.0.0'
	[string]$appScriptDate = '<insert date here>'
	[string]$appScriptAuthor = '<insert your name here>'
    [string]$biosPassword = ''
	##*===============================================
	## Variables: Install Titles (Only set here to override defaults set by the toolkit)
	[string]$installName = ''
	[string]$installTitle = ''
	
	##* Do not modify section below
	#region DoNotModify
	
	## Variables: Exit Code
	[int32]$mainExitCode = 0
	
	## Variables: Script
	[string]$deployAppScriptFriendlyName = 'Deploy Application'
	[version]$deployAppScriptVersion = [version]'3.6.9'
	[string]$deployAppScriptDate = '02/12/2017'
	[hashtable]$deployAppScriptParameters = $psBoundParameters
	
	
	
	## Dot source the required App Deploy Toolkit Functions
	Try {
		[string]$moduleAppDeployToolkitMain = "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
		If (-not (Test-Path -LiteralPath $moduleAppDeployToolkitMain -PathType 'Leaf')) { Throw "Module does not exist at the specified location [$moduleAppDeployToolkitMain]." }
		If ($DisableLogging) { . $moduleAppDeployToolkitMain -DisableLogging } Else { . $moduleAppDeployToolkitMain }
	}
	Catch {
		If ($mainExitCode -eq 0){ [int32]$mainExitCode = 60008 }
		Write-Error -Message "Module [$moduleAppDeployToolkitMain] failed to load: `n$($_.Exception.Message)`n `n$($_.InvocationInfo.PositionMessage)" -ErrorAction 'Continue'
		## Exit the script, returning the exit code to SCCM
		If (Test-Path -LiteralPath 'variable:HostInvocation') { $script:ExitCode = $mainExitCode; Exit } Else { Exit $mainExitCode }
	}
	
	#endregion
	##* Do not modify section above
	##*===============================================
	##* END VARIABLE DECLARATION
	##*===============================================
		
	If ($deploymentType -ine 'Uninstall') {
        
		##*===============================================
		##* PRE-INSTALLATION
		##*===============================================
		[string]$installPhase = 'Pre-Installation'
		
        $buttonOKText = 'OK'
        $buttonCancelText = 'Cancel'
        $message = "Updating device drivers to latest version. This process can last up to 10 minutes. Please confirm to continue."
        
        #Show-InstallationWelcome -DeferTimes 3 -AllowDefer -RequiredDiskSpace 2000 -CheckDiskSpace -ForceCountdown 6600 # 1 hours 50 minutes

        ## Show Progress Message (with the default message)
		Show-InstallationProgress
		
		## <Perform Pre-Installation tasks here>

        #  ******  Get Pending Rename from registry  ******
        If (Test-RegistryValue -Key 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Value PendingFileRenameOperations)
        {
            #  ******  Registry key exists, grab value  ******
            Write-Log -Message "Pending File Rename Operations exists, retrieving and deleting." -Source 'Test-RegistryValue'
            $PendingRename = Get-RegistryKey -Key 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Value PendingFileRenameOperations
            Write-Log -Message "Captured PendingFileRenameOperations value, deleting..." -Source 'Get-RegistryKey'
            Remove-RegistryKey -Key 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations
            Write-Log -Message "Deleted PendingFileRenameOperations value." -Source 'Remove-RegistryKey'
        } Else
        {
            #  ******  Registry key does not exist, mark  ******
            Write-Log -Message "PendingFileRenameOperations value does not exist." -Source 'Test-RegistryKey'
            $PendingRename = "n/a"
		}
		
		
		$TSManager = Get-Process tsmanager -ErrorAction SilentlyContinue
		if ($TSManager -eq $null)
		{
			Write-Log -Message "I am not in a TS"
			$InTS = "False"
		}
		else
		{
			Write-Log -Message "I am in a TS"
			$InTS = "True"
		}
		
		## Disable Bitlocker
		If(Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
			$bitlockerEncryption = $true
		}
		Else {
			$bitlockerEncryption = $false
		}

		## Handle Zero-Config MSI Installations
		If($bitlockerEncryption) {
			$Status = Get-BitLockerVolume | ? { $_.MountPoint -eq $env:SystemDrive }

			If($status) {
				$BitLockerOn = $Status.ProtectionStatus
				$savedBitlockerStatus = $Status.ProtectionStatus
			}
			else {
				# not needed
			}        
		}

		if($BitLockerOn -eq 'On')
		{
			Write-Log "Turning BitLocker Off!" -Source 'Pre-Installation'
			Suspend-BitLocker -MountPoint $env:SystemDrive -RebootCount 1
		}

        # Remove password from Dell BIOS 
        $unlockBios = $true
        $BIOS =  Get-WMIObject Win32_BIOS
        
        Switch($BIOS.Manufacturer) {
            'Dell Inc.' {
            }
        }
		
		if (Test-Path "c:\Program Files\DisplayLink Core Software")
		{
			Write-Log -Message "I have Displaylink. Setting Variable."
			$DisplayLink = "True"
		}
		
		if ($InTS -eq "False")
		{
			if (Test-Path "C:\temp\AlreadyDidINF.txt")
			{
				Remove-Item -Path "C:\temp\AlreadyDidINF.txt" -force -erroraction SilentlyContinue
			}
		}
		
		if (!(Test-Path "C:\Windows\Logs\Drivers"))
		{
			New-Folder -Path "C:\Windows\Logs\Drivers"
		}
		
		if (Test-Path "$dirfiles\pnp\d.zip")
		{
			
			if (!(Test-Path "C:\temp\AlreadyDidINF.txt"))
			{
				Write-log "Driver Zip found; extracting!"
				Expand-Archive -Path "$dirfiles\pnp\d.zip" -DestinationPath "$dirfiles\pnp" -Force -ErrorAction SilentlyContinue
				$DriverZip = "True"
			}
			else
			{
							Write-log "Driver Zip found; extracting!"
				Expand-Archive -Path "$dirfiles\pnp\d.zip" -DestinationPath "$dirfiles\pnp" -Force -ErrorAction SilentlyContinue
				$DriverZip = "True"
			}
			
		}
		
# Reg2CI (c) 2022 by Roger Zander
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters' -Name 'DeviceInstallDisabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

		
		
		##*===============================================
		##* INSTALLATION 
		##*===============================================
		[string]$installPhase = 'Installation'

        ##*===============================================
        ##* BIOS Installation
        ##*===============================================

        $BIOS =  Get-WMIObject Win32_BIOS
        
 

        ##*===============================================
        ##* Driver Installation
        ##*===============================================
        


        # Reg2CI (c) 2022 by Roger Zander
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters' -Name 'DeviceInstallDisabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

		
		if ($DriverZip -eq "True")
		{
			if (!(Test-Path "C:\Windows\Logs\Drivers\PNPInstall.log"))
			{
				New-Item -Path C:\Windows\Logs\Drivers\PNPInstall.log -ItemType File -ErrorAction SilentlyContinue
				sleep 1
			}
			Write-Log -Message "INF DRIVERS BEGIN since DRIVES DETECTED!"
			Get-ChildItem "$dirfiles\pnp" -Recurse -Filter "*inf" -ErrorAction SilentlyContinue | ForEach-Object { PNPUtil.exe /add-driver $_.FullName /install >> C:\Windows\Logs\Drivers\PNPInstall.log } -ErrorAction SilentlyContinue
			Write-Log -Message "INF DRIVERS END"
			New-Item -Path "C:\temp\AlreadyDidINF.txt" -ItemType file -Force -ErrorAction SilentlyContinue
			sleep 3
		}
		else
		{
			Write-Log -Message "No INF Drivers to install!"
		}
		
		if ($BIOS.Manufacturer -eq "Lenovo")
		{
			Write-log -message "I am a Lenovovovovovovo!"
			Write-Log -Message "Begin LSUpdate against repository"
			$updates = Get-LSUpdate -repository $dirfiles\p | Where-Object { $_.Installer.Unattended }
			Write-Log -Message "$($updates.Count) updates found"
			#Set-Variable -Name "RebootLenovo" -Scope Global -Value "False" -Force -ErrorAction SilentlyContinue
			$RebootNeeded = "False"
			$i = 1
			foreach ($update in $updates)
			{
				Write-Log -Message "Installing update $i of $($updates.Count): $($update.Title)"
				$result = Install-LSUpdate -Package $update -Verbose
				$i++
				switch ($result.PendingAction)
				{
					'REBOOT_MANDATORY' {
						$RebootNeeded = "True"
						Write-log -Message "$($update.Title) needs a reboot, MANDATORY"
						#Set-Variable -Name "RebootLenovo" -Scope Global -Value "True" -Force -ErrorAction SilentlyContinue
					}
					'SHUTDOWN' {
						$RebootNeeded = "True"
						Write-log -Message "$($update.Title) needs a reboot, SHUTDOWN"
						#	Set-Variable -Name "RebootLenovo" -Scope Global -Value "True" -Force -ErrorAction SilentlyContinue
						
					}
				}
			}
			
			If (-not [Int]::TryParse($response, [ref]$mainExitCode))
			{
				$mainExitCode = 0
			}
			else
			{
				$mainExitCode = $response
				
				# Set TS variable so TS can restart
				If ($response = 3010)
				{
					# Construct TSEnvironment object
					try
					{
						$TSEnvironment = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
						$TSEnvironment.Value('SMSTSRebootRequested') = $true
					}
					catch [System.Exception] {
						#Write-Warning -Message "Unable to construct Microsoft.SMS.TSEnvironment object"
					}
				}
			}
		}
		# Reg2CI (c) 2022 by Roger Zander
if((Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters") -ne $true) {  New-Item "HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters" -force -ea SilentlyContinue };
New-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\DeviceInstall\Parameters' -Name 'DeviceInstallDisabled' -Value 0 -PropertyType DWord -Force -ea SilentlyContinue;

		
		if ($BIOS.Manufacturer -eq "Dell Inc.")
		{
			Write-log -message "I am a Dell!"
			 $response = DriverUpdate -driverFolder "$scriptDirectory\Files\d" -PackageFolder "$scriptDirectory\Files\p" -logDir "$($env:SystemRoot)\Logs\Drivers" -dpinstBinary "$scriptDirectory\SupportFiles\Bin\Dpinst\x64\dpinst.exe" -ThinInstallerBinary $thinInstaller -ssmBinary "$scriptDirectory\SupportFiles\Bin\SSM\SSM.exe"
				#$response = DriverUpdate -PackageFolder "$scriptDirectory\Files\p" -logDir "$($env:SystemRoot)\Logs\Drivers" 
			If (-not [Int]::TryParse($response, [ref]$mainExitCode))
			{
				$mainExitCode = 0
			}
			else
			{
				$mainExitCode = $response
				
				# Set TS variable so TS can restart
				If ($response = 3010)
				{
					# Construct TSEnvironment object
					try
					{
						$TSEnvironment = New-Object -ComObject Microsoft.SMS.TSEnvironment -ErrorAction Stop
						$TSEnvironment.Value('SMSTSRebootRequested') = $true
					}
					catch [System.Exception] {
						#Write-Warning -Message "Unable to construct Microsoft.SMS.TSEnvironment object"
					}
				}
			}
		}
		
		
		# prep return code


        ##*===============================================
        ##* Unrestricted Lenovo package installer - ingore any of the restrictions put in the XML's by Lenovo 
        ##*===============================================
        ##
        ## could be usefull at some point - not used now

      
        Get-ChildItem -Path $dirfiles\s -File "Deploy-Application.exe" -Recurse | Foreach { Execute-Process -Path $_.FullName -IgnoreExitCodes '*' } -ErrorAction SilentlyContinue
        ####
        # End Unrestricted Lenovo package installer 
        ####
		
		
		if ($DriverZip -eq "True")
		{

			Write-Log "Done with special, purging zip files if they existed!"
			##ZIP CLEANUP https://superuser.com/questions/529771/delete-all-folders-and-files-except-for-specified-files
			Get-ChildItem -Path "$dirfiles\pnp" -File -Recurse | Where-Object { $_.Name -ne "d.zip" -and $_.Parent -notin ("folder1", "folder2") } | Remove-Item -Force -ErrorAction SilentlyContinue
			sleep 1
			
			Get-ChildItem -Path $dirfiles\pnp -Force -Recurse -Directory | Where-Object { (Get-ChildItem -Path $_.FullName -Recurse -File -EA SilentlyContinue | Measure-Object).Count -eq 0 } | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
		}
		
		##*===============================================
		##* POST-INSTALLATION
		##*===============================================
		[string]$installPhase = 'Post-Installation'

        # Add password from Dell BIOS 
        $unlockBios = $false
        $BIOS =  Get-WMIObject Win32_BIOS
		
		Switch ($BIOS.Manufacturer)
		{
			'Dell Inc.' {
				
				
				
				$InstallFolder = "C:\Windows\UpgradeDrivers"
				if (Test-Path $InstallFolder)
				{
					Write-Log -Message "Removing Staged Drivers!"
					Remove-Folder -Path $InstallFolder
				}
				
				Remove-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CompanyName AutoPilot Updates'
				
				
				[string]$installPhase = 'Post-Installation'
				$UninstallKeys = @{ } #Initialize the hash table, don't change
				
				$Uninstall_Key_Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CompanyName Dell Updates" #<- Required, change appropriately
				
				$UninstallKeys["UninstallString"] = "String", "c:\Windows\temp\BWC_TNSNames_Uninstall.bat" #<- Required, change appropriately
				$UninstallKeys["DisplayName"] = "String", "CompanyName Dell Updates" #<- Required, change appropriately
				$UninstallKeys["DisplayVersion"] = "String", "$appVersion" #<- Required, change appropriately
				
				$UninstallKeys["InstallDate"] = "String", [string]$(Get-Date -Format "yyyyMMdd") #<-- Don't change.
				$UninstallKeys["InstalledBy"] = "String", $env:USERNAME #<-- Don't change.
				
				$UninstallKeys["Publisher"] = "String", "Cardinal Health" #<-- Do modify if required
				#$UninstallKeys["DisplayIcon"] = "String","[path to EXE or ICO file]"              #<-- Do modify if required
				$UninstallKeys["NoRepair"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["NoModify"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["NoRemove"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["SystemComponent"] = "DWORD", 1 #<-- Modify if needed
				
				Foreach ($reg_value in $UninstallKeys.Keys)
				{
					Set-RegistryKey -Key "Registry::$Uninstall_Key_Path" -Name $reg_value -Type $UninstallKeys[$reg_value][0] -Value $UninstallKeys[$reg_value][1]
				}
				
				##AP ARP
				
				#[string]$installPhase = 'Post-Installation'
				#$UninstallKeys = @{ } #Initialize the hash table, don't change
				
	<#			$Uninstall_Key_Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CompanyName AutoPilot Updates" #<- Required, change appropriately
				
				$UninstallKeys["UninstallString"] = "String", "c:\Windows\temp\BWC_TNSNames_Uninstall.bat" #<- Required, change appropriately
				$UninstallKeys["DisplayName"] = "String", "CompanyName AutoPilot Updates" #<- Required, change appropriately
				$UninstallKeys["DisplayVersion"] = "String", "$appVersion" #<- Required, change appropriately
				
				$UninstallKeys["InstallDate"] = "String", [string]$(Get-Date -Format "yyyyMMdd") #<-- Don't change.
				$UninstallKeys["InstalledBy"] = "String", $env:USERNAME #<-- Don't change.
				
				$UninstallKeys["Publisher"] = "String", "Cardinal Health" #<-- Do modify if required
				#$UninstallKeys["DisplayIcon"] = "String","[path to EXE or ICO file]"              #<-- Do modify if required
				$UninstallKeys["NoRepair"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["NoModify"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["NoRemove"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["SystemComponent"] = "DWORD", 1 #<-- Modify if needed
				
				Foreach ($reg_value in $UninstallKeys.Keys)
				{
					Set-RegistryKey -Key "Registry::$Uninstall_Key_Path" -Name $reg_value -Type $UninstallKeys[$reg_value][0] -Value $UninstallKeys[$reg_value][1]
				}#>
				
				#Execute-process -path "$scriptDirectory\SupportFiles\CCTK\CCTK.exe" -Parameters @('-i', $dellConfig, '-l', "$env:SystemRoot\Logs\DellBiosSettings.log") -IgnoreExitCodes 65
				
				#If($LASTEXITCODE = 65) {
				#    Write-Log  "BIOS Password must be specified!"
				#    Execute-Process -path "$scriptDirectory\SupportFiles\CCTK\CCTK.exe" -SecureParameters @('-i', $dellConfig, "--ValSetupPwd=$biosPassword", '-l', "$env:SystemRoot\Logs\DellBiosSettings.log")
				#}
				# Unset BIOS Password
				#If($unlockBios) {
				#    Execute-Process -Path "$scriptDirectory\SupportFiles\CCTK\CCTK.exe" -SecureParameters @("--setuppwd=", "--ValSetupPwd=$biosPassword") 
				#}
				# Set BIOS passsord (assuming no password set)
				#else {
				##    Execute-Process -Path "$scriptDirectory\SupportFiles\CCTK\CCTK.exe" -SecureParameters @("--setuppwd=$biosPassword")
				#}
			}
			
			'Lenovo' {
				
				
				
				$InstallFolder = "C:\Windows\UpgradeDrivers"
				if (Test-Path $InstallFolder)
				{
					Write-Log -Message "Removing Staged Drivers!"
					Remove-Folder -Path $InstallFolder
				}
				
				Remove-RegistryKey -Key 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CompanyName AutoPilot Updates'
				
				
				[string]$installPhase = 'Post-Installation'
				$UninstallKeys = @{ } #Initialize the hash table, don't change
				
				$Uninstall_Key_Path = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\CompanyName Lenovo Updates" #<- Required, change appropriately
				
				$UninstallKeys["UninstallString"] = "String", "c:\Windows\temp\BWC_TNSNames_Uninstall.bat" #<- Required, change appropriately
				$UninstallKeys["DisplayName"] = "String", "CompanyName Lenovo Updates" #<- Required, change appropriately
				$UninstallKeys["DisplayVersion"] = "String", "$appVersion" #<- Required, change appropriately
				
				$UninstallKeys["InstallDate"] = "String", [string]$(Get-Date -Format "yyyyMMdd") #<-- Don't change.
				$UninstallKeys["InstalledBy"] = "String", $env:USERNAME #<-- Don't change.
				
				$UninstallKeys["Publisher"] = "String", "Cardinal Health" #<-- Do modify if required
				#$UninstallKeys["DisplayIcon"] = "String","[path to EXE or ICO file]"              #<-- Do modify if required
				$UninstallKeys["NoRepair"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["NoModify"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["NoRemove"] = "DWORD", 1 #<-- Modify if needed
				$UninstallKeys["SystemComponent"] = "DWORD", 1 #<-- Modify if needed
				
				Foreach ($reg_value in $UninstallKeys.Keys)
				{
					Set-RegistryKey -Key "Registry::$Uninstall_Key_Path" -Name $reg_value -Type $UninstallKeys[$reg_value][0] -Value $UninstallKeys[$reg_value][1]
				}
				
				
			}
			}
			
			
			## <Perform Post-Installation tasks here>
        Show-InstallationProgress -StatusMessage "Running Post-install tasks $appVendor $appName $appVersion, please wait..."
        If (($mainExitCode -eq 0) -or ($mainExitCode -eq 3010) -or ($mainExitCode -eq 3011) -or ($mainExitCode -eq 1641))
        {            
            #  ******  Set status to success  ******
            Write-Log -Message "Installation of $appVendor $appName $appVersion is successfull!  Exit code = $mainExitCode" -Source 'mainExitCode'
            [string]$status = "Success"
        } Else
        {
            Write-Log -Message "Error installing $appVendor $appName $appVersion!  Exit code = $mainExitCode" -Source 'mainExitCode'
            [string]$status = "Failure"
        }
		
        #  ******  Restore PendingFileRenameOperations, if necessary  ******
        If ($PendingRename -ne "n/a")
        {
            #  ******  Restoring PendingFileRenameOperations  ******
            If (Test-RegistryValue -Key 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Value PendingFileRenameOperations)
            {
                #  ******  Registry key exists, grab value  ******
                Write-Log -Message "PendingFileRenameOperations added by installer, get value, then add to current value." -Source 'Test-RegistryValue'
                $PendingRenameNew = Get-RegistryKey -Key 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Value PendingFileRenameOperations
            } Else
            {
                #  ******  Registry key exists, grab value  ******
                Write-Log -Message "PendingFileRenameOperations not added by installer, set blank value for appending." -Source 'Test-RegistryValue'
                $PendingRenameNew = ""
            }

            #  ******  Add new PendingRename to old  ******
            Set-RegistryKey -Key 'HKLM:\System\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -Value ($PendingRename + $PendingRenameNew) -Type MultiString
        }
        
        #  ******  Tag registry  ******
        Set-RegistryKey -Key "HKLM\Software\CompanyName\Cardinal\$appVendor.$appName.$appVersion" -Name 'ExitCode' -Value $mainExitCode -Type String
        Set-RegistryKey -Key "HKLM\Software\CompanyName\Cardinal\$appVendor.$appName.$appVersion" -Name 'InstallDate' -Value $(Get-Date) -Type String
        Set-RegistryKey -Key "HKLM\Software\CompanyName\Cardinal\$appVendor.$appName.$appVersion" -Name 'InstallStatus' -Value $status -Type String
        Set-RegistryKey -Key "HKLM\Software\CompanyName\Cardinal\$appVendor.$appName.$appVersion" -Name 'PkgBuildDate' -Value $appScriptDate -Type String
        Set-RegistryKey -Key "HKLM\Software\CompanyName\Cardinal\$appVendor.$appName.$appVersion" -Name 'PkgInstallVersion' -Value "v$appScriptVersion, r$appRevision" -Type String
		
		## Display a message at the end of the install
		#If (-not $useDefaultMsi) { Show-InstallationPrompt -Message 'You can customize text to appear at the end of an install or remove it completely for unattended installations.' -ButtonRightText 'OK' -Icon Information -NoWait }
        
	}
	ElseIf ($deploymentType -ieq 'Uninstall')
	{
        Write-Log -Message "Not imlpemented!" -Source 'Remove-RegistryKey'
	}
	
	##*===============================================
	##* END SCRIPT BODY
	##*===============================================
	
	## Call the Exit-Script function to perform final cleanup operations
	Exit-Script -ExitCode $mainExitCode
}
Catch {
	[int32]$mainExitCode = 60001
	[string]$mainErrorMessage = "$(Resolve-Error)"
	Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
	Show-DialogBox -Text $mainErrorMessage -Icon 'Stop'
	Exit-Script -ExitCode $mainExitCode
}
