function LoadConfig {
    param([Parameter(Mandatory=$True)] [string]$path = $(throw "You must specify a config file"))
    $global:appSettings = @{}
    $config = [xml](get-content $path)
    foreach ($addNode in $config.configuration.appsettings.add) {
     if ($addNode.Value.Contains(‘,’)) {
      # Array case
      $value = $addNode.Value.Split(‘,’)

      for ($i = 0; $i -lt $value.length; $i++) {
        $value[$i] = $value[$i].Trim()
      }
     }
     else {
      # Scalar case
      $value = $addNode.Value
     }
     $global:appSettings[$addNode.Key] = $value
    }
}

#Export-ModuleMember -Function LoadConfig

Function Get-ComputerModel {
    Switch((Get-WmiObject 'Win32_ComputerSystem' -Property Manufacturer).Manufacturer) {
    
        'LENOVO' {
            $model = (Get-WmiObject 'Win32_ComputerSystemProduct' -Property Version).Version
            break
        }
        'Hewlett-Packard' {
            $model = (Get-WmiObject 'Win32_ComputerSystem' -Property Model).Model
            break
        }
        'HP' {
            $model = (Get-WmiObject 'Win32_ComputerSystem' -Property Model).Model
            break
        }
        default {
            $model = (Get-WmiObject 'Win32_ComputerSystem' -Property Model).Model
            break
        }
    }

    Return $model
}

function Get-OSArchitecture {            
    [cmdletbinding()]            
    param(            
        [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]            
        [string[]]$ComputerName = $env:computername                        
    )            

    begin {}            

    process {            

     foreach ($Computer in $ComputerName) {            
      if(Test-Connection -ComputerName $Computer -Count 1 -ea 0) {            
       Write-Verbose "$Computer is online"            
       $OS  = (Get-WmiObject -computername $computer -class Win32_OperatingSystem ).Caption            
       if ((Get-WmiObject -Class Win32_OperatingSystem -ComputerName $Computer -ea 0).OSArchitecture -eq '64-bit') {            
        $architecture = "64-Bit"            
       } else  {            
        $architecture = "32-Bit"            
       }            

       $OutputObj  = New-Object -Type PSObject            
       $OutputObj | Add-Member -MemberType NoteProperty -Name ComputerName -Value $Computer.ToUpper()            
       $OutputObj | Add-Member -MemberType NoteProperty -Name Architecture -Value $architecture            
       $OutputObj | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value $OS            
       $OutputObj            
      }            
     }            
    }            

    end {}            

}

Function HPSystemSoftwareManager {
    param(
	    [ValidateScript({Test-Path -Path $_})][String] $ssd,
	    [ValidateScript({Split-Path $_ -parent})] [String] $log = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - HP System Software Manager.log",
        $verbosePreference = "Continue",
        $repository,
        $wait = $true,
        $timeout = 1800
    )

    Switch([String]::Join('.',(Get-CimInstance win32_OperatingSystem).Version.Split('.')[0..1])) {
        '6.1' {
            $osName = 'Win7'
        }
        '6.3' {
            $osName = 'Win8.1'
        }
        '10.0' {
            $osName = 'Win10'
        }    
    }

    if([String]::IsNullOrEmpty($osName)){
        Write-Error "Could not determine OS version"
        Exit 1
    }

    If(-not(Test-Path $repository)) {
        Write-error "Repository not found: $repository"
        exit 1
    }
    else {
        "SSM: $ssm" | Out-File -FilePath $log -Append
        ("Arguments: {0}" -f [String]::Join(' ', @("`"$repository`"", '/accept', '/noreboot', "/log:c:\windows\logs\hpssm.log'")))  | Out-File -FilePath $log -Append

        $p = Start-Process -FilePath $ssm -ArgumentList @($repository, '/accept', '/noreboot', "/log:c:\windows\logs\hpssm.log'") -PassThru

        If($wait -and (Get-process -ID $p.ID -ErrorAction SilentlyContinue)) {

            Wait-Process -id $p.ID -timeout $timeout

            if(!$p.hasExited) {
                taskkill /T /F /PID $p.ID | Out-File -FilePath $log -Append
                #$p.Kill()
        
                "Process killed after $timeout" | Out-File -FilePath $log -Append
            }
        }
    }
}

Function ThinInstaller {
    param(
	    [ValidateScript({Test-Path -Path $_})][String] $thinInstaller = "${env:ProgramFiles(x86)}\Lenovo\ThinInstaller\ThinInstaller.exe",
	    [ValidateScript({Split-Path $_ -parent})] [String] $log = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - Lenovo ThinInstaller.log",
        $repository,
        $verbosePreference = "Continue",
        $allowReboot = $false,
        $rebootTypes = @(2,3),
        $wait = $true,
        $timeout = 1800
    )

    # !!! BUG in ThinInstaller: does not work if thininstaller is called from UNC path. From network mapped drive works fine.


    if($allowReboot) {
        $reboot = ' '
    }
    else {
        $reboot = '-noreboot'
    }

    $allowedRebootTypes = [String]::Join(',', $rebootTypes)


    If(-not (Test-Path "$repository")) {
        Write-error "Repository not found: $repository"
        exit 1
    }
    else {
        Write-Verbose "ThinInstaller: $thinInstaller"

        Write-Verbose ("Arguments: {0}" -f @([String]::Join(' ', @('/CM', '-search', 'A', '-action', 'install', '-repository',  "$repository", '-log', "$log", '-includerebootpackages', $allowedRebootTypes, $reboot, '-noicon'))))
        $p = Start-Process -FilePath "`"$thinInstaller`"" -ArgumentList @('/CM', '-search', 'A', '-action', 'install', '-repository',  "`"$repository`"", '-log', "`"$log`"", '-includerebootpackages', $allowedRebootTypes, $reboot, '-noicon') -Verb RunAs -PassThru

        If($wait -and (Get-process -ID $p.ID -ErrorAction SilentlyContinue)) {

            Wait-Process -id $p.ID -timeout $timeout

            if(!$p.hasExited) {
                taskkill /T /F /PID $p.ID | Out-File -FilePath $log -Append
                #$p.Kill()
        
                "Process killed after $timeout" | Out-File -FilePath $log -Append
            }
        }
    }

    $ourObject = New-Object -TypeName psobject
    $ourObject | Add-Member -MemberType NoteProperty -Name ExitCode -Value $p.ExitCode

    Return $ourObject
}

#The DPInst executable returns a decimal value. We can decode it find out what the outcome of the installation was.
#First, the value needs to be convert the decimal value into hexadecimal. The easieast way to do it is using the Calculator. Switch to Programmer View, select Decimal, enter the value, click on Hex. That’s it.
#You’ll obtain a value like 0xWWXXYYZZ(or less digits – in this case, the zeros in front won’t be shown). Then, we separate the pairs. Basically, we`ll get 4 hex numbers. This is their meaning:

Function AnalyseDPinstExitcode{
	param(
		$code
	)

	$psCustomObject = New-Object PsCustomObject

	$hexCodeString = "{0:X8}" -f $code

	Switch($hexCodeString.Substring(0,2)) {
		'80' {
			$psCustomObject | Add-Member -MemberType NoteProperty -Name Status -Value "Could not install package"
		}
		'40' {
			$psCustomObject | Add-Member -MemberType NoteProperty -Name Status -Value "Reboot required"
			$psCustomObject | Add-Member -MemberType NoteProperty -Name Reboot -Value $true
		}
		'00' {
			$psCustomObject | Add-Member -MemberType NoteProperty -Name Reboot -Value $false
		}
	}

	$psCustomObject | Add-Member -MemberType NoteProperty -Name 'Failed' -Value ([Int]::Parse($hexCodeString.Substring(2,2))) -ErrorAction SilentlyContinue
	$psCustomObject | Add-Member -MemberType NoteProperty -Name 'Updated in driver store' -Value ([Int]::Parse($hexCodeString.Substring(4,2))) -ErrorAction SilentlyContinue
	$psCustomObject | Add-Member -MemberType NoteProperty -Name 'Installed' -Value ([Int]::Parse($hexCodeString.Substring(6,2))) -ErrorAction SilentlyContinue

	$psCustomObject
}

# https://www.howtogeek.com/tips/how-to-extract-zip-files-using-powershell/
Function Expand-ZIPFile($file, $destination) {
	$shell = new-object -com shell.application
	
	#$zip = $shell.NameSpace($file)
	#foreach($item in $zip.items())
	#{
	#		$shell.Namespace($destination).copyhere($item,  (0x4 -bor 0x14))
	#}

	Add-Type -assembly “system.io.compression.filesystem”

	[io.compression.zipfile]::ExtractToDirectory($file, $destination)



}

# https://www.howtogeek.com/tips/how-to-extract-zip-files-using-powershell/
Function Expand-CabFile($file, $destination) {
	#$shell = new-object -com shell.application
	#$zip = $shell.NameSpace($file)
	#foreach($item in $zip.items())
	#{
	##	$shell.Namespace($destination).copyhere($item,  (0x4 -bor 0x14))
	#}

	#Add-Type -assembly “system.io.compression.filesystem”

	#[io.compression.zipfile]::ExtractToDirectory($file, $destination, $true)
    & 'expand.exe' @('-F:*', $file, $destination)


}

function WriteLogSectionHeader {
	param(
		$caption,
		$logFile
	)

	WriteLog -line (""-f $_.FullName) -logFile $outputFile
	WriteLog -line ("----------------------------------------------------------------------"-f $_.FullName) -logFile $outputFile
	WriteLog -line ("$caption") -logFile $outputFile
	WriteLog -line ("----------------------------------------------------------------------"-f $_.FullName) -logFile $outputFile
}

function WriteLogSectionFooter {
	param(
		$logFile
	)

	WriteLog -line ("----------------------------------------------------------------------") -logFile $outputFile
}

function WriteLog {
	param(
		$line,
		$logFile
	)

	($line) | Out-File -FilePath $logFile -Append    
}

Function ThinInstallerSection {
	param(
		$packageFolder,
		$outputFile,
		$thinInstaller,
		$rebootTypes,
		$wait = $true
	)

	If(Test-Path -Path $packageFolder) {
		$candidates = GCI -PATH $packageFolder -verbose | Select @{name='Name';expression={ ([xml](Get-Content ((Gci -Path $_.FullName -Filter "$($_.BaseName)*.xml").FullName | select -First 1))).SelectNodes('/Package/Title/Desc').InnerText    } }        

		$action = 'ThinInstaller'
		$caption = "Starting $action for packages with reboot type: "  + [String]::Join(',', $rebootTypes)
		$thinInstallerLog = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - Lenovo ThinInstaller.log"

		WriteLogSectionHeader -caption $caption -logFile $outputFile

		If($candidates -and (Test-Path -path $thinInstaller)) {
		
			$thinInstallerLog = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - Lenovo ThinInstaller.log"

			WriteLog -line ("Output logged to: $thinInstallerLog") -logFile $outputFile
		
			WriteLog -line ("Candidate products: ") -logFile $outputFile

			$candidates | % {
				WriteLog -line (("Product name: {0} ") -f $_.Name) -logFile $outputFile
			}     

			ThinInstaller -repository $packageFolder -log $thinInstallerLog -thinInstaller $thinInstaller  -rebootTypes $rebootTypes -wait $wait -allowReboot $false 4>> $outputFile
		}
		else {
			WriteLog -line "No candidate products found or Lenovo ThinInstaller is not installed. Skipping ThinINstaller" -logFile $outputFile
		}
		
	}
	else {
		WriteLog -line ("No package repository found for this computer model on this platform available. Folder: $packageFolder was not found." -f $_.FullName) -logFile $outputFile
	}

}

function New-TemporaryDirectory {
  $parent = [System.IO.Path]::GetTempPath()
  do {
    $name = [System.IO.Path]::GetRandomFileName()
    $item = New-Item -Path $parent -Name $name -ItemType "directory" -ErrorAction SilentlyContinue
  } while (-not $item)
  return $Item.FullName
}

Function DriverUpdate {
	# Script DriverUpdate.ps1

	<# .SYNOPSIS
		 DriverUpdate allows you to easily automate driver installtion for HP and Lenovo systems
	.DESCRIPTION
		Script is a PowerShell front end for installing drivers using:
		- Dpinst - installing INF-drivers
		- Lenovo driver packages (installing using Lenovo ThinInstaller)
		- HP SoftPaq's (installing using HP System Software Manager)

		Script requires elevation.

	.NOTES
		 Author     : Christian Smit - christian.smit@cardinalhealth.net
	.LINK
		 http://
	#>

	Param (
		#[Parameter(Mandatory=$false,HelpMessage='Directory where to store log file.)')]
		$logDir = "$($env:SystemRoot)\Logs\Software",

		[Parameter(Mandatory=$false,HelpMessage='Version number of driver package')]
		$driverUpdateVersion,
		$driverFolder = ".\Out-Of-Box-Drivers",
		$packageFolder = ".\Packages",
        $dpinstBinary = ".\..\Bin\Dpinst\x64\dpinst.exe",
        $thinInstallerBinary,
        $ssmBinary
	)
	#write-host $driverFolder



	$rebootRequired = $false

	# Original Script located at:
	# http://blogs.msdn.com/b/virtual_pc_guy/archive/2010/09/23/a-self-elevating-powershell-script.aspx

	# Get the ID and security principal of the current user account
	$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
	$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

	# Get the security principal for the Administrator role
	$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

	# Check to see if we are currently running "as Administrator"
	if ($myWindowsPrincipal.IsInRole($adminRole))

		{
		# We are running "as Administrator" - so change the title and background color to indicate this
		#$Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
		#$Host.UI.RawUI.BackgroundColor = "DarkBlue"
		#clear-host

		}
	else
		{
		# We are not running "as Administrator" - so relaunch as administrator

		# Create a new process object that starts PowerShell
		$newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";

		# Specify the current script path and name as a parameter
		$newProcess.Arguments = $myInvocation.MyCommand.Definition;

		# Indicate that the process should be elevated
		$newProcess.Verb = "runas";

		# Start the new process
		[System.Diagnostics.Process]::Start($newProcess);
		   
		# Exit from the current, unelevated, process
		return 5

	}


	# Check for elevation 
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) 
	{ 
		Write-Warning "Oupps, you need to run this script from an elevated PowerShell prompt!`nPlease start the PowerShell prompt as an Administrator and re-run the script." 
		Write-Warning "Aborting script..."
		Break 
	}

	# Check for silly path restriction
	If ($PSScriptRoot.Contains(' ')) 
	{ 
		Write-Warning "Oupps, you need to run this script from a folder/path that does not contain spaces." 
		Write-Warning "Aborting script..."
		Break 
	}

	Switch((Get-OSArchitecture | Where { $_.ComputerName -eq $env:computername } | Select Architecture).Architecture) {
		"32-bit" {
			$dpInst = $dpinstBinary
			$architecture = 'x86'
			$thinInstaller = $thinInstallerBinary
			$ssm = $ssmBinary
		}
		"64-bit" {
			$dpInst = $dpinstBinary
			$architecture = 'x64'
			$thinInstaller = $thinInstallerBinary
			$ssm = $ssmBinary
		}
        default {
            $dpInst = $dpinstBinary
			$architecture = 'x64'
			$thinInstaller = $thinInstallerBinary
			$ssm = $ssmBinary
        }
	}

	$manufacturer = (Get-WmiObject 'Win32_ComputerSystem' -Property Manufacturer).Manufacturer
	$osMajorVersionNumber = [String]::Join('.',(Get-CimInstance win32_OperatingSystem).Version.Split('.')[0..1])
	$computerModel = (Get-ComputerModel).Replace(' ', '_') # because dpinst does not like spaces in paths

	$outputFile = "$logDir\{0} - DriverUpdate.log" -f @((Get-Date -format 'MM-dd-yyyy HH.mm.ss'))

	# seperate folders for multiple computer models
	$possibleDriverRepo = "$driverFolder\{0}\{1}\{2}\{3}" -f $osMajorVersionNumber, $architecture, $manufacturer, $computerModel
	If(Test-Path -Path $possibleDriverRepo) {
		$driverFolders = @($possibleDriverRepo)
	}
	# single folder for drivers
	Else {
		$driverFolders = @($driverFolder)
	}

	$driverFolders | % {

        $folder = $_
        
	    # extract a driver package
	    If(Test-Path -Path $folder) {
	   
		    $zips = gci -Path $folder -Filter *.zip

		    If(($zips | Measure-Object).Count -ne 0) {
			
			    # create parent folder
			    $newItem = New-TemporaryDirectory
			
			    If(-not (Test-path -Path $newItem)) {
				    New-Item -Path $newItem -ItemType Directory -ErrorAction Stop
			    }
			
			    If(Test-Path -Path $newItem) {
				    If(($zips | Measure-Object).Count -ge 1) {
			
					    $zips | % {            
						    Expand-ZIPFile –File $_.FullName –Destination $newItem
					    }

					    $driverFolders += $newItem
				    }
			    }
		    }
        
	

	        # extract a driver package	                                                                                                                                                                                                                If(Test-Path -Path $driverFolders) {
	   
		    $cabs = gci -Path $folder -Filter *.cab

		    If(($cabs | Measure-Object).Count -ne 0) {
			
			    # create parent folder
			    $newItem = New-TemporaryDirectory
			
			    If(-not (Test-path -Path $newItem)) {
				    New-Item -Path $newItem -ItemType Directory -ErrorAction Stop
			    }
			
			    If(Test-Path -Path $newItem) {
				    If(($cabs | Measure-Object).Count -ge 1) {
			
					    $cabs | % {            
						    Expand-CABFile –File $_.FullName –Destination $newItem
					    }

					    $driverFolders += $newItem
				    }
			    }
		    }

            # extract HP SoftPaqs that contain INF-files
            If(@('hp', 'hewlett-packard') -Contains $manufacturer.ToLower()) { 
                $candidates = GCI -PATH $folder -verbose -File -Filter *.exe
		        $wait = $true
                $timeout = 300
		        Write-Verbose "Install HP packages"

		        $candidates | % {
								
                    #$packageLog = "$($env:SystemRoot)\Logs\Software\HP_$($_.Name)_install.log"

                    (("Installing product: {0} ") -f $_.Name)| Out-File -File $outputFile -Append
                    (("Executing: {0} {1}") -f $_.Fullname, '/s')| Out-File -File $outputFile -Append

                    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                    $pinfo.FileName = $_.FullName
                    $pinfo.RedirectStandardError = $true
                    $pinfo.RedirectStandardOutput = $true
                    $pinfo.UseShellExecute = $false
                    $pinfo.Arguments = @('-s', '-pdf', '-f', $driverFolder)

                    $p = New-Object System.Diagnostics.Process

                    $p.StartInfo = $pinfo

                    $p.Start() | Out-Null

			        If($wait -and (Get-process -ID $p.ID -ErrorAction SilentlyContinue)) {

				        Wait-Process -id $p.ID -timeout $timeout

				        if(!$p.hasExited) {
					        taskkill /T /F /PID $p.ID | Out-File -FilePath $outputFile -Append
					        "Process killed after $timeout" | Out-File -FilePath $outputFile -Append
				        }
			        }
		        }
            }
	    }
    
    }

	# filter out only existing driver folders
	$driverFolders = $driverFolders | ? { Test-Path -Path $_ } 

	# Get all unique folders that contain an INF-file
	$driverFolders = $driverFolders | % { Gci -Path $_ -Recurse -Include *.inf -ErrorAction SilentlyContinue | Select @{name='FullName';expression={Split-Path -parent $_}}}
    
    # If structure is there to supprot multple models    
    If(Test-path -Path ("$packageFolder\{0}\{1}\{2}\{3}" -f $osMajorVersionNumber, $architecture, $manufacturer, $computerModel)) {
        $packageFolder = "$packageFolder\{0}\{1}\{2}\{3}" -f $osMajorVersionNumber, $architecture, $manufacturer, $computerModel
    }
    else {
        # keep
    }


	$caption = "Starting script with following values"

	WriteLogSectionHeader -caption $caption -logFile $outputFile 
	WriteLog -line "Using following values" -logFile $outputFile
	WriteLog -line "Computer manufacturer: $manufacturer" -logFile $outputFile       
	WriteLog -line "Computer model: $computerModel" -logFile $outputFile       
	WriteLog -line "Windows major version number : $osMajorVersionNumber" -logFile $outputFile       
	WriteLog -line "Architecture: $architecture" -logFile $outputFile       
	WriteLog -line "INF Driver folder Manufacturer: $driverFolder" -logFile $outputFile
	WriteLog -line "Vendor ($manufacturer) package folder: $packageFolder" -logFile $outputFile       
	WriteLog -line "Dpinst.exe: $dpinst" -logFile $outputFile       
	WriteLog -line "Thininstaller: $thinInstaller" -logFile $outputFile       
	WriteLog -line "HP SSM: $ssm" -logFile $outputFile       
	WriteLogSectionFooter -logFile $outputFile 

	If($driverFolders -and ((Test-Path -Path $driverFolders | Measure-Object).Count -gt 0)) {

		########################################
		# Install all drivers using Dpinst

		$caption = "Installing INF drivers"
		WriteLogSectionHeader -caption $caption -logFile $outputFile 

		If(-not [String]::IsNullOrEmpty($dpInst)) {
			
			WriteLog -line "For more details on dpinst actions, review: %SystemRoot%\Dpinst.log and see the application and system event log at $(Get-date)." -logFile $outputFile
			WriteLog -line "Will process following driver folders:" -logFile $outputFile
			WriteLog -Line ($driverFolders  |  Ft -autosize | out-string -width 4096 ) -logFile $outputFile

			$driverFolders |  % {
			
				$driverFolder = $_
				WriteLog -line ("----------------------------------------------------------------------"-f $_.FullName) -logFile $outputFile
				WriteLog -line ("Found driver: {0}"	-f $_.FullName) -logFile $outputFile
				WriteLog -line ("Starting dpinst: {0} {1} {2} {3} {4} {5} {6}" -f @($dpInst, $_.FullName, '/a', '/s', '/se', '/sw', "/path `"$($driverFolder.FullName)`"")) -logFile $outputFile
			
				# /f - force installation of driver
				$processResult = Start-Process -FilePath $dpInst -ArgumentList @('/a', '/s', '/se', '/sw', "/path `"$($driverFolder.FullName)`"") -Wait -PassThru
			
				

				If($processResult -and [String]::IsNullOrWhiteSpace($processResult.OutputDataReceived)) {

					$rebootRequired = $rebootRequired #-or ((AnalyseDPinstExitcode -code $processResult.ExitCode).Reboot)

					Writelog -Line "Dpist exited with code : $($processResult.ExitCode). This code means:"  -logFile $outputFile
					WriteLog -Line (""-f $_.FullName) -logFile $outputFile
					#WriteLog -Line (AnalyseDPInstExitcode -code $processResult.ExitCode | Out-String ).Trim() -logFile $outputFile
					WriteLog -Line (""-f $_.FullName) -logFile $outputFile
			 
				}
			
			}
		}
		Else { #pdinst not found
			 WriteLog -line "$dpinst not found!" -logFile $outputFile
		}
	}
	else {
		WriteLog -line ("No valid folders found with INF-drivers: $(($driverFolders | % {$_.FullName}) -join ', ')" -f $_.FullName) -logFile $outputFile
	}

	If(Test-Path -Path $packageFolder) {
		
		Switch($manufacturer) {
			'Hewlett-Packard' {
				#$candidates = GCI -PATH $packageFolder -verbose | Select @{name='Name';expression={ ([xml](Get-Content ((Gci -Path $_.FullName -Filter "$($_.BaseName)*.xml").FullName | select -First 1))).SelectNodes('/Package/Title/Desc').InnerText    } }        
			  
				$caption = 'HP System Software Manager'
				WriteLogSectionHeader -caption $caption -logFile $outputFile   

				If( (Test-Path -path $ssm)) {
			
					$log = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - HP SSM.log"

					("Output logged to: $log") | Out-File -File $outputFile -Append
			
					("Candidate products: ") | Out-File -File $outputFile -Append

					#$candidates | % {
					#	(("Product name: {0} ") -f $_.Name)| Out-File -File $outputFile -Append
					#}     

					HPSystemSoftwareManager -ssm $ssm -repository $packageFolder -log $log 4>> $outputFile
				}
				else {
					("No candidate products found or HP SSM is not installed. Skipping HP System Software Manager") | Out-File -File $outputFile -Append
				}


			}
			'HP' {
				#$candidates = GCI -PATH $packageFolder -verbose | Select @{name='Name';expression={ ([xml](Get-Content ((Gci -Path $_.FullName -Filter "$($_.BaseName)*.xml").FullName | select -First 1))).SelectNodes('/Package/Title/Desc').InnerText    } }        
			  
				$caption = 'HP System Software Manager'
				WriteLogSectionHeader -caption $caption -logFile $outputFile   

				If( (Test-Path -path $ssm)) {
			
					$log = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - HP SSM.log"

					("Output logged to: $log") | Out-File -File $outputFile -Append
			
					("Candidate products: ") | Out-File -File $outputFile -Append

					#$candidates | % {
					#	(("Product name: {0} ") -f $_.Name)| Out-File -File $outputFile -Append
					#}     

					HPSystemSoftwareManager -ssm $ssm -repository $packageFolder -log $log 4>> $outputFile
				}
				else {
					("No candidate products found or HP SSM is not installed. Skipping HP System Software Manager") | Out-File -File $outputFile -Append
				}

				
			}
			'Dell Inc.' {
				$candidates = GCI -PATH $packageFolder -verbose -File -Filter *.exe
				$wait = $true
                
                $TSManager = Get-Process tsmanager -ErrorAction SilentlyContinue
		        if ($TSManager -eq $null)
                {
               # "Task Sequence is not null, timeout is 600" | Out-File -FilePath $log -Append
               WriteLog -line "Task Sequence is null, timeout is 720" -logFile $outputFile
               # Write-Verbose "Task Sequence is null, timeout is 600"
                $timeout = 720
                }
                else
                {
                #Write-Verbose "Task Sequence is active, timeout is 300"
                WriteLog -line "Task Sequence is active, timeout is 720" -logFile $outputFile
                #"Task Sequence is null, timeout is 300" | Out-File -FilePath $log -Append
                $timeout = 720
                }

				Write-Verbose "Install Dell packages"

				$candidates | % {
								
                    $packageLog = "$($env:SystemRoot)\Logs\Software\Dell_$($_.Name)_install.log"

                    (("Installing product: {0} ") -f $_.Name)| Out-File -File $outputFile -Append
                    (("Executing: {0} {1} {2}") -f $_.Fullname, '/s', ("/l=`"{0}`"" -f $packageLog))| Out-File -File $outputFile -Append

                    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
                    $pinfo.FileName = $_.FullName
                    $pinfo.RedirectStandardError = $true
                    $pinfo.RedirectStandardOutput = $true
                    $pinfo.UseShellExecute = $false
                    $pinfo.Arguments = @('/s', ("/l=`"{0}`"" -f $packageLog))

                    $p = New-Object System.Diagnostics.Process

                    $p.StartInfo = $pinfo

                    $p.Start() | Out-Null

                    #$p.WaitForExit()

                    #$p.ExitCode


		            #$p = Start-Process -FilePath $_.Fullname -ArgumentList @('/s', ("/l=`"{0}`"" -f $packageLog)) -Verb RunAs -PassThru 
                    #Start-Sleep 10
					If($wait -and (Get-process -ID $p.ID -ErrorAction SilentlyContinue)) {

					    Wait-Process -id $p.ID -timeout $timeout

					    if(!$p.hasExited) {
						    taskkill /T /F /PID $p.ID | Out-File -FilePath $outputFile -Append
						    "Process killed after $timeout" | Out-File -FilePath $outputFile -Append
						}
					}
				}
					
			}
			'Lenovo' {

            
		        $rebootTypes = @(2,3)
		        $wait = $true
	        

	            If(Test-Path -Path $packageFolder) {
		            $candidates = GCI -PATH $packageFolder -verbose | Select @{name='Name';expression={ ([xml](Get-Content ((Gci -Path $_.FullName -Filter "$($_.BaseName)*.xml").FullName | select -First 1))).SelectNodes('/Package/Title/Desc').InnerText    } }        

		            $action = 'ThinInstaller'
		            $caption = "Starting $action for packages with reboot type: "  + [String]::Join(',', $rebootTypes)
		            $thinInstallerLog = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - Lenovo ThinInstaller.log"

		            WriteLogSectionHeader -caption $caption -logFile $outputFile

		            If($candidates -and (Test-Path -path $thinInstaller)) {
		
			            $thinInstallerLog = "$($env:SystemRoot)\Logs\$(Get-Date -format 'MM-dd-yyyy HH.mm.ss') - Lenovo ThinInstaller.log"

			            WriteLog -line ("Output logged to: $thinInstallerLog") -logFile $outputFile
		
			            WriteLog -line ("Candidate products: ") -logFile $outputFile

			            $candidates | % {
				            WriteLog -line (("Product name: {0} ") -f $_.Name) -logFile $outputFile
			            }     

			            $resultThinInstaller = ThinInstaller -repository $packageFolder -log $thinInstallerLog -thinInstaller $thinInstaller  -rebootTypes $rebootTypes -wait $wait -allowReboot $false 4>> $outputFile

                        Writelog -Line "Lenovo ThinInstaller existed with: $($resultThinInstaller.ExitCode)"  -logFile $outputFile
						
						If($resultThinInstaller -and $resultThinInstaller.ExitCode -eq 3010) {
							$rebootRequired = $true
						}

		            }
		            else {
			            WriteLog -line "No candidate products found or Lenovo ThinInstaller is not installed. Skipping ThinINstaller" -logFile $outputFile
		            }
		
	            }
	            else {
		            WriteLog -line ("No package repository found for this computer model on this platform available. Folder: $packageFolder was not found." -f $_.FullName) -logFile $outputFile
	            }

				
			}
		}
	}
	else {
		WriteLog -line ("No package repository found for this computer model on this platform available: $packageFolder was not found." -f $_.FullName) -logFile $outputFile
	}

    <#
	$caption = "Configuring wireless advanced settings"

	WriteLogSectionHeader -caption $caption -logFile $outputFile
		
	$action = 'Registry'
	$caption = "Tagging $action with driver update version"

	WriteLogSectionHeader -caption $caption -logFile $outputFile

	If(-not [String]::IsNullOrEmpty($driverUpdateVersion)) {
		

		If (!(Test-Path "HKLM:\Software\CAH\Cardinal")) {
			New-Item -Type RegistryKey -Path "HKLM:\Software\CAH\Cardinal" -Force -Verbose 4>> $outputFile
		}

		Set-ItemProperty -Path "HKLM:\Software\CAH\Cardinal" -Name "DriverUpdate" -Type 'String' -Value $driverUpdateVersion -Verbose 4>> $outputFile

	}
	else {
		WriteLog -line ("registry not tagged - driver version was blank") -logFile $outputFile
	}
    #>

	WriteLogSectionHeader -caption "Script finished" -logFile $outputFile


	If($rebootRequired) {
		$returnCode = 3010
	}
    Else {
        $returnCode = 0
    }

    return $returnCode
}


