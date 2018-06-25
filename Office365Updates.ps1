##Versions are set for Feb 2018 updates. MLW 2.12.2018

$Dir = "C:\Windows\Logs\APP-Office365UpdateUserCheck.log" 
 
$SizeMax = 5 
 
$Size = (Get-ChildItem $Dir| Measure-Object -property length -sum)  
 
$SizeMb="{0:N2}" -f ($size.sum / 1MB) + "MB" 
 
if ($sizeMb -ge $sizeMax) { 
 
Get-ChildItem $dir -Recurse | Remove-Item –Force 
 
} 



function Write-Log 
{ 
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory=$true, 
                   ValueFromPipelineByPropertyName=$true)] 
        [ValidateNotNullOrEmpty()] 
        [Alias("LogContent")] 
        [string]$Message, 
 
        [Parameter(Mandatory=$false)] 
        [Alias('LogPath')] 
        [string]$Path='C:\Windows\Logs\APP-Office365UpdateUserCheck.log', 
         
        [Parameter(Mandatory=$false)] 
        [ValidateSet("Error","Warn","Info")] 
        [string]$Level="Info", 
         
        [Parameter(Mandatory=$false)] 
        [switch]$NoClobber 
    ) 
 
    Begin 
    { 
        # Set VerbosePreference to Continue so that verbose messages are displayed. 
        $VerbosePreference = 'Continue' 
    } 
    Process 
    { 
         
        # If the file already exists and NoClobber was specified, do not write to the log. 
        if ((Test-Path $Path) -AND $NoClobber) { 
           # Write-Error "Log file $Path already exists, and you specified NoClobber. Either delete the file or specify a different name." 
            Return 
            } 
 
        # If attempting to write to a log file in a folder/path that doesn't exist create the file including the path. 
        elseif (!(Test-Path $Path)) { 
           # Write-Verbose "Creating $Path." 
            $NewLogFile = New-Item $Path -Force -ItemType File 
            } 
 
        else { 
            # Nothing to see here yet. 
            } 
 
        # Format Date for our Log File 
        $FormattedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss" 
 
        # Write message to error, warning, or verbose pipeline and specify $LevelText 
        switch ($Level) { 
            'Error' { 
               # Write-Error $Message 
                $LevelText = 'ERROR:' 
                } 
            'Warn' { 
              #  Write-Warning $Message 
                $LevelText = 'WARNING:' 
                } 
            'Info' { 
              #  Write-Verbose $Message 
                $LevelText = 'INFO:' 
                } 
            } 
         
        # Write log entry to $Path 
        "$FormattedDate $LevelText $Message" | Out-File -FilePath $Path -Append 
    } 
    End 
    { 
    } 
}

$Ipaddress= "xxxxxx"
$Port= "xxx"

$t = New-Object Net.Sockets.TcpClient
$t.Connect($Ipaddress,$Port)
    if($t.Connected)
{


$LoggedOn = Get-WmiObject -Class win32_process  -computer 'localhost' -Filter "name='explorer.exe'" | 
    Foreach-Object { 
        $_.GetOwner() 
    }

    if($LoggedOn.User)
    {
    Write-Log -Message 'User is logged on! I am super excited about this!, but Im going to exit' -Level Info
    Write-Host "Success"
    exit  
    }
else
{
Write-Log -Message 'User is not logged on! Im gonna continue!' -Level Info

}

if(!$LoggOn.User)
{
function trigger-AvailableSupInstall
{
 Param
(
 [String][Parameter(Mandatory=$True, Position=1)] $Computername,
 [String][Parameter(Mandatory=$True, Position=2)] $SupName
 
)
Begin
{
 $AppEvalState0 = "0"
 $AppEvalState1 = "1"
 $ApplicationClass = [WmiClass]"root\ccm\clientSDK:CCM_SoftwareUpdatesManager"
}
 
Process
{
If ($SupName -Like "All" -or $SupName -like "all")
{
 Foreach ($Computer in $Computername)
{
 $Application = (Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_SoftwareUpdate -ComputerName $Computer | Where-Object { $_.EvaluationState -like "*$($AppEvalState0)*" -or $_.EvaluationState -like "*$($AppEvalState1)*"})
 Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$Application) -Namespace root\ccm\clientsdk -ComputerName $Computer
 
}
 
}
 Else
 
{
 Foreach ($Computer in $Computername)
{
 $Application = (Get-WmiObject -Namespace "root\ccm\clientSDK" -Class CCM_SoftwareUpdate -ComputerName $Computer | Where-Object { $_.EvaluationState -like "*$($AppEvalState)*" -and $_.Name -like "*$($SupName)*"})
 Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$Application) -Namespace root\ccm\clientsdk -ComputerName $Computer
 
}
 
}
}
End {}
}

function Get-RegistryValue($key, $value) {
(Get-ItemProperty $key $value).$value
}

$Channel = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration" CDNBaseURL

if($Channel -eq 'http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60')
{
Write-Log -Message 'I am Current' -Level Info
$Target = "16.0.8827.2148"
}

if($Channel -eq 'http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114')
{
Write-Log -Message 'I am Deferred!' -Level Info
$Target = "16.0.8431.2153"
}

if($Channel -eq 'http://officecdn.microsoft.com/pr/64256afe-f5d9-4f86-8936-8840a6a4f5be')
{
Write-Log -Message 'I am Monthly Channel Targeted!' -Level Info
$Target = "16.0.9001.2080"
}



$computer = $env:COMPUTERNAME
$namespace = "ROOT\ccm\ClientSDK"
$classname = "CCM_SoftwareUpdate"

$Updates = Get-WmiObject -Class $classname -ComputerName $computer -Namespace $namespace 
if($Updates.Name -like "*Office 365 Client*")
{
Write-Log -Message 'I have an outstanding Office 365 update; lets see if we can do it!'


If ($env:PROCESSOR_ARCHITECTURE -eq "AMD64")
{
Write-Log -Message 'I am x64!' -Level Info  
$Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Microsoft Office 15\ClientX64\OfficeClickToRun.exe").FileVersion

}
else
{
Write-Log -Message 'I am x86!' -Level Info  
$Version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo("C:\Program Files\Microsoft Office 15\ClientX86\OfficeClickToRun.exe").FileVersion
}

if($Version -lt $Target)
{
Write-Log -Message 'I am less than the target! Lets do this!' -Level Info  
Trigger-AvailableSupInstall -Computername localhost -Supname 'Office 365 Client'
}
else
{
Write-Log -Message 'I didnt do anything! Tee hee! My versions did not require an update!' -Level Info  
Write-Host "Success"
}
}
else
{
Write-Log -Message 'User is logged on, exiting' -Level Info
Write-Host "Sucess"

}
}
}
else
{
Write-Log -Message 'I do not have network!' -Level Info
Write-Host "Success"
}
