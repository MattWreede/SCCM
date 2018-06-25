##Reboot checker!#####
$SCCMRunning = Get-Process ccmexec -ErrorAction SilentlyContinue
if($SCCMRunning)
{
$LoggedOn = Get-WmiObject -Class win32_process  -computer 'localhost' -Filter "name='explorer.exe'" | 
    Foreach-Object { 
        $_.GetOwner() 
    }

    if($LoggedOn.User)
    {
    Write-Log -Message 'User is logged on! I am super excited about this!' -Level Info  
    }
else
{
Write-Log -Message 'User is not logged on! This is also super exciting!' -Level Info
}

$LastTime = Get-RegistryValue "HKLM:\software\XXX\SCCM" LastTime
$now=Get-Date -format "dd-MMM-yyyy HH:mm"
$rebootPending = (Invoke-WmiMethod -Namespace root\ccm\clientsdk -Class CCM_ClientUtilities -Name DetermineIfRebootPending).RebootPending
$Name = "LastTime"
$RebootPath = Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
$RingValue = Get-RegistryValue "HKLM:\software\XXX\SCCM" Ring
$RebootAlreadyPending = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client\Reboot Management\RebootData' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty 'NotifyUI' -ErrorAction SilentlyContinue

if($RebootAlreadyPending -eq "1")
{
Write-Log -Message "I already have a reboot pending"
}
else
{
Write-Log -Message "I have not fired off a reboot."
}



if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore)
{
Write-Log -Message 'I have pending file rename operations!' -Level Info
$FileRename = "True"
}


#Setting base DAYS value
$Days = "7"

##My logic for determining days!
if($RingValue -eq "Ring 3")
{
Write-Log -Message 'I am ring 3, setting DAYS to 5.' -Level Info
$Days = "5"
}

if($RingValue -eq "Ring 2")
{
Write-Log -Message 'I am ring 2, setting DAYS to 3.' -Level Info
$Days = "3"
}

if(Test-Path $VirtualFile)
{
Write-Log -Message 'I am Virtual, setting DAYS to 3.' -Level Info
$Days = "3"
}



if(Test-Path $registryPath)
{
Write-Log -Message 'Registry key exists, no need to create!' -Level Info  
}
else
{
Write-Log -Message 'Creating new Registry key!' -Level Info  
New-Item $RegistryPath -Force
}

if($rebootPending)
{
Write-Log -Message 'I have reboot pending from CCM itself!' -Level Info
}

if($RebootPath)
{
Write-Log -Message 'I have a reboot pending from WUA!' -Level Info
}

if($FileRename)
{
Write-Log -Message 'I have a reboot pending from FileRename! I am not however doing anything about this!' -Level Warn
}

if ($rebootPending -or $RebootPath)

{
    Write-Log -Message 'I have reboot pending from either source!' -Level Info
     if(!$LoggedOn.User)
    {
    Write-Log -Message 'User is NOT logged on! I am super excited about this! I GET TO REBOOT!' -Level Info
    Remove-ItemProperty -Path $registryPath -Name "LastTime"  
   Write-Host "Success"
    ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('XXXXX-XXX000F1-1A3D4F5C')
    
    exit  
    }  
    if(Test-RegistryValue $registryPath 'LastTime')
{
Write-Log -Message 'My time key exists! I will use it later to compare stuff!' -Level Info  
}
else
{
Write-Log -Message 'My time key does not exist, going to make it now!' -Level Info  
New-ItemProperty -Path $registryPath -Name $Name -Value $now -PropertyType String -Force | Out-Null
}

$TimeSpanReboot = NEW-TIMESPAN –Start $LastTime –End $now
Write-Log -Message 'Adding Hardware Inventory keys!' -Level Info
$InventoryKey = "Custom3"
$InventoryValue = $TimeSpanReboot.Days
New-ItemProperty -Path $registryPath -Name $InventoryKey -Value $InventoryValue -PropertyType String -Force | Out-Null
$TimeSpanRebootDays = $TimeSpanReboot.TotalDays
Write-Log -Message "My TimeSpanRebootTotalDays is $TimeSpanRebootDays"

    if($TimeSpanReboot.Days -gt $Days -and $RebootAlreadyPending -ne "1")
    {
    Write-Log -Message 'REBOOT - Time is greater than the specified number of days, kicking off REBOOT and removing the original LastTime!' -Level Info
    Remove-ItemProperty -Path $registryPath -Name "LastTime"  
    ([wmiclass]'ROOT\ccm:SMS_Client').TriggerSchedule('XXXX20083-XXXX000F1-1A3D4F5C')
    Write-Host "Success"

    }
    else
    {
    Write-Log -Message 'I am not within the specified number of days; no reboot kick off! Failing Compliance!' -Level Info
Write-Log -Message "My number of days is $TimeSpanRebootDays" -Level Info   
    Write-Host "Fail"
    }
    }
    else
    {
    Write-Log -Message 'Deleting the registry key of LastTime and Custom3, since I have no pending reboot!' -Level Info
    Remove-ItemProperty -Path $registryPath -Name "LastTime"
    Remove-ItemProperty -Path $registryPath -Name "Custom3"   
    Write-Host "Success"
    }

    }
    }