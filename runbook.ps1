<#
.NOTES
  Version:        1.0
  Author:         Alexander A. Nordbø
  Creation Date:  21.12.2021
  Purpose/Change: Automaticly download a spesific version of lets encrypt.
                  Disable old scheduled tasks for renewal.
#>

# Do not change these variables unless you know what youre doing!
$Package = "https://github.com/win-acme/win-acme/releases/download/v2.1.20.1/win-acme.v2.1.20.1185.x64.pluggable.zip"
$ExtractPath = "C:\Tools\letsencrypt_automation\letsencrypt_automation\"
$DownloadDir = "C:\temp\letsencrypt_automation\"
$LogDir = "C:\Tools\letsencrypt_automation\letsencrypt_automation_logs"

# Get the time and date for logging purposes
$timestamp = Get-Date -Format FileDateTime

Function LogWrite
{
   Param ([string]$logstring)

   Add-content "$LogDir\$timestamp-automation_transcript.txt" -value $logstring
   Write-Host $logstring
}

Function Unlock
{
  # Cleanup lock file
  Remove-Item $lockfile -Force | Out-Null
}

# Loop that runs until we have exclusive write access to $LockFile
$LockFile = "C:\Temp\run.lock"
$sleeptime = 60

If (!(Test-Path -PathType Container -Path $LockFile)) {
  New-Item -ItemType Directory -Force -Path C:\Temp | Out-Null
}


While(Test-Path -Path $lockfile)
{
    Write-Host "! [WARNING] LOCKFILE Found!"
    Write-Host "This means this task is being used by another process"
    Write-Host "Wait for file to be deleted/released"
    Write-Host "Sleeping for $sleeptime seconds (feel free to cancel script)"
    Start-Sleep $sleeptime -Verbose
}

# Active LOCKFILE preventing this script from running in another process
New-item -Path $lockfile | Out-Null

# check if wacs.exe process is running.
$process = Get-Process wacs -ErrorAction SilentlyContinue
if ($null -ne $process) {
  LogWrite "- [ERROR] wacs.exe is running. Stopping script."
  Unlock
  exit
}

# Do cleanup
$oldFolders = "C:\Tools\letsencrypt\letsencrypt_automation", "C:\Tools\letsencrypt\letsencrypt_automation_logs"

foreach ($FolderName in $oldFolders) {
  if (Test-Path $FolderName) {
 
    Write-Host "$FolderName Exists"
    Remove-Item $FolderName -Force -Recurse
  }
  else
  {
      Write-Host "$FolderName Doesn't Exists"
  }
}

try {
    Import-Module WebAdministration -ErrorAction SilentlyContinue | Out-Null
    Import-Module IISAdministration -ErrorAction SilentlyContinue | Out-Null
  }
  catch {
    LogWrite "- [ERROR] Unable to load powershell libraries"
    Unlock
    exit
  }
  
  If (!(test-path $ExtractPath)) {
    New-Item -ItemType Directory -Force -Path $ExtractPath | Out-Null
  }
  
  If (!(test-path $DownloadDir)) {
    New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null
  }
  
  If (!(test-path $LogDir)) {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
  }
  
# Download, extract and replace current version
if (!(test-path $ExtractPath))
{
  try {
    $Url = $Package
    LogWrite "+ [INFO] Downloading Lets Encrypt from:"
    LogWrite "+ [Download URL] $Url"
    $DownloadZipFile = $DownloadDir + $(Split-Path -Path $Url -Leaf)
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Url -OutFile $DownloadZipFile
    $ExtractShell = New-Object -ComObject Shell.Application 
    $ExtractFiles = $ExtractShell.Namespace($DownloadZipFile).Items() 
    $ExtractShell.NameSpace($ExtractPath).CopyHere($ExtractFiles)
    Remove-Item -Path $DownloadZipFile -Confirm:$false -Force | Out-Null
  }
  catch {
    LogWrite "- [ERROR] Unable to Download/Update Lets Encrypt Packages from $Url"
    Unlock
    exit 1
  }
} else {
  LogWrite "+ [INFO] Lets's Encrypt already exists!"
}
  
  # Update default settings for win-acme to redirect logs
  LogWrite "+ [INFO] Update Lets Encrypt Configuration to fit our needs"
  $configFiles = Get-ChildItem -File -Path "$ExtractPath\*" -include settings_default.json
  foreach ($file in $configFiles) { 
    (Get-Content $file.PSPath) | Foreach-Object { 
      $_ -replace '"LogPath": null,', '"LogPath": "C:\\Tools\\letsencrypt_automation\\letsencrypt_automation_logs",' 
    } | Set-Content $file.PSPath
  }

# Disable all previous/old scheduled task for letsencrypt and create new one based on latest version.
LogWrite "+ [INFO] Clean up scheduled tasks and update them to make sure we are compliant with the selected version."
Get-ScheduledTask | Select-Object -Property * | Where-Object { $_.Description -like '*Lets Encrypt*' -or $_.Description -like '*ACME*' } | ForEach-Object { Disable-ScheduledTask -TaskName $_.TaskName -ErrorAction SilentlyContinue } | Out-Null
Start-Process -FilePath "$ExtractPath\wacs.exe" -WorkingDirectory "$ExtractPath" -ArgumentList "--setuptaskscheduler" -Wait

Unlock
