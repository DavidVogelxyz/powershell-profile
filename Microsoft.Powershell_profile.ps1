### PowerShell template profile
###
### Original source file:
### Version 1.03 - Tim Sneath <tim@sneath.org>
### From https://gist.github.com/timsneath/19867b12eee7fd5af2ba
###
### This file should be stored in $PROFILE.CurrentUserAllHosts
### If $PROFILE.CurrentUserAllHosts doesn't exist, you can make one with the following:
###    PS> New-Item $PROFILE.CurrentUserAllHosts -ItemType File -Force
### This will create the file and the containing subdirectory if it doesn't already
###
### As a reminder, to enable unsigned script execution of local scripts on client Windows,
### you need to run this line (or similar) from an elevated PowerShell prompt:
###   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
### This is the default policy on Windows Server 2012 R2 and above for server Windows. For
### more information about execution policies, run Get-Help about_Execution_Policies.

# Import Terminal Icons
#Import-Module -Name Terminal-Icons

# Find out if the current user identity is elevated (has admin rights)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal $identity
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# If so, and the current host is a command line, then change to red color
# as warning to user that they are operating in an elevated context
if (($host.Name -match "ConsoleHost") -and ($isAdmin)) {
     $host.UI.RawUI.BackgroundColor = "DarkRed"
     $host.PrivateData.ErrorBackgroundColor = "White"
     $host.PrivateData.ErrorForegroundColor = "DarkRed"
     Clear-Host
}

# Set up command prompt and window title. Use UNIX-style convention for identifying
# whether user is elevated (root) or not. Window title shows current version of PowerShell
# and appends [ADMIN] if appropriate for easy taskbar identification
function prompt {
    if ($isAdmin)   { "[" + (Get-Location) + "] # " }
    else            { "[" + (Get-Location) + "] $ " }
}

if ($isAdmin)       { $Host.UI.RawUI.WindowTitle += " [ADMIN]" }

$Host.UI.RawUI.WindowTitle = "PowerShell {0}" -f $PSVersionTable.PSVersion.ToString()

# We don't need these any more; they were just temporary variables to get to $isAdmin.
# Delete them to prevent cluttering up the user profile.
Remove-Variable identity
Remove-Variable principal

Function Test-CommandExists {
    Param ($command)
    $oldPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try { if (Get-Command $command) { RETURN $true } }
    Catch { Write-Host "$command does not exist"; RETURN $false }
    Finally { $ErrorActionPreference = $oldPreference }
}

#####################################################################
# ALIASES FOR TEXT EDITOR
#####################################################################

# Set `$EDITOR`
if (Test-CommandExists nvim)            { $EDITOR='nvim' }
else                                    { $EDITOR='notepad'}

# Set aliases for `$EDITOR`
Set-Alias -Name v -Value $EDITOR
Set-Alias -Name vim -Value $EDITOR

#####################################################################
# OTHER FUNCTIONS
#####################################################################

# Functions that fit on one line
function Edit-Profile                   { v $profile }
function Env:                           { Set-Location Env: }
function Get-PubIP                      { (Invoke-WebRequest http://ifconfig.me/ip).Content }
function HKCU:                          { Set-Location HKCU: }
function HKLM:                          { Set-Location HKLM: }
function export($name, $value)          { set-item -force -path "env:$name" -value $value; }
function ll                             { Get-ChildItem -Path $pwd -File }
function lsof                           { Get-Process | Select-Object -Property Name, Id, Handles | Sort-Object -Property Handles -Descending }
function md5sum                         { Get-FileHash -Algorithm MD5 $args }
function pgrep($name)                   { Get-Process $name }
function pkill($name)                   { Get-Process $name -ErrorAction SilentlyContinue | Stop-Process }
function reload-profile                 { & $profile }
function restart-wsl                    { Get-Service vmcompute | Restart-Service }
function sed($file, $find, $replace)    { (Get-Content $file).replace("$find", $replace) | Set-Content $file }
function sha1sum                        { Get-FileHash -Algorithm SHA1 $args }
function sha256sum                      { Get-FileHash -Algorithm SHA256 $args }
function touch($file)                   { "" | Out-File $file -Encoding ASCII }
function which($name)                   { Get-Command $name | Select-Object -ExpandProperty Definition }

# Simple function to start a new elevated process. If arguments are supplied then
# a single command is started with admin rights; if not then a new admin instance
# of PowerShell is started.
function admin {
    if ($args.Count -gt 0) {
       $argList = "& '" + $args + "'"
       Start-Process "$psHome\powershell.exe" -Verb runAs -ArgumentList $argList
    }

    else {
       Start-Process "$psHome\powershell.exe" -Verb runAs
    }
}

# Does the the rough equivalent of dir /s /b. For example, dirs *.png is dir /s /b *.png
function dirs {
    if ($args.Count -gt 0) {
        Get-ChildItem -Recurse -Include "$args" | Foreach-Object FullName
    }

    else {
        Get-ChildItem -Recurse | Foreach-Object FullName
    }
}

function find-file($name) {
    ls -recurse -filter "*${name}*" -ErrorAction SilentyContinue | foreach {
        $place_path = $_.directory
        echo "${place_path}\${_}"
    }
}

function grep($regex, $dir) {
    if ($dir) {
        Get-ChildItem $dir | select-string $regex
        return
    }

    $input | select-string $regex
}

function unzip ($file) {
    Write-Output("Extracting", $file, "to", $pwd)
    $fullFile = Get-ChildItem -Path $pwd -Filter .\cove.zip | ForEach-Object { $_.FullName }
    Expand-Archive -Path $fullFile -DestinationPath $pwd
}

function uptime {
    Get-WmiObject win32_operatingsystem | select csname, @{
        LABEL='LastBootUpTime';
        EXPRESSION={$_.ConverttoDateTime($_.lastbootuptime)}
    }
}

#####################################################################
# OTHER ALIASES
#####################################################################

Set-Alias -Name df -Value Get-Volume
Set-Alias -Name g -Value git

# Set UNIX-like aliases for the admin command, so sudo <command> will run the command
# with elevated rights.
Set-Alias -Name su -Value admin
Set-Alias -Name sudo -Value admin

#####################################################################
# FINAL CONFIGS
#####################################################################

# Import the Chocolatey Profile that contains the necessary code to enable
# tab-completions to function for `choco`.
# Be aware that if you are missing these lines from your profile, tab completion
# for `choco` will not function.
# See https://ch0.co/tab-completion for details.
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile))      { Import-Module "$ChocolateyProfile" }

# Initialize "oh my posh"
oh-my-posh --init --shell pwsh --config "$env:POSH_THEMES_PATH/cobalt2.omp.json" | Invoke-Expression

# Import "posh-git"
Import-Module 'C:\tools\poshgit\dahlbyk-posh-git-9bda399\src\posh-git.psd1'
