#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Bulk modify Active Directory users from CSV input with full audit logging.

.DESCRIPTION
    Modifies AD users (edit attributes, disable, delete/review) based on CSV.
    Logs all actions: old/new values, changes, errors. Safe WhatIf mode.
    
    CSV format (English column names):
    action,samAccountName,description,displayName,upn,jobTitle,department,company,manager,targetOU
    
    Actions: "keep" (edit), "disable" (edit+disable), "delete" (disable first), "review"
    
    Example:
    action,samAccountName,description,displayName
    keep,user1,New IT Support,User One (IT)

.PARAMETER Execute
    Actually perform changes (default: WhatIf dry-run)

.EXAMPLE
    .\AD-Bulk-Modify.ps1          # Dry run
    .\AD-Bulk-Modify.ps1 -Execute # Real changes

.NOTES
    Author: @florian1744
    Version: 2.0 
#>

param([switch]$Execute)

$WhatIfPreference = -not $Execute

# Configuration Region
#region CONFIG
$InputCsvPath = ".\input.csv"  # Change to your CSV
#endregion CONFIG

# Safe path handling + logging
$inputCsvFileName = [System.IO.Path]::GetFileNameWithoutExtension($InputCsvPath)
$logDir = ".\_logs"
$null = New-Item -Path $logDir -ItemType Directory -Force
$LogCsv = "$logDir\ad_log_$inputCsvFileName_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"

Import-Module ActiveDirectory
$users = Import-Csv $InputCsvPath -Delimiter "," -Encoding UTF8
$log = [System.Collections.Generic.List[object]]::new()  # Efficient logging

function Set-AdUserFieldIfChanged {
    <#
    .SYNOPSIS
        Safely set AD user field only if changed.
    #>
    param(
        [string]$SamAccountName,
        [string]$FieldLabel,
        $OldValue,
        $NewValue,
        [scriptblock]$Setter
    )
    if ($null -eq $NewValue -or [string]::IsNullOrWhiteSpace([string]$NewValue) -or
        $NewValue -match '^#' -or $NewValue -eq '0') {
        return $false
    }
    if ($NewValue -ne $OldValue) {
        & $Setter $SamAccountName $NewValue
        return $true
    }
    return $false
}

function Update-UserAttributes {
    param($SamAccountName, $User, $Entry)
    # Common attribute updates (de-duplicated)
    $descChanged = Set-AdUserFieldIfChanged -SamAccountName $SamAccountName -FieldLabel "Description" `
        -OldValue $User.Description -NewValue $Entry.description `
        -Setter { param($s,$v) Set-ADUser -Identity $s -Description $v -ErrorAction Stop }

    $displayChanged = Set-AdUserFieldIfChanged -SamAccountName $SamAccountName -FieldLabel "DisplayName" `
        -OldValue $User.DisplayName -NewValue $Entry.displayName `
        -Setter { param($s,$v) Set-ADUser -Identity $s -DisplayName $v -ErrorAction Stop }

    Set-AdUserFieldIfChanged -SamAccountName $SamAccountName -FieldLabel "UserPrincipalName" `
        -OldValue $User.UserPrincipalName -NewValue $Entry.upn `
        -Setter { param($s,$v) Set-ADUser -Identity $s -UserPrincipalName $v -ErrorAction Stop } | Out-Null

    Set-AdUserFieldIfChanged -SamAccountName $SamAccountName -FieldLabel "Title" `
        -OldValue $User.Title -NewValue $Entry.jobTitle `
        -Setter { param($s,$v) Set-ADUser -Identity $s -Title $v -ErrorAction Stop } | Out-Null

    Set-AdUserFieldIfChanged -SamAccountName $SamAccountName -FieldLabel "Department" `
        -OldValue $User.Department -NewValue $Entry.department `
        -Setter { param($s,$v) Set-ADUser -Identity $s -Department $v -ErrorAction Stop } | Out-Null

    Set-AdUserFieldIfChanged -SamAccountName $SamAccountName -FieldLabel "Company" `
        -OldValue $User.Company -NewValue $Entry.company `
        -Setter { param($s,$v) Set-ADUser -Identity $s -Company $v -ErrorAction Stop } | Out-Null
}

function Get-NewDistinguishedName {
    param([string]$SamAccountName, [string]$OldDistinguishedName)
    try {
        $userAfter = Get-ADUser -Identity $SamAccountName -Properties DistinguishedName -ErrorAction Stop
        return [PSCustomObject]@{
            DistinguishedName = $userAfter.DistinguishedName
            DistinguishedNameChanged = ($userAfter.DistinguishedName -ne $OldDistinguishedName)
        }
    }
    catch {
        return [PSCustomObject]@{ DistinguishedName = $OldDistinguishedName; DistinguishedNameChanged = $false }
    }
}

foreach ($entry in $users) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $sam = $entry.samAccountName
    $action = $entry.action.ToLower().Trim()

    $executedAction = "None"
    $result = "Success"
    $errorMessage = ""

    try {
        if ([string]::IsNullOrWhiteSpace($sam)) {
            throw "Missing samAccountName in CSV row."
        }

        $user = Get-ADUser -Identity $sam -Properties Description,DisplayName,DistinguishedName,
            UserPrincipalName,Department,Title,Company,Manager -ErrorAction Stop

        # Update attributes (common for keep/disable)
        Update-UserAttributes -SamAccountName $sam -User $user -Entry $entry

        $dnResult = Get-NewDistinguishedName -SamAccountName $sam -OldDistinguishedName $user.DistinguishedName

        switch ($action) {
            "keep" { 
                $executedAction = "Edited attributes"
            }
            "disable" { 
                Disable-ADAccount -Identity $sam -ErrorAction Stop
                $executedAction = "Disabled + edited"
            }
            "delete" { 
                Disable-ADAccount -Identity $sam -ErrorAction Stop  # Safe: disable first
                $executedAction = "Disabled (ready for delete)"
            }
            "review" { 
                $executedAction = "Review mode"
            }
            default { 
                $result = "Skipped"; $executedAction = "Unknown action: $action"
            }
        }
    }
    catch {
        $result = "Error"
        $errorMessage = $_.Exception.Message
    }

    # Efficient log append
    $log.Add([PSCustomObject]@{
        Timestamp = $timestamp
        SamAccountName = $sam
        ActionCSV = $action
        DescriptionOld = $user?.Description
        DescriptionNew = $entry.description
        DescriptionChanged = $descChanged
        DisplayNameOld = $user?.DisplayName
        DisplayNameNew = $entry.displayName
        DisplayNameChanged = $displayChanged
        DistinguishedNameOld = $user?.DistinguishedName
        DistinguishedNameNew = $dnResult.DistinguishedName
        DistinguishedNameChanged = $dnResult.DistinguishedNameChanged
        UserPrincipalNameOld = $user?.UserPrincipalName
        UserPrincipalNameNew = $entry.upn
        UserPrincipalNameChanged = $userPrincipalNameChanged  
        JobTitleOld = $user?.Title
        JobTitleNew = $entry.jobTitle
        JobTitleChanged = $jobTitleChanged
        DepartmentOld = $user?.Department
        DepartmentNew = $entry.department
        DepartmentChanged = $departmentChanged
        CompanyOld = $user?.Company
        CompanyNew = $entry.company
        CompanyChanged = $companyChanged
        ExecutedAction = $executedAction
        Result = $result
        ErrorMessage = $errorMessage
        WhatIfMode = [bool]$WhatIfPreference
    })
}

# Finalize
$WhatIfPreference = $false
$log | Export-Csv -Path $LogCsv -NoTypeInformation -Encoding UTF8
Write-Host "Done. Log saved to: $LogCsv" -ForegroundColor Green
