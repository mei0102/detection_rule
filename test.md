Import-Module ActiveDirectory

$targetUser = "dcsync-operator"
$domainDn   = (Get-ADDomain).DistinguishedName
$aclPath    = "AD:\$domainDn"

$target = Get-ADUser -Identity $targetUser -ErrorAction Stop
$acl    = Get-Acl -Path $aclPath

$rights = @(
    @{
        Name = "Replicating Directory Changes"
        Guid = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    },
    @{
        Name = "Replicating Directory Changes All"
        Guid = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    }
)

foreach ($right in $rights) {
    $rule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
        $target.SID,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $right.Guid
    )

    [void]$acl.AddAccessRule($rule)
    Write-Host "Staged: $($right.Name)"
}

# ここで初めて2権限を同時に反映
Set-Acl -Path $aclPath -AclObject $acl

Write-Host "Granted both replication rights to $targetUser"
