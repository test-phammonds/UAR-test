Import-Module ActiveDirectory

$RightsGroups  = Get-ADGroup -Filter * -SearchBase "OU=Rights,OU=RBAC,DC=idanalytics,DC=net" -Properties description,info | Where-Object { $_.DistinguishedName -notlike '*OU=FS*' -and $_.DistinguishedName -notlike '*OU=Jira*'}

$AccessRights = @()
$i = 0
ForEach ($Group in $RightsGroups) {
    $Members = Get-ADGroupMember -Recursive -Identity $Group.Name | Get-ADUser -Properties employeeid,sn,employeeType | Where-Object {$_.DistinguishedName -like '*OU=InHouse*' -or $_.DistinguishedName -like '*OU=LNRS Users*' -or $_.DistinguishedName -like '*OU=Remote*' -or $_.DistinguishedName -like '*OU=Administrators*'}
    ForEach ($Member in $Members) {
            $AccessRight = [PSCustomObject]@{
            emp_id = $Member.employeeid
            emp_first_name = $Member.givenName
            emp_last_name = $Member.sn
            resource_name = "NET Domain Controller"
            resource_type = "Application"
            resource_userid = $Member.userPrincipalName
            role = $Member.employeeType
            reference = $Group.Name
            resource_group = "IDA Corp"
            business_unit = "Business Services"
            lifecycle = "NonProd"
            user_comment = $Group.description
            extract_date = $(Get-Date -format "yyyyMMdd")
        }
    $AccessRights += $AccessRight
    }
    $i = $i + 1
    Write-Progress -Activity "Enumerating Rights" -Status "Progress:" -PercentComplete (($i/$RightsGroups.Count)*100)
}

$AccessRights | Export-CSV -Path C:\Admin\scripts\user_access_reporting\$((Get-Date).ToString("yyyyMMdd"))-net-access-rights.csv -NoTypeInformation

$local = [system.net.dns]::GetHostEntry('').HostName.tolower() # get local fqdn

$from = "$local@idanalytics.com"
#$to = "priscilla.hammonds@lexisnexisrisk.com","andrew.citro@lexisnexisrisk.com","dl-ida-ets@lexisnexisrisk.com","ALP.QueueIT@lexisnexis.com","karen.newman@lexisnexisrisk.com"
$to = "priscilla.hammonds@lexisnexisrisk.com"

$subject = "aud.it:ida_net_access_rights:powershell "
$smtp = "mail.idanalytics.com"
$attachment = "C:\Admin\scripts\user_access_reporting\$((Get-Date).ToString("yyyyMMdd"))-net-access-rights.csv"

Send-Mailmessage -from $from -to $to -Subject $subject -attachment $attachment -smtp $smtp
