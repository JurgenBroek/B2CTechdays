# This script will require the Web Application and permissions setup in Azure Active Directory

Connect-MsolService
Get-MsolRole
b0f54661-2d74-4c50-afa3-1ec803f12efe
4a5d8f65-41da-4de4-8968-e035b65339cf

$sp = Get-MsolServicePrincipal -AppPrincipalId $ClientID
Add-MsolRoleMember -RoleObjectId 88d8e3e3-8f55-4a1e-953a-9b9898b8876b -RoleMemberObjectId $sp.ObjectId -RoleMemberType servicePrincipal
Add-MsolRoleMember -RoleObjectId b0f54661-2d74-4c50-afa3-1ec803f12efe -RoleMemberObjectId $sp.ObjectId -RoleMemberType servicePrincipal
Add-MsolRoleMember -RoleObjectId 4a5d8f65-41da-4de4-8968-e035b65339cf -RoleMemberObjectId $sp.ObjectId -RoleMemberType servicePrincipal
Remove-MsolRoleMember -RoleObjectId 4a5d8f65-41da-4de4-8968-e035b65339cf -RoleMemberObjectId $sp.ObjectId -RoleMemberType servicePrincipal

# Constants
$ClientID      = "d5cd0a2c-bf82-4ccf-9fba-5db8203e4dd0"  
$ClientSecret  = 'Gvm+;1{nESs93$Q\'
$loginURL      = "https://login.microsoftonline.com"
$tenantdomain  = "jurgenvandenbroek.onmicrosoft.com"
$pathToJsonFile = "C:\Users\jurge\OneDrive\Events\2017 Techdays NL\Demo\b2cUserJourneySummaryEvents.json"
$pathToOutputFile = "C:\Users\jurge\OneDrive\Events\2017 Techdays NL\Demo\b2cUserJourneySummaryEvents.csv"
# Get an Oauth 2 access token based on client id, secret and tenant domain
$body          = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
$oauth         = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body
if ($oauth.access_token -ne $null) {
    $headerParams  = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}

    Write-host Data from the tenantUserCount report
    Write-host ====================================================
     # Returns a JSON document for the report
    $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/tenantUserCount?api-version=beta")
    Write-host $myReport.Content
    $myReport.Content | Out-File -FilePath $pathToJsonFile -Force


    Write-host Data from the tenantUserCount report with datetime filter
    Write-host ====================================================
    $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/tenantUserCount?%24filter=TimeStamp+gt+2016-10-15&api-version=beta")
    Write-host $myReport.Content

    Write-host Data from the b2cAuthenticationCountSummary report
    Write-host ====================================================
    $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/b2cAuthenticationCountSummary?api-version=beta")
    Write-host $myReport.Content

    Write-host Data from the b2cAuthenticationCount report with datetime filter
    Write-host ====================================================
    $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/b2cAuthenticationCount?%24filter=TimeStamp+gt+2016-09-20+and+TimeStamp+lt+2016-10-03&api-version=beta")
    Write-host $myReport.Content

    Write-host Data from the b2cAuthenticationCount report with ApplicationId filter
    Write-host ====================================================
    # Returns a JSON document for the " " report
        $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/b2cAuthenticationCount?%24filter=ApplicationId+eq+ada78934-a6da-4e69-b816-10de0d79db1d&api-version=beta")
    Write-host $myReport.Content

    Write-host Data from the b2cMfaRequestCountSummary
    Write-host ====================================================
    $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/b2cMfaRequestCountSummary?api-version=beta")
    Write-host $myReport.Content

    Write-host Data from the b2cMfaRequestCount report with datetime filter
    Write-host ====================================================
    $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/b2cMfaRequestCount?%24filter=TimeStamp+gt+2016-09-10+and+TimeStamp+lt+2016-10-04&api-version=beta")
    Write-host $myReport.Content

    Write-host Data from the b2cMfaRequestCount report with ApplicationId filter
    Write-host ====================================================
    $myReport = (Invoke-WebRequest -Headers $headerParams -Uri "https://graph.windows.net/$tenantdomain/reports/b2cMfaRequestCountSummary?%24filter=ApplicationId+eq+ada78934-a6da-4e69-b816-10de0d79db1d&api-version=beta")
     Write-host $myReport.Content

} else {
    Write-Host "ERROR: No Access Token"
    }

    $myReport.Content | Out-File -FilePath b2cUserJourneySummaryEvents.json -Force