Import-Module ExchangeOnlineManagement

$ApplicationId = $($ENV:ApplicationId)
$TenantID = $($ENV:TenantID)

$RefreshToken = $($ENV:RefreshToken)
$CredentialPwd = ConvertTo-SecureString "$($ENV:CredentialPwd)" -AsPlainText -Force

$Credential = New-Object System.Management.Automation.PSCredential ("$ENV:CredentialUser", $CredentialPwd)
$ExchangeRefreshToken = $($ENV:ExchangeRefreshToken)

$upn = $($ENV:upn)

$AlertEmail = $($ENV:MalwareSpamEmail)

$aadGraphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.windows.net/.default' -ServicePrincipal -Tenant $tenantID 
$graphToken = New-PartnerAccessToken -ApplicationId $ApplicationId -Credential $credential -RefreshToken $refreshToken -Scopes 'https://graph.microsoft.com/.default' -ServicePrincipal -Tenant $tenantID 

Connect-MsolService -AdGraphAccessToken $aadGraphToken.AccessToken -MsGraphAccessToken $graphToken.AccessToken

$excludeTenants = Get-Content c:\jenkins-files\exclude-tenants.txt
$customers = Get-MsolPartnerContract -All | Where-Object { $_.DefaultDomainName -notin $excludeTenants }

foreach ($customer in $customers) {
    $customerId = $customer.DefaultDomainName
    try {
        $token = New-PartnerAccessToken -ApplicationId 'a0c73c16-a7e3-4564-9a95-2bdf47383716'-RefreshToken $ExchangeRefreshToken -Scopes 'https://outlook.office365.com/.default' -Tenant $customer.TenantId -ErrorAction Stop
    }
    catch {
        "Skipping - Unable to create a Partner Access Token on $customerId"
        continue
    }

    $tokenValue = ConvertTo-SecureString "Bearer $($token.AccessToken)" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($upn, $tokenValue)
        
    try {
        $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri "https://ps.outlook.com/powershell-liveid?DelegatedOrg=$($customerId)&amp;BasicAuthToOAuthConversion=true" -Credential $credential -Authentication Basic -AllowRedirection -ErrorAction Stop
    }
    catch {
        "Skipping - Unable to connect to Exchange on $customerId"
        continue
    }
    
    Import-PSSession $session

    try {
        #set the default Hosted Content Filter (anti-spam) policy
        Write-Host "Setting up spam filter policy on $customerId"
        Set-HostedContentFilterPolicy -Identity "Default" -BulkSpamAction "MovetoJmf" -BulkThreshold "7" -EnableEndUserSpamNotifications $true -EndUserSpamNotificationFrequency 1 -HighConfidencePhishAction "Quarantine" -HighConfidenceSpamAction "Quarantine" -InlineSafetyTipsEnabled $true -MarkAsSpamBulkMail "On" -PhishSpamAction "MoveToJmf" -PhishZapEnabled $true -QuarantineRetentionPeriod "30" -SpamAction "MoveToJmf" -SpamZapEnabled $true
    }
    catch {
        Write-Host "Unable to set up spam filter on $customerid"
        Write-Host $_.Exception.Message
    }

    try {
        $PhishPolicy = (Get-AntiPhishPolicy | Where-Object { $_.Identity -match "Default" }).Identity
        #this will only work for orgs with Defender enabled
        Set-AntiphishPolicy -Identity $PhishPolicy -AuthenticationFailAction "Quarantine" -Enabled $true -EnableFirstContactSafetyTips $true -EnableMailboxIntelligenceProtection $true -EnableOrganizationDomainsProtection $true -EnableSimilarDomainsSafetyTips $true -EnableSimilarUsersSafetyTips $true -EnableSpoofIntelligence $true -EnableUnauthenticatedSender $true -EnableUnusualCharactersSafetyTips $true -EnableViaTag $true -MailboxIntelligenceProtectionAction "Quarantine" -PhishThresholdLevel "1" -TargetedDomainProtectionAction "Quarantine" 
        Write-Host "Setting up Phishing policy (with Defender) for $customerid"
    }
    catch {
        #anti-phish policy for orgs without Defender
        Set-AntiphishPolicy -Identity $PhishPolicy -AuthenticationFailAction "Quarantine" -Enabled $true -EnableFirstContactSafetyTips $true -EnableSpoofIntelligence $true -EnableUnauthenticatedSender $true -EnableViaTag $true
        Write-Host "Setting up Phishing policy (without Defender) for $customerid"
        Write-Host $_.Exception.Message
    }

    try {
        #anti-malware for orgs with Defender
        $FileTypes = @("ace", "ani", "app", "docm", "exe", "jar", "reg", "scr", "vbe", "vbs", "ade", "adp", "asp", "bas", "bat", "cer", "chm", "cmd", "com", "cpl", "crt", "csh", "der", "dll", "dos", "fxp", "gadget", "hlp", "Hta", "Inf", "Ins", "Isp", "Its", "js", "Jse", "Ksh", "Lnk", "mad", "maf", "mag", "mam", "maq", "mar", "mas", "mat", "mau", "mav", "maw", "mda", "mdb", "mde", "mdt", "mdw", "mdz", "msc", "msh", "msh1", "msh1xml", "msh2", "msh2xml", "mshxml", "msi", "msp", "mst", "obj", "ops", "os2", "pcd", "pif", "plg", "prf", "prg", "ps1", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "pst", "scf", "sct", "shb", "shs", "tmp", "url", "vb", "vsmacros", "vsw", "vxd", "w16", "ws", "wsc", "wsf", "wsh", "xnk")
        Set-MalwareFilterPolicy -Identity "Default" -Action "DeleteAttachmentAndUseDefaultAlert" -CustomNotifications $False -InternalSenderAdminAddress $AlertEmail -EnableInternalSenderNotifications $True -EnableExternalSenderNotifications $True -EnableInternalSenderAdminNotifications $True -EnableExternalSenderAdminNotifications $False -EnableFileFilter $True -FileTypes $FileTypes -ZapEnabled $True
        Write-Host "Setting up Malware policy for $customerId"
    }
    catch {
        Write-Host "$customerId does not have a Defender license. Can't enable Malware policy"
        Write-Host $_.Exception.Message
    }

    Remove-PSSession $session
}