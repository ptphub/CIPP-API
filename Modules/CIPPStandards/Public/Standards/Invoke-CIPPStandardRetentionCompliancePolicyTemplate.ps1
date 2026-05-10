function Invoke-CIPPStandardRetentionCompliancePolicyTemplate {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) RetentionCompliancePolicyTemplate
    .SYNOPSIS
        (Label) Retention Compliance Policy Template
    .DESCRIPTION
        (Helptext) Deploy Microsoft Purview retention compliance policies from CIPP templates. Existing policies and rules are overwritten in place.
        (DocsDescription) Deploy Microsoft Purview retention compliance policies from CIPP templates. If a policy or rule with the same name already exists in the tenant, it is updated in place; otherwise it is created. Uses the application token to bypass GDAP delegated-identity restrictions on retention cmdlets.
    .NOTES
        MULTI
            True
        CAT
            Templates
        DISABLEDFEATURES
            {"report":false,"warn":false,"remediate":false}
        IMPACT
            Medium Impact
        ADDEDDATE
            2026-05-10
        EXECUTIVETEXT
            Deploys retention policies that govern how long content is preserved in Exchange, SharePoint, OneDrive, and Teams. Enforces consistent compliance retention across tenants for regulatory and legal hold needs.
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":true,"creatable":false,"name":"retentionCompliancePolicyTemplate","label":"Select Retention Compliance Policy Templates","api":{"url":"/api/ListRetentionCompliancePolicyTemplates","labelField":"name","valueField":"GUID","queryKey":"ListRetentionCompliancePolicyTemplates"}}
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>
    param($Tenant, $Settings)

    # Static-scope parameter set only. AdaptiveScopeLocation defines a separate parameter set and would
    # cause "Multiple parameter sets are applicable" if mixed with the static locations.
    $PolicyAllowedFields = @(
        'Name', 'Comment', 'Enabled', 'RestrictiveRetention',
        'ExchangeLocation', 'ExchangeLocationException',
        'SharePointLocation', 'SharePointLocationException',
        'OneDriveLocation', 'OneDriveLocationException',
        'ModernGroupLocation', 'ModernGroupLocationException',
        'TeamsChannelLocation', 'TeamsChannelLocationException',
        'TeamsChatLocation', 'TeamsChatLocationException',
        'PublicFolderLocation',
        'SkypeLocation', 'SkypeLocationException'
    )

    $RequiredOneOfLocations = @(
        'ExchangeLocation', 'SharePointLocation', 'OneDriveLocation', 'ModernGroupLocation',
        'TeamsChannelLocation', 'TeamsChatLocation', 'PublicFolderLocation', 'SkypeLocation'
    )

    # Rules use a different cmdlet with its own param set
    $RuleAllowedFields = @(
        'Name', 'Policy', 'Comment',
        'RetentionDuration', 'RetentionComplianceAction',
        'ExpirationDateOption', 'PublishComplianceTag',
        'ApplyComplianceTag', 'ContentMatchQuery',
        'ContentDateFrom', 'ContentDateTo'
    )

    $LocationProperties = @(
        'ExchangeLocation', 'ExchangeLocationException',
        'SharePointLocation', 'SharePointLocationException',
        'OneDriveLocation', 'OneDriveLocationException',
        'ModernGroupLocation', 'ModernGroupLocationException',
        'TeamsChannelLocation', 'TeamsChannelLocationException',
        'TeamsChatLocation', 'TeamsChatLocationException',
        'PublicFolderLocation',
        'SkypeLocation', 'SkypeLocationException'
    )

    function ConvertTo-LocationValue {
        param($Value)
        if ($null -eq $Value) { return $null }
        if ($Value -is [string]) { return $Value }
        $items = @($Value) | ForEach-Object {
            if ($null -eq $_) { return }
            if ($_ -is [string]) { $_ }
            elseif ($_.Name) { $_.Name }
            elseif ($_.PrimarySmtpAddress) { $_.PrimarySmtpAddress }
            elseif ($_.DisplayName) { $_.DisplayName }
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        if ($items.Count -eq 0) { return $null }
        if ($items -contains 'All') { return 'All' }
        return @($items)
    }

    function ConvertTo-CleanFromAllowlist {
        param($Source, [string[]]$Allowed, [string[]]$Locations)
        $clean = @{}
        foreach ($prop in $Source.PSObject.Properties) {
            if ($prop.Name -notin $Allowed) { continue }
            $val = $prop.Value
            if ($null -eq $val) { continue }
            if ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) { continue }
            if (($val -is [array] -or $val -is [System.Collections.IList]) -and @($val).Count -eq 0) { continue }
            if ($Locations -and $prop.Name -in $Locations) {
                $normalized = ConvertTo-LocationValue -Value $val
                if ($null -eq $normalized) { continue }
                $clean[$prop.Name] = $normalized
            } else {
                $clean[$prop.Name] = $val
            }
        }
        return $clean
    }

    $TemplateSelection = $Settings.retentionCompliancePolicyTemplate ?? $Settings.TemplateList ?? $Settings.'standards.RetentionCompliancePolicyTemplate.TemplateIds'
    $TemplateIds = @($TemplateSelection | ForEach-Object {
            if ($_ -is [string]) { $_ } elseif ($_.value) { $_.value } else { $null }
        }) | Where-Object { $_ }

    if (-not $TemplateIds -or $TemplateIds.Count -eq 0) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message 'No retention compliance policy templates selected.' -sev Error
        return
    }

    $Table = Get-CippTable -tablename 'templates'
    $Filter = "PartitionKey eq 'RetentionCompliancePolicyTemplate' and (RowKey eq '$($TemplateIds -join "' or RowKey eq '")')"
    $Templates = (Get-CIPPAzDataTableEntity @Table -Filter $Filter).JSON | ConvertFrom-Json

    if (-not $Templates) {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message 'No retention compliance policy templates resolved from the selected IDs.' -sev Error
        return
    }

    try {
        $ExistingPolicies = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-RetentionCompliancePolicy' -Compliance -AsApp | Select-Object Name
    } catch {
        $ExistingPolicies = @()
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "Could not list existing retention compliance policies: $($_.Exception.Message)" -sev Warning
    }

    try {
        $ExistingRules = New-ExoRequest -tenantid $Tenant -cmdlet 'Get-RetentionComplianceRule' -Compliance -AsApp | Select-Object Name, Policy
    } catch {
        $ExistingRules = @()
        Write-LogMessage -API 'Standards' -tenant $Tenant -message "Could not list existing retention compliance rules: $($_.Exception.Message)" -sev Warning
    }

    if ($Settings.remediate -eq $true) {
        foreach ($Template in @($Templates)) {
            $TemplateName = $Template.Name ?? $Template.name
            try {
                $PolicyParams = ConvertTo-CleanFromAllowlist -Source $Template -Allowed $PolicyAllowedFields -Locations $LocationProperties

                # Reconstruct empty locations from the Workload string when needed (legacy templates from Get-*)
                $HasLocation = $false
                foreach ($loc in $RequiredOneOfLocations) {
                    if ($PolicyParams.ContainsKey($loc)) { $HasLocation = $true; break }
                }
                if (-not $HasLocation -and $Template.Workload) {
                    $workloads = ($Template.Workload -split ',') | ForEach-Object { $_.Trim() }
                    $map = @{
                        'Exchange'            = 'ExchangeLocation'
                        'SharePoint'          = 'SharePointLocation'
                        'OneDriveForBusiness' = 'OneDriveLocation'
                        'Skype'               = 'SkypeLocation'
                        'ModernGroup'         = 'ModernGroupLocation'
                        'PublicFolder'        = 'PublicFolderLocation'
                    }
                    foreach ($wl in $workloads) {
                        if ($map.ContainsKey($wl) -and -not $PolicyParams.ContainsKey($map[$wl])) {
                            $PolicyParams[$map[$wl]] = 'All'; $HasLocation = $true
                        }
                    }
                    if ('Teams' -in $workloads) {
                        if (-not $PolicyParams.ContainsKey('TeamsChatLocation')) { $PolicyParams['TeamsChatLocation'] = 'All'; $HasLocation = $true }
                        if (-not $PolicyParams.ContainsKey('TeamsChannelLocation')) { $PolicyParams['TeamsChannelLocation'] = 'All'; $HasLocation = $true }
                    }
                }
                # Last-ditch fallback for legacy templates that have neither locations nor a Workload string.
                if (-not $HasLocation) {
                    $PolicyParams['ExchangeLocation'] = 'All'
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Retention compliance policy template '$TemplateName' has no location info — defaulting to ExchangeLocation = 'All'. Edit the template to scope it more narrowly." -sev Warning
                }

                $PolicyExists = [bool]($ExistingPolicies | Where-Object { $_.Name -eq $TemplateName })

                if ($PolicyExists) {
                    $SetParams = @{} + $PolicyParams
                    $SetParams.Remove('Name')
                    $SetParams['Identity'] = $TemplateName
                    $null = New-ExoRequest -tenantid $Tenant -cmdlet 'Set-RetentionCompliancePolicy' -cmdParams $SetParams -Compliance -AsApp -useSystemMailbox $true
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Updated retention compliance policy '$TemplateName' in place" -sev Info
                } else {
                    $null = New-ExoRequest -tenantid $Tenant -cmdlet 'New-RetentionCompliancePolicy' -cmdParams $PolicyParams -Compliance -AsApp -useSystemMailbox $true
                    Write-LogMessage -API 'Standards' -tenant $Tenant -message "Created retention compliance policy '$TemplateName'" -sev Info
                }

                $RuleSource = $Template.RuleParams
                if ($RuleSource) {
                    $RuleHash = ConvertTo-CleanFromAllowlist -Source $RuleSource -Allowed $RuleAllowedFields
                    $RuleHash['Policy'] = $TemplateName
                    $RuleName = if ($RuleHash.ContainsKey('Name') -and -not [string]::IsNullOrWhiteSpace([string]$RuleHash['Name'])) {
                        $RuleHash['Name']
                    } else {
                        "$TemplateName Rule"
                    }
                    $RuleHash['Name'] = $RuleName

                    $RuleExists = [bool]($ExistingRules | Where-Object { $_.Name -eq $RuleName -or $_.Policy -eq $TemplateName })

                    if ($RuleExists) {
                        $SetRuleHash = @{} + $RuleHash
                        $SetRuleHash.Remove('Name')
                        $SetRuleHash.Remove('Policy')
                        $SetRuleHash['Identity'] = $RuleName
                        $null = New-ExoRequest -tenantid $Tenant -cmdlet 'Set-RetentionComplianceRule' -cmdParams $SetRuleHash -Compliance -AsApp -useSystemMailbox $true
                        Write-LogMessage -API 'Standards' -tenant $Tenant -message "Updated retention rule '$RuleName' for policy '$TemplateName'" -sev Info
                    } else {
                        $null = New-ExoRequest -tenantid $Tenant -cmdlet 'New-RetentionComplianceRule' -cmdParams $RuleHash -Compliance -AsApp -useSystemMailbox $true
                        Write-LogMessage -API 'Standards' -tenant $Tenant -message "Created retention rule '$RuleName' for policy '$TemplateName'" -sev Info
                    }
                }
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to deploy retention compliance policy '$TemplateName'. Error: $ErrorMessage" -sev Error
            }
        }
    }

    # Compute missing list once for both alert and report
    $MissingPolicies = foreach ($Template in @($Templates)) {
        $TemplateName = $Template.Name ?? $Template.name
        if (-not ($ExistingPolicies | Where-Object { $_.Name -eq $TemplateName })) { $TemplateName }
    }
    $MissingPolicies = @($MissingPolicies)

    if ($Settings.alert -eq $true) {
        if ($MissingPolicies.Count -eq 0) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message 'All selected retention compliance policy templates are deployed.' -sev Info
        } else {
            $AlertMessage = "Retention compliance policies not deployed in tenant: $($MissingPolicies -join ', ')"
            Write-StandardsAlert -message $AlertMessage -object @{ MissingPolicies = $MissingPolicies } -tenant $Tenant -standardName 'RetentionCompliancePolicyTemplate' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message $AlertMessage -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        $CurrentValue = @{ MissingPolicies = $MissingPolicies }
        $ExpectedValue = @{ MissingPolicies = @() }

        Set-CIPPStandardsCompareField -FieldName 'standards.RetentionCompliancePolicyTemplate' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
        Add-CIPPBPAField -FieldName 'RetentionCompliancePolicyTemplate' -FieldValue ($MissingPolicies.Count -eq 0) -StoreAs bool -Tenant $Tenant
    }
}
