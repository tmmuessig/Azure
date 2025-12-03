<#
.SYNOPSIS
Enable Microsoft Sentinel Analytics Rules at Scale.

.DESCRIPTION
How to create and enable Microsoft Sentinel Analytics Rules at Scale using PowerShell.

.NOTES
File Name : Set-AnalyticsRules.ps1
Author    : Microsoft MVP/MCT - Charbel Nemnom
Version   : 3.1
Date      : 24-October-2022
Updated   : 13-August-2025
Requires  : PowerShell 7.4.x (Core)
Module    : Az Module

.LINK
To provide feedback or for further assistance please visit:
 https://charbelnemnom.com 

.EXAMPLE
.\Set-AnalyticsRules.ps1 -SubscriptionId "SUB-ID" -ResourceGroup "RG-NAME" -WorkspaceName "Log-Analytics" -SolutionName "Source-Name" -enableRules [Yes] -Verbose
This example will connect to your Azure account using the subscription Id specified, and then create all analytics rules from templates for the specified Microsoft Sentinel solution.
By default, all of the rules will be created in a Disabled state, however, you have the option to enable the rules at creation time by setting the parameter -enableRules [Yes].
You also have the option to exclude specific rule templates by using the -excludeRuleTemplates parameter, and you can specify the names of the templates you want to exclude.
The "Preview" and "Deprecated" rule templates can be also excluded by setting the -excludePreviewDeprecated parameter to [Yes]. This option is set to [Yes] by default.
#>

param (
    [Parameter(Position = 0, Mandatory = $true, HelpMessage = 'Enter Azure Subscription ID')]
    [string]$subscriptionId,
    [Parameter(Position = 1, Mandatory = $true, HelpMessage = 'Enter Resource Group Name where Microsoft Sentinel is deployed')]
    [string]$resourceGroupName,
    [Parameter(Position = 2, Mandatory = $true, HelpMessage = 'Enter Log Analytics Workspace Name')]
    [string]$workspaceName,    
    [Parameter(Position = 3, Mandatory = $true, HelpMessage = 'Enter Microsoft Sentinel Content Hub Solution Name')]
    [string]$solutionName,
    [Parameter(Position = 4, Mandatory = $false, HelpMessage = 'Exclude Rule Templates Names i.e: @("ABC","DEF")')]
    [ValidateNotNullOrEmpty()]
    [array]$excludeRuleTemplates,
    [Parameter(Position = 5, Mandatory = $false, HelpMessage = 'Exclude [Preview] and [Deprecated] Rule Templates [Yes/No]')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Yes", "No")]
    [String]$excludePreviewDeprecated = 'Yes',
    [Parameter(Position = 6, Mandatory = $false, HelpMessage = 'Enable Rules at Creation Time [Yes/No]')]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("Yes", "No")]
    [String]$enableRules = 'No'
)

#! Install Az Module If Needed
function Install-Module-If-Needed {
    param([string]$ModuleName)
 
    if (Get-Module -ListAvailable -Name $ModuleName) {
        Write-Host "Module '$($ModuleName)' already exists, continue..." -ForegroundColor Green
    } 
    else {
        Write-Host "Module '$($ModuleName)' does not exist, installing..." -ForegroundColor Yellow
        Install-Module $ModuleName -Force  -AllowClobber -ErrorAction Stop
        Write-Host "Module '$($ModuleName)' installed." -ForegroundColor Green
    }
}

#! Install Az Accounts Module If Needed
Install-Module-If-Needed Az.Accounts

#! Check Azure Connection
Try { 
    Write-Verbose "Connecting to Azure Cloud..." 
    Connect-AzAccount -ErrorAction Stop | Out-Null 
}
Catch { 
    Write-Warning "Cannot connect to Azure Cloud. Please check your credentials. Exiting!" 
    Break 
}

# Define the Preview API Version to use for Microsoft Sentinel
# The Preview API Version is needed to include the MITRE ATT&CK "Sub techniques"
$apiVersion = "?api-version=2025-01-01-preview"

# Create the authentication access token
Write-Verbose "Creating authentication access token..."
$context = Get-AzContext
if (-not $context) {
    throw "No Azure context found. Please re-authenticate."
} 
$tokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, "https://management.azure.com/")
if (-not $tokenRequest) {
    throw "Failed to obtain access token. Please check your authentication."
}
$AzureAccessToken = $tokenRequest.AccessToken
$authHeader = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$authHeader.Add("Content-Type", "application/json")
$authHeader.Add("Authorization", "Bearer $AzureAccessToken")

# Get Content Product Packages
$contentURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentProductPackages$($apiVersion)"
$contentResponse = (Invoke-RestMethod $contentURI -Method 'GET' -Headers $authHeader).value
$solutions = $contentResponse | Where-Object { $null -ne $_.properties.version }
$solution = ($solutions | Where-Object { $_.properties.displayName -eq "$solutionName" }).properties.contentId

# Get Content Templates
$contentURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates$($apiVersion)"
$contentResponse = (Invoke-RestMethod $contentURI -Method 'GET' -Headers $authHeader).value

try {
    $contentTemplates = $contentResponse | Where-Object { $_.properties.packageId -eq $solution -and $_.properties.contentKind -eq "AnalyticsRule" }
    if ($contentTemplates.count -eq 0) {
        throw "Solution Name: [$solutionName] cannot be found. Please check the solution name and Install it from the Content Hub blade"
    }
}
catch {
    Write-Error $_ -ErrorAction Stop
}

if ($excludePreviewDeprecated -eq 'Yes') {
    Write-Verbose "Excluding Preview and Deprecated Rule Templates"

    $contentTemplatesExcluded = $contentTemplates | Where-Object {
        $_.properties.displayName -notmatch '^(Preview|Deprecated)' -and
        $_.properties.displayName -notmatch '\[Preview\]' -and
        $_.properties.displayName -notmatch '\[Deprecated\]'
    }

    if ($contentTemplatesExcluded.Count -ne $contentTemplates.Count) {
        Write-Verbose "$($contentTemplates.Count - $contentTemplatesExcluded.Count) Analytic Rule(s) were excluded for: [$solutionName]"
        $contentTemplates = $contentTemplatesExcluded
    }
    else {
        Write-Verbose "No Preview and Deprecated Analytic Rules were excluded for: [$solutionName]"
    }
}

if ($excludeRuleTemplates) {
    Write-Verbose "Excluding Rule Templates: $($excludeRuleTemplates -join ', ')"
    foreach ($ruleTemplate in $excludeRuleTemplates) {
        $contentTemplates = $contentTemplates | Where-Object { $_.properties.displayname -ne "$ruleTemplate" }
    }
}

Write-Verbose "$($contentTemplates.count) Analytic Rules found for: [$solutionName]"

foreach ($contentTemplate in $contentTemplates) {
    $ruleName = $contentTemplate.name
    $ruleTemplateURI = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/contentTemplates/$($ruleName)$($apiVersion)"
    $ruleResponse = Invoke-RestMethod $ruleTemplateURI -Method 'GET' -Headers $authHeader -Verbose:$false    
        
    $ruleProperties = $ruleResponse.properties.mainTemplate.resources | Where-Object type -eq 'Microsoft.OperationalInsights/workspaces/providers/metadata' | Select-Object properties     
    $ruleProperties.properties = $ruleProperties.properties | Select-Object * -ExcludeProperty description, parentId 

    $rule = $ruleResponse.properties.mainTemplate.resources | Where-Object type -eq 'Microsoft.SecurityInsights/AlertRuleTemplates'
    $rule.properties | Add-Member -NotePropertyName alertRuleTemplateName -NotePropertyValue $rule.name
    $rule.properties | Add-Member -NotePropertyName templateVersion -NotePropertyValue $ruleResponse.properties.version    

    # Fix Grouping Configuration 
    if ($rule.properties.PSObject.Properties.Name -contains "incidentConfiguration") {
        if ($rule.properties.incidentConfiguration.PSObject.Properties.Name -contains "groupingConfiguration") {
            if (-not $rule.properties.incidentConfiguration.groupingConfiguration) {
                $rule.properties.incidentConfiguration | Add-Member -NotePropertyName "groupingConfiguration" -NotePropertyValue @{
                    matchingMethod   = "AllEntities"
                    lookbackDuration = "PT1H"
                }
            }
            else {
                # Ensure `matchingMethod` exists
                if (-not ($rule.properties.incidentConfiguration.groupingConfiguration.PSObject.Properties.Name -contains "matchingMethod")) {
                    $rule.properties.incidentConfiguration.groupingConfiguration | Add-Member -NotePropertyName "matchingMethod" -NotePropertyValue "AllEntities"
                }

                # Ensure `lookbackDuration` is in ISO 8601 format
                if ($rule.properties.incidentConfiguration.groupingConfiguration.PSObject.Properties.Name -contains "lookbackDuration") {
                    $lookbackDuration = $rule.properties.incidentConfiguration.groupingConfiguration.lookbackDuration
                    if ($lookbackDuration -match "^(\d+)(h|d|m)$") {
                        $timeValue = $matches[1]
                        $timeUnit = $matches[2]
                        switch ($timeUnit) {
                            "h" { $isoDuration = "PT${timeValue}H" }
                            "d" { $isoDuration = "P${timeValue}D" }
                            "m" { $isoDuration = "PT${timeValue}M" }
                        }
                        $rule.properties.incidentConfiguration.groupingConfiguration.lookbackDuration = $isoDuration
                    }
                }
            }
        }
    }

    If ($enableRules -eq "Yes") {
        $rule.properties.enabled = $true
    }    

    $rulePayload = $rule | ConvertTo-Json -EnumsAsStrings -Depth 50
    $ruleURI = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/alertRules/$($rule.name)$($apiVersion)"    
    try {        
        $ruleResult = Invoke-AzRestMethod -Method PUT -path $ruleURI -Payload $rulePayload -Verbose:$false

        If (!($ruleResult.StatusCode -in 200, 201)) {
            Write-Host $ruleResult.StatusCode
            Write-Host $ruleResult.Content
            throw "Error when enabling Analytics rule: $($rule.properties.displayName)"
        }        
        If ($enableRules -eq "Yes") {
            Write-Verbose "Creating and Enabling Analytic rule: $($rule.properties.displayName)"
        }
        Else {
            Write-Verbose "Creating Analytic rule: $($rule.properties.displayName)"
        }
        
    }
    catch {
        Write-Error $_ -ErrorAction Continue
    }
    
    If ($ruleResult.StatusCode -in 200, 201) {
        $ruleResult = $ruleResult.Content | ConvertFrom-Json        
        $ruleProperties.properties | Add-Member -NotePropertyName parentId -NotePropertyValue $ruleResult.id 
        $metadataURI = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/metadata/analyticsrule-$($rule.name)$($apiVersion)"
        $metadataPayload = $ruleProperties | ConvertTo-Json -EnumsAsStrings -Depth 50
        try {
            $resultMetadata = Invoke-AzRestMethod -Method PUT -path $metadataURI -Payload $metadataPayload -Verbose:$false
            if (!($resultMetadata.StatusCode -in 200, 201)) {
                Write-Host $resultMetadata.StatusCode
                Write-Host $resultMetadata.Content
                throw "Error when updating Metadata for Analytic rule: $($rule.properties.displayName)"
            }
            Write-Verbose "Updating Metadata for Analytic rule: $($rule.properties.displayName)"
        }
        catch {
            Write-Error $_ -ErrorAction Continue

        }
    }   
}