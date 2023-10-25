#Setup helper function
Function Get-KQLQueryResults
{
    [CmdletBinding()]
    Param
    (
        $KQLQuery,

        $WorkplaceID
    )
    Process
    {
        If ($KQLQuery)
        {
            Try
            {
                $QueryResults = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkplaceID -Query $KQLQuery -ErrorAction Stop -ErrorVariable QueryError | Select-Object -ExpandProperty Results
                If ($QueryResults) 
                {
                    $UTC = [datetime]::Parse("$($QueryResults.Time)")
                    Get-Date -Date ($UTC.ToLocalTime()) -Format 'MM/dd/yyyy hh:mm:ss tt'
                }
                Else
                {
                    "No query results"
                }
            }
            Catch
            {
                Return "KQL Error"
            }        
        }
        Else
        {
            "No kql query to run"
        }
    }

    end
    {
       
    }
}

#Connect to Azure
Connect-AzAccount -Environment  -Tenant 

#Get the Correct Management URL
$resourceUrl = (Get-AzContext).Environment.ResourceManagerUrl -replace ".$", ""

# Get azure subs
$Subs = Get-AzSubscription

# Build Bearer Token
$token = (Get-AzAccessToken -ResourceUrl $resourceUrl).Token
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "Bearer $token")

$Report = New-Object System.Collections.ArrayList

Foreach ($Sub in ($Subs))
{
    # Build Bearer Token
    $token = (Get-AzAccessToken -ResourceUrl $resourceUrl).Token
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Authorization", "Bearer $token")

    $Context = Set-AzContext $Sub.Id
    Write-Host "$($Context.Subscription.Name) - SubId: $($Sub.Id)" -ForegroundColor Cyan
    
    $Workspaces = Get-AzOperationalInsightsWorkspace 
    Foreach ($Workspace in ($Workspaces ))
    {
        Write-Host "`t -- $($Workspace.Name) -- " -NoNewline
        $Url = "$resourceUrl/subscriptions/$($Sub.Id)/resourceGroups/$($Workspace.ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($Workspace.Name)/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-09-01-preview"
        Try
        {
            $Results = Invoke-RestMethod $url -Method Get -Headers $headers -ErrorAction Stop
            Write-Host "Sentinel Onboarded" -ForegroundColor Green
            foreach ($Connector in ($results.value | Where-Object { $_.Kind -ne 'AzureSecurityCenter' } | Select-object Kind, Properties))
            {
                Write-Host "`t`t * $($Connector.properties.connectorUiConfig.title)"
                #$Connector.Properties.connectorUiConfig.dataTypes.lastDataReceivedQuery
                $AllConnectors = $Connector.Properties.connectorUiConfig.dataTypes.name
                $Connector.Properties.connectorUiConfig.dataTypes | ForEach-Object {
                    Write-Host "`t`t`t - $($_.lastDataReceivedQuery.split('|').Trim()[0])"
                    $tReport = [PSCustomObject]@{
                        #Kind                  = $Connector.kind
                        Title                 = $Connector.Properties.connectorUiConfig.title
                        AllDataTypes          = $AllConnectors
                        DataTypes             = $_.lastDataReceivedQuery.split('|').Trim()[0]
                        ID                    = $Connector.Properties.connectorUiConfig.id
                        lastDataReceivedQuery = $_.lastDataReceivedQuery
                        LastLogsReceived      = (Get-KQLQueryResults -KQLQuery ($_.lastDataReceivedQuery) -WorkplaceId $Workspace.CustomerId)
                        Workspace             = $Workspace.Name
                        ResourceGroup         = $Workspace.ResourceGroupName
                        Subscription          = $Sub.Name
                    }
                    If ($tReport.Title -or $tReport.kind)
                    {
                        [void]$Report.Add($tReport)
                    }
                }
            }
        }
        Catch
        {
            If ($Error[0] -like "*not onboarded to Microsoft Sentinel*")
            {
                Write-Host "not onboarded to Sentinel" -ForegroundColor Red
            }
            Else
            {
                Write-Host "Other Error, Investigate!" -ForegroundColor Red
            }
           
        }
    }
}
$Report | out-gridview 

