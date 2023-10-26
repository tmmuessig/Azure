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

Function Get-BearerToken
{
    [CmdletBinding()]
    Param ($resourceUrl)
    Begin {}
    Process
    {

        # Build Bearer Token
        $token = (Get-AzAccessToken -ResourceUrl $resourceUrl).Token
        $UrlHeaders = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $UrlHeaders.Add("Authorization", "Bearer $token")
        Return $UrlHeaders
    }
}

Function Get-SentinelConnectors
{
    [cmdletbinding()]
    Param
    (
        $Connectors
    )

    Begin
    {

    }

    Process
    {

    }

    End
    {
        
    }
}
#Connect to Azure
Connect-AzAccount -Environment  -Tenant 

#Get the Correct Management URL
$resourceUrl = (Get-AzContext).Environment.ResourceManagerUrl -replace ".$", ""


# Get azure subs
$Subs = Get-AzSubscription

# Initialize variable to hold final results
$Report = New-Object System.Collections.ArrayList

Foreach ($Sub in ($Subs)[1,4,7])
{
    $Headers = Get-BearerToken -resourceUrl $resourceUrl 

    $Context = Set-AzContext $Sub.Id
    Write-Host "$($Context.Subscription.Name) - SubId: $($Sub.Id)" -ForegroundColor Cyan
    
    $Workspaces = Get-AzOperationalInsightsWorkspace 
    Foreach ($Workspace in ($Workspaces ))
    {
        Write-Host "`t - $($Workspace.Name) " -NoNewline -ForegroundColor Cyan
        $Url = "$resourceUrl/subscriptions/$($Sub.Id)/resourceGroups/$($Workspace.ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($Workspace.Name)/providers/Microsoft.SecurityInsights/dataConnectors?api-version=2023-09-01-preview"
        Try
        {
            $Results = Invoke-RestMethod $url -Method Get -Headers $Headers -ErrorAction Stop
            Write-Host "Sentinel Onboarded" -ForegroundColor Green
            foreach ($Connector in ($results.value | Where-Object { $_.Kind -ne 'AzureSecurityCenter' } | Select-object Kind, Properties))
            {
                If ($Connector.kind -like "*icUI")
                {
                    Write-Host "`t`t * $($Connector.properties.connectorUiConfig.title)" -ForegroundColor Green
                    #$Connector.Properties.connectorUiConfig.dataTypes.lastDataReceivedQuery
                    $AllConnectors = $Connector.Properties.connectorUiConfig.dataTypes.name
                    $Connector.Properties.connectorUiConfig.dataTypes | ForEach-Object {
                        Write-Host "`t`t`t - $($_.lastDataReceivedQuery.split('|').Trim()[0])" -ForegroundColor  Yellow
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
                Else
                {
                    Write-Host "`t`t`t$($Connector.kind)" -ForegroundColor DarkMagenta
                    $tReport = [PSCustomObject]@{
                        Title                 = $Connector.kind
                        AllDataTypes          = ""
                        DataTypes             = $connector.properties.datatypes.alerts.state
                        ID                    = ""
                        lastDataReceivedQuery = ""
                        LastLogsReceived      = ""
                        Workspace             = $Workspace.Name
                        ResourceGroup         = $Workspace.ResourceGroupName
                        Subscription          = $Sub.Name

                    }
                    If ($tReport.Title)
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

