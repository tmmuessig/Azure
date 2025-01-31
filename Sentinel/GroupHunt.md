# KQL Hunting for group Adds and Removals

```kql
let TimeSpan = ago(30d);
let filterValue = "";
AuditLogs
| where TimeGenerated >= TimeSpan
| where OperationName in ('Add member to group', 'Remove member from group')
| extend Details = parse_json(TargetResources)  
| extend UserPrincipalName = iff(isnotnull(Details[0].userPrincipalName), Details[0].userPrincipalName, Details[0].displayName)
| extend GroupDetails = iff(OperationName has "Add member to group", replace('\"',"", tostring(Details[0].modifiedProperties[1].newValue)), replace('\"',"", tostring(Details[0].modifiedProperties[1].oldValue)))
| extend Actor = iff(isnotnull(InitiatedBy.user.userPrincipalName), InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName)
| where Actor != "Azure AD Identity Governance - Directory Management"
| where (UserPrincipalName contains filterValue or filterValue == "" or Actor contains filterValue)
| project TimeGenerated, Actor, OperationName, UserPrincipalName, GroupDetails
```
