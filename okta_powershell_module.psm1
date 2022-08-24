

#function Add-OktaNewZoneBlock{
#
#}

#function Add-OktaNewZoneIP{
   <#
#    .SYNOPSIS
        Creates a new Zone using IP addressing
#    .DESCRIPTION
#        Creates a new Zone using IP addressing
#    .NOTES
        This function can accept either CIDR or dash notation (see examples)
        Either gateways or proxies *must* be defined. Note the parameter "gateways" and "proxies" are integer values for the total
#    .EXAMPLE
        Add-OktaNewZoneIP -DeviceID "abblababl"
        #>
        
#        param(

#            [parameter(Mandatory=$true)][string]$DeviceID,
#            [parameter(Mandatory=$true)][int]$ProxyCount,
#            [parameter(Mandatory=$true)][int]$GatewayCount

#            )
            
#            $device = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/zones" -headers $global:headers -method 'POST' | ConvertFrom-Json
        
#            return $device
        
#}

#function Add-OktaNewZoneDynamic{
#
#}

function Get-OktaZone{
<#
    .SYNOPSIS
        Returns a single zone object as identified by the zone ID
    .DESCRIPTION
        Returns a single zone as identified by a device ID. If the ID cannot be found, you will receive a 404
    .NOTES
        In the event a zone ID cannot be found, a 404 will be returned. It is suggested you be running PowerShell 7 or have proper error handling in place    
    .EXAMPLE
        Get-OktaDeviceByID -DeviceID "abblababl"
        #>

        param(
            [parameter(Mandatory=$true)][string]$ZoneID
            )
        
            $zone = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/zones/$zoneid" -headers $global:headers | ConvertFrom-Json
        
            return $zone
}

function Get-OktaZonesAll{
<#
    .SYNOPSIS
        Returns all zones in an array
    .DESCRIPTION
        Returns all zones in an array
    .NOTES
        Due to pagination constraints, this may take some time to run if a large number of zones are returned, as this function aggregates all zones into a single array before displaying
    #>

    $results = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/zones" -headers $global:headers

    if ($results.headers.after.length -ne 0) {
    $values2 = $values2+$results
        DO
        {
            $results = Invoke-WebRequest -uri $results.after -Headers $headers -Method GET | ConvertFrom-JSON
            $values2=$values2+$results
        } Until ($results.after.length -eq 0)
        return $results | ConvertFrom-JSON
    }


    return $results | ConvertFrom-Json
}

function Get-OktaZoneSearch{

}

function Set-OktaZone{

}

function Set-OktaAuthentication {
    <#
    .SYNOPSIS
        Defines relevant elements of Okta REST API authentication
    .DESCRIPTION
        Accepts two values - Okta subdomain, API Key. Consult online help to acquire these values
    .PARAMETER APIToken
        Token issued via Okta dashboard
    .PARAMETER Target
        Okta subdomain to which this session will authenticate. This is subdomain only - https, TLD, and Okta domain are not necessary. IE, use "subdomain", not "https://subdomain.okta.com"
    .NOTES
        This is the only function in this module with globally scoped variables that are available throughout the PS session. Use 'Remove-OktaAuthentication' to clear them
        Note in addition to the above that multiple credential sets cannot be maintained per session in accordance with best practices
        If you wish to maintain multiple credential sets, it is recommended that you modify the Target and APIToken and Header variables to be captured in an array and the cmdlets be modified to use desired array of authentication values
        Finally, this is the REST API Token process. For OAuth Bearer Tokens (which are not fully implemented everywhere) you'll need to add an additional auth mechanism
    .EXAMPLE
        Set-OktaAuthentication -APIToken "abcdefgh12347890_123" -target "contoso" 
    #>

    param(
    [parameter(Mandatory=$true)][String]$APIToken,
    [parameter(Mandatory=$true)][String]$Target
    )

    $global:APIToken = $APIToken
    $global:Target = $Target
    $global:headers = @{'Accept' = 'application/json'; 'Content-Type' = 'application/json';'Authorization' = 'SSWS'+$global:APIToken}

}

function Remove-OktaAuthentication {
    <#
    .SYNOPSIS
        Clears existing Okta authentication values
    .DESCRIPTION
        Clears existing Okta authentication values. May be used in cases of improperly scoped API token, wrong account access, or typo
        If you need to access different API scopes or different Okta tenants, it is recommended that credentials be cleared and reset between targeting different tenants
    .NOTES
        Removes relevant Okta Powershell authentication variables 
        You will need to run Set-OktaAuthentication again after running this command if you wish to use PowerShell module with tenant again
    #>    
    remove-variable "APIToken" -scope "global"
    remove-variable "Target" -scope "global"
    remove-variable "headers" -scope "global"
}

function Get-OktaDeviceByID {
<#
    .SYNOPSIS
        Returns a single device object as identified by the device ID
    .DESCRIPTION
        Returns a single device as identified by a device ID. If the ID cannot be found, you will receive a 404
    .NOTES
        In the event a device ID cannot be found, a 404 will be returned. It is suggested you be running PowerShell 7 or have proper error handling in place    
    .EXAMPLE
        Get-OktaDeviceByID -DeviceID "abblababl"
        #>

    param(
    [parameter(Mandatory=$true)][string]$DeviceID
    )

    $device = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices/$deviceid" -headers $global:headers | ConvertFrom-Json

    return $device

}

function Get-OktaDevicesAll {
    <#
    .SYNOPSIS
        Returns all devices in an array
    .DESCRIPTION
        Returns all devices in an array
    .NOTES
        Due to pagination constraints, this may take some time to run if a large number of devices are returned, as this function aggregates all pages into a single array before displaying
    #>

    $results = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices" -headers $global:headers

    if ($results.headers.after.length -ne 0) {
    $values2 = $values2+$results
        DO
        {
            $results = Invoke-WebRequest -uri $results.after -Headers $headers -Method GET | ConvertFrom-JSON
            $values2=$values2+$results
        } Until ($results.after.length -eq 0)
        return $results | ConvertFrom-JSON
    }


    return $results | ConvertFrom-Json
}

function Get-OktaDevicesBySearch {
    <#
    .SYNOPSIS
        Returns all devices matched by specified search filter, in an array
    .DESCRIPTION
        Returns all devices matched by specified search filter, in an array
    .NOTES
        Due to pagination constraints, this may take some time to run if a large number of devices are returned, as this function aggregates all pages into a single array before displaying
        If "number of filters" is not specified, default is 1
    #>
    
    $results = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices" -headers $global:headers

    if ($results.headers.after.length -ne 0) {
    $values2 = $values2+$results
        DO
        {
            $results = Invoke-WebRequest -uri $results.after -Headers $headers -Method GET | ConvertFrom-JSON
            $values2=$values2+$results
        } Until ($results.after.length -eq 0)
        return $results | ConvertFrom-JSON
    }


    return $results | ConvertFrom-Json

}

function Remove-OktaDevice{

    <#
    .SYNOPSIS
        Deletes a single device object as identified by the device ID
    .DESCRIPTION
        Deletes a single device as identified by a device ID. If the ID cannot be found, you will receive a 404
    .NOTES
        In the event a device ID cannot be found, a 404 will be returned. It is suggested you be running PowerShell 7 or have proper error handling in place    
        A device must presently be in DEACTIVATED state prior to deletion or a 400 BAD REQUEST will be returned
        DO NOT USE THIS COMMAND UNLESS YOU FULLY UNDERSTAND THE IMPLICATIONS OF DEVICE REMOVAL
    .EXAMPLE
        Remove-OktaDevice -DeviceID "abblababl"
        #>
        
    param(
    [parameter(Mandatory=$true)][string]$DeviceID
    )

    $device = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices/$deviceid" -headers $global:headers -method 'DELETE' | ConvertFrom-Json

    return $device

}
function Set-OktaDeviceActivated{
    
    <#
    .SYNOPSIS
        Activates a single device object as identified by the device ID and returns a 204 in acknowledgement
    .DESCRIPTION
        Activates a single device as identified by a device ID. If the ID cannot be found, you will receive a 404
    .NOTES
        In the event a device ID cannot be found, a 404 will be returned. It is suggested you be running PowerShell 7 or have proper error handling in place    
        In the event a device is not in CREATED or ACTIVATED state, a 400 Bad Request will be returned
    .EXAMPLE
        Set-OktaDeviceActivated -DeviceID "abblababl"
        #>
        
        param(
            [parameter(Mandatory=$true)][string]$DeviceID
            )
            
            $device = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices/$deviceid/lifecycle/activate" -headers $global:headers -method 'POST' | ConvertFrom-Json
        
            return $device
        
}

function Set-OktaDeviceDeactivated{
    <#
    .SYNOPSIS
        Deactivates a single device object as identified by the device ID and returns a 204 in acknowledgement
    .DESCRIPTION
        Deactivates a single device as identified by a device ID. If the ID cannot be found, you will receive a 404
    .NOTES
        In the event a device ID cannot be found, a 404 will be returned. It is suggested you be running PowerShell 7 or have proper error handling in place    
        In the event a device is not in an ACTIVATED or SUSPENDED status, a 400 Bad Request will be returned
    .EXAMPLE
        Set-OktaDeviceDeactivated -DeviceID "abblababl"
        #>
        
        param(
            [parameter(Mandatory=$true)][string]$DeviceID
            )
        
            $device = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices/$deviceid/lifecycle/deactivate" -headers $global:headers -method 'POST' | ConvertFrom-Json
        
            return $device
        
}

function Set-OktaDeviceSuspended{
 
    <#
    .SYNOPSIS
        Suspends a single device object as identified by the device ID and returns a 204 acknowledgement
    .DESCRIPTION
        Suspends a single device as identified by a device ID. If the ID cannot be found, you will receive a 404
    .NOTES
        In the event a device ID cannot be found, a 404 will be returned. It is suggested you be running PowerShell 7 or have proper error handling in place    
        In the event a device is not currently in ACTIVE state, a 400 Bad Request will be returned when attempting to suspend it
    .EXAMPLE
        Set-OktaDeviceSuspended -DeviceID "abblababl"
        #>
        
        param(
            [parameter(Mandatory=$true)][string]$DeviceID
            )
        
            $device = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices/$deviceid/lifecycle/suspend" -headers $global:headers -method 'POST' | ConvertFrom-Json
        
            return $device
        
}

function Set-OktaDeviceUnSuspended{

    <#
    .SYNOPSIS
        Unsuspends a single device object as identified by the device ID
    .DESCRIPTION
        Unsuspends a single device as identified by a device ID. If the ID cannot be found, you will receive a 404
    .NOTES
        In the event a device ID cannot be found, a 404 will be returned. It is suggested you be running PowerShell 7 or have proper error handling in place    
        In the event a device is not presently in a SUSPENDED status, this will return 400 Bad Request
    .EXAMPLE
        Set-OktaDeviceUnsuspended -DeviceID "abblababl"
        #>
        
        param(
            [parameter(Mandatory=$true)][string]$DeviceID
            )
        
            $device = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/devices/$deviceid/lifecycle/unsuspend" -headers $global:headers -method 'POST' | ConvertFrom-Json
        
            return $device
        

}

function Get-OktaUsersAll {
    <#
    .SYNOPSIS
        Returns all users in an array
    .DESCRIPTION
        Returns all users in an array
    .NOTES
        Due to pagination constraints, this may take some time to run if a large number of users are returned, as this function aggregates all pages into a single array before displaying
    #>

    $results = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/users" -headers $global:headers
    $values2 = $values2+($results|convertfrom-json)
    if ($results.headers.link.count -eq 2) {

        DO
        {
            $nextlink = $results.headers.link[1].split(";")[0]
            $nextlink2 = $nextlink.substring(1,$nextlink.length-2)
            $results = Invoke-WebRequest -uri $nextlink2 -Headers $global:headers
            $values2=$values2+($results|convertfrom-json)
        } Until ($results.headers.link.count -eq 1)
        return $values2
    }

 
    return $results | ConvertFrom-Json
}

function Get-OktaUsersAlltoCSV {
    <#
    .SYNOPSIS
        Returns all users in a CSV
    .DESCRIPTION
        Returns all users in a CSV
    .NOTES
        Due to pagination constraints, this may take some time to run if a large number of users are returned, as this function aggregates all pages into a single array before displaying
    #>

    param(
            [parameter(Mandatory=$true)][string]$CSVOutputPath
            )
          

    $results = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/users" -headers $global:headers
    $values2 = $values2+($results|convertfrom-json)
    if ($results.headers.link.count -eq 2) {

        DO
        {
            $nextlink = $results.headers.link[1].split(";")[0]
            $nextlink2 = $nextlink.substring(1,$nextlink.length-2)
            $results = Invoke-WebRequest -uri $nextlink2 -Headers $global:headers
            $values2=$values2+($results|convertfrom-json)
        } Until ($results.headers.link.count -eq 1)
        
        $values2|export-csv $CSVOutputPath
        return $values2
    }


    $results|export-csv $csvoutputpath
    return $results | ConvertFrom-Json

}



function Add-OktaNewUser {
    <#
    .SYNOPSIS
        Create a new user
    .DESCRIPTION
        Create a new user
    .NOTES
        Create a new user. This is limited in capability at the moment
            #>
    
            param(

            [parameter(Mandatory=$true)][string]$FirstName,
            [parameter(Mandatory=$true)][string]$LastName
            #[parameter(Mandatory=$true)][string]$Email

            )

            $profile = @{
                "firstName" =$FirstName
                "lastName" = $LastName
                "email" = $FirstName + "."+ $LastName + "@segovillage.local"
                "login" = $FirstName + "."+ $LastName + "@segovillage.local"
            }
            $body = @{
                "profile" = $profile
            }
            $results = Invoke-WebRequest -uri "https://$global:target.okta.com/api/v1/users" -body ($body|convertto-json) -method POST -headers $global:headers


}

