function GetSignatureString
{
    [OutputType([string])] 
	param(
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $Url,
        [parameter(Mandatory=$true)]  
        [string] 
        $Version,
        [parameter(Mandatory=$true)]  
        [string]  
        $Method,  
        [parameter(Mandatory=$true)] 
        [hashtable] 
        $Headers
	) 
	
	$uri = New-Object System.Uri -ArgumentList $Url
    $lf = [char]10
	
    if($Method -eq "HEAD" -or $Method -eq "GET")
    {
        $contentLenght = ""
    }
    else
    {
        $contentLenght = "0"
    }

	$signatureString =   "$Method$lf$lf$lf$contentLenght$lf$lf$lf$lf$lf$lf$lf$lf$lf"
    $headersOrdered = $Headers.GetEnumerator() | Sort-Object { $_.Key } 

    # x-ms headers first
    foreach ($header in $headersOrdered.GetEnumerator())
    {  
        If ($header.Key.ToString().StartsWith("x-ms-"))
        {
           $signatureString += $header.Key + ":" + $header.Value + $lf
        } 
    }
    
	$signatureString += "/$StorageAccountName" + $uri.AbsolutePath
    
    # other headers 
    if ($headersOrdered.Count -gt 2)
    {
        $signatureString += $lf
    }
    
    $count = 0
    foreach ($header in $headersOrdered.GetEnumerator())
    {  
        If ($header.Key.ToString().StartsWith("x-ms-") -eq $false)
        {

           if ($count -ne 0)
           {
                $signatureString +=  $lf
           }

           $signatureString += $header.Key + ":" + $header.Value
           $count += 1
        } 
    }

	$dataToMac = [System.Text.Encoding]::UTF8.GetBytes($signatureString)
	$accountKeyBytes = [System.Convert]::FromBase64String($StorageAccountKey)
	$hmac = new-object System.Security.Cryptography.HMACSHA256((,$accountKeyBytes))
	[System.Convert]::ToBase64String($hmac.ComputeHash($dataToMac))
}

function InvokeRequest
{
    [OutputType([object])] 
    param(	
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
        [parameter(Mandatory=$false)] 
        [string] 
        $Version = "2014-02-14",
        [parameter(Mandatory=$true)]  
        [string]  
        $Method,  
        [parameter(Mandatory=$true)]  
        [string]  
        $Resource,  
		[parameter(Mandatory=$false)] 
        [string] 
        $RequestBody = "",
        [parameter(Mandatory=$false)] 
        [bool]
        $UseSecondary = $false,
        [parameter(Mandatory=$false)] 
        [hashtable]
        $Metadata = $null
    )
    $requestUtcTime = (get-date -format r).ToString()
    $secondaryParam = ""

    if($UseSecondary)
    {
        $secondaryParam = "-secondary"
    }

    $uri = "https://$StorageAccountName$secondaryParam.blob.core.windows.net/$Resource"

    # Default
    $headers = @{
                "x-ms-version"=$Version; 
                "x-ms-date" = $requestUtcTime
                }

    # Resource params
    foreach ($p in $Resource.split("?").split("&"))
    { 
        if($p.ToString().Contains("="))
        {
            $headers.Add($p.Split("=")[0],$p.Split("=")[1])
        }
    } 

    if($Metadata -ne $null)
    {
        foreach ($p in $Metadata.GetEnumerator())
        {
            $headers.Add($p.Key, $p.Value)
        }
    }

    $authHeader = GetSignatureString -url $uri `
                                      -StorageAccountName $StorageAccountName `
                                      -StorageAccountKey $StorageAccountKey `
                                      -Version $Version `
                                      -Headers $headers `
                                      -Method $Method 

    $headers.Add("Authorization", ("SharedKey " + $StorageAccountName + ":" + $authHeader)) 

    $result = InvokeWebRequest -Method $Method -Uri $uri -Headers $headers

    return $result
}

function InvokeWebRequest 
{   
    [OutputType([object])] 
    param(
        [parameter(Mandatory=$true)]  
        [string]  
        $Method,
        [parameter(Mandatory=$true)]  
        [string]  
        $Uri,
        [parameter(Mandatory=$true)] 
        [hashtable]
        $Headers
  )

    # Not supported in Azure Automation
    #Invoke-WebRequest -Uri $uri -Method $Method -Headers $headers

    $request = [System.Net.WebRequest]::Create($Uri)
    $request.Method = $Method

    foreach ($header in $Headers.GetEnumerator())
    { 
         $request.Headers.Add($header.Key, $header.Value)
    }

    if($Method -eq "HEAD" -or $Method -eq "GET")
    {
        $request.ContentLength = ""
    }
    else
    {
        $request.ContentLength = 0
    }

    $response = $request.GetResponse()
    $stream = $response.GetResponseStream()
    $reader = New-Object IO.StreamReader($stream)

    $result = @{
      "StatusCode" = $response.StatusDescription
      "Headers" = $response.Headers
      "Content" = $reader.ReadToEnd()
    }

    $reader.Close()
    $stream.Close()
    $response.Close()

    return $result
}

function GetContainers
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,
        [parameter(Mandatory=$False)] 
        [int] 
        $MaxResults,
        [parameter(Mandatory=$False)] 
        [string] 
        $Prefix
	)

    if($MaxResults)
    {
        $maxResultsParam = "&maxresults=$MaxResults"
    }

    if($Prefix -ne "")
    {
        $prefixsParam = "&prefix=$Prefix"
    }

    $resource = "?comp=list$maxResultsParam$prefixsParam"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "GET" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Lists all of the containers in a storage account.
#>
function Get-Containers
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179352.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,
        [parameter(Mandatory=$false)] 
        [int] 
        $MaxResults,
        [parameter(Mandatory=$false)] 
        [string] 
        $Prefix,
        [parameter(Mandatory=$false)]  
        [string]  
        $ReturnXML = $true
	)

    $result = GetContainers  -StorageAccountName $StorageAccountName `
                                 -StorageAccountKey $StorageAccountKey -MaxResults $MaxResults -Prefix $Prefix 

    if($result.StatusCode -eq "OK")
    {
        $xmlContent =[xml]$result.Content.ToString().Replace("ï»¿","")

        if ($ReturnXML -eq $true)
        {
            return $xmlContent
        }
        else
        {
            $containers = @()

            foreach ($container in $xmlContent.SelectNodes("//Container")) 
            {
                $containers += $container.Name
            }

            return $containers 
        }
    }
}

function GetBlobServiceProperties
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey
	)

    $resource = "?restype=service&comp=properties"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "GET" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Gets the properties of the Blob service, including logging and metrics settings, and the default service version.
#>
function Get-BlobServiceProperties
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/hh452239.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,
        [parameter(Mandatory=$false)]  
        [string]  
        $ReturnXML = $true
	)

    $result = GetBlobServiceProperties -StorageAccountName $StorageAccountName `
                                        -StorageAccountKey $StorageAccountKey

    if($result.StatusCode -eq "OK")
    {
        $xmlContent =[xml]$result.Content.ToString().Replace("ï»¿","")

        if ($ReturnXML -eq $true)
        {
            return $xmlContent
        }
        else
        {
            throw [System.NotImplementedException] 
        }
    }
}

function NewContainer
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $resource = $ContainerName + "?restype=container"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "PUT" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Creates a new container in a storage account.
#>
function New-Container
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179468.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $result = NewContainer  -StorageAccountName $StorageAccountName `
                                -StorageAccountKey $StorageAccountKey `
                                -ContainerName $ContainerName

    if($result.StatusCode -eq "OK")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function GetContainerProperties
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $resource = "$ContainerName" + "?restype=container"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "GET" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Returns all user-defined metadata and system properties of a container.
#>
function Get-ContainerProperties
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179370.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $result = GetContainerProperties    -StorageAccountName $StorageAccountName `
                                            -StorageAccountKey $StorageAccountKey `
                                            -ContainerName $ContainerName

    if($result.StatusCode -eq "OK")
    {
        return  $result.Headers #ISSUE-11 FILTER
    }  
}

function GetContainerMetadata
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $resource = "$ContainerName" + "?restype=container&comp=metadata"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "GET" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Returns only user-defined metadata of a container.
#>
function Get-ContainerMetadata
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/ee691976.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $result = GetContainerMetadata  -StorageAccountName $StorageAccountName `
                                        -StorageAccountKey $StorageAccountKey `
                                        -ContainerName $ContainerName 

    if($result.StatusCode -eq "OK")
    {
        return  $result.Headers #ISSUE-12 FILTER
    }
}

function SetContainerMetadata
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [hashtable]
        $Metadata
	)

    $resource = $ContainerName + "?restype=container&comp=metadata"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "PUT" `
                    -Resource $resource `
                    -Metadata $Metadata
}

<#
    .SYNOPSIS
    Sets user-defined metadata of a container.
#>
function Set-ContainerMetadata
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179362.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [hashtable]
        $Metadata
	)

    $result = SetContainerMetadata  -StorageAccountName $StorageAccountName `
                                        -StorageAccountKey $StorageAccountKey `
                                        -ContainerName $ContainerName `
                                        -Metadata $Metadata

    if($result.StatusCode -eq "OK")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function GetContainerACL
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $resource = "$ContainerName" + "?restype=container&comp=acl"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "GET" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Gets the public access policy and any stored access policies for the container.
#>
function Get-ContainerACL
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179469.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$false)]  
        [string]  
        $ReturnXML = $true
	)

    $result = GetContainerACL   -StorageAccountName $StorageAccountName `
                                    -StorageAccountKey $StorageAccountKey `
                                    -ContainerName "samplecontainer1" `

    if($result.StatusCode -eq "OK")
    {
        $xmlContent =[xml]$result.Content.ToString().Replace("ï»¿","")

        if ($ReturnXML -eq $true)
        {
            return $xmlContent
        }
        else
        {
            throw [System.NotImplementedException] 
        }
    }
}

function RemoveContainer
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $resource = $ContainerName + "?restype=container"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "DELETE" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Deletes the container and any blobs that it contains.
#>
function Remove-Container
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179408.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName
	)

    $result = RemoveContainer   -StorageAccountName $StorageAccountName `
                                    -StorageAccountKey $StorageAccountKey `
                                    -ContainerName $ContainerName

    if($result.StatusCode -eq "OK")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function GetBlobs
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$false)] 
        [int] 
        $MaxResults,
        [parameter(Mandatory=$false)] 
        [string] 
        $Prefix
	)

    if($MaxResults)
    {
        $maxResultsParam = "&maxresults=$MaxResults"
    }

    if($Prefix -ne "")
    {
        $prefixsParam = "&prefix=$Prefix"
    }

    $resource = "$ContainerName" + "?restype=container&comp=list$maxResultsParam$prefixsParam"

    InvokeRequest -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "GET" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Lists all of the blobs in a container.
#>
function Get-Blobs
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd135734.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$false)] 
        [int] 
        $MaxResults,
        [parameter(Mandatory=$false)] 
        [string] 
        $Prefix,
        [parameter(Mandatory=$false)]  
        [string]  
        $ReturnXML = $true
	)

   $result = GetBlobs   -StorageAccountName $StorageAccountName `
                            -StorageAccountKey $StorageAccountKey `
                            -ContainerName $ContainerName `
                            -MaxResults $MaxResults `
                            -Prefix $Prefix

    if($result.StatusCode -eq "OK")
    {
        $xmlContent =[xml]$result.Content.ToString().Replace("ï»¿","")

        if ($ReturnXML -eq $true)
        {
            return $xmlContent
        }
        else
        {
            throw [System.NotImplementedException] 
        }
    }
}

function SetBlobProperties
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName,
        [parameter(Mandatory=$false)] 
        [string] 
        $CacheControl = "",
        [parameter(Mandatory=$false)] 
        [string] 
        $ContentType = "",
        [parameter(Mandatory=$false)] 
        [string] 
        $ContentMD5 = ""
	)

    $metadata = @{}

    if($CacheControl -ne "")
    {
        $metadata.Add("x-ms-blob-cache-control", $CacheControl)
    }

    if($ContentType -ne "")
    {
        $metadata.Add("x-ms-blob-content-type", $ContentType)
    }

    if($ContentMD5 -ne "")
    {
        $metadata.Add("x-ms-blob-content-md5", $ContentMD5)
    }

    $resource = "$ContainerName/$BlobName" + "?comp=properties"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "PUT" `
                    -Resource $resource  `
                    -Metadata $metadata
}

<#
    .SYNOPSIS
    Sets system properties defined for an existing blob.
#>
function Set-BlobProperties
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/ee691966.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName,
        [parameter(Mandatory=$false)] 
        [string] 
        $CacheControl = "",
        [parameter(Mandatory=$false)] 
        [string] 
        $ContentType = "",
        [parameter(Mandatory=$false)] 
        [string] 
        $ContentMD5 = ""
	)

    $result = SetBlobProperties     -StorageAccountName $StorageAccountName `
                                        -StorageAccountKey $StorageAccountKey `
                                        -ContainerName $ContainerName  `
                                        -BlobName $BlobName `
                                        -CacheControl $CacheControl `
                                        -ContentType $ContentType `
                                        -ContentMD5 $ContentMD5 

    if($result.StatusCode -eq "OK")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function SetBlobMetaData
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName,
        [parameter(Mandatory=$true)] 
        [hashtable]
        $Metadata
	)

    $resource = "$ContainerName/$BlobName" + "?comp=metadata"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "PUT" `
                    -Resource $resource `
                    -Metadata $Metadata
}

<#
    .SYNOPSIS
    Sets user-defined metadata of an existing blob.
#>
function Set-BlobMetaData
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179414.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName,
        [parameter(Mandatory=$true)] 
        [hashtable]
        $Metadata
	)

    $resource = "$ContainerName/$BlobName" + "?comp=metadata"

    $result = SetBlobMetaData   -StorageAccountName $StorageAccountName `
                                    -StorageAccountKey $StorageAccountKey `
                                    -ContainerName $ContainerName `
                                    -BlobName $BlobName `
                                    -Metadata $Metadata

    if($result.StatusCode -eq "OK")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function GetBlobMetaData
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)

    $resource = "$ContainerName/$BlobName" + "?comp=metadata"

    InvokeRequest  -StorageAccountName $StorageAccountName `
                    -StorageAccountKey $StorageAccountKey `
                    -Method "HEAD" `
                    -Resource $resource
}

<#
    .SYNOPSIS
    Retrieves all user-defined metadata of an existing blob or snapshot.
#>
function Get-BlobMetaData
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179350.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)


    $result = GetBlobMetaData   -StorageAccountName $StorageAccountName `
                                    -StorageAccountKey $StorageAccountKey `
                                    -ContainerName $ContainerName `
                                    -BlobName $BlobName

    if($result.StatusCode -eq "OK")
    {
         return  $result.Headers #ISSUE-12 FILTER
    }
}

function RemoveBlob
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)
    $resource = "$ContainerName/$BlobName" 

    InvokeRequest -StorageAccountName $StorageAccountName `
                      -StorageAccountKey $StorageAccountKey `
                      -Method "DELETE" `
                      -Resource $resource

}

<#
    .SYNOPSIS
    Marks a blob for deletion.
#>
function Remove-Blob
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179413.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)

    $result = RemoveBlob -StorageAccountName $StorageAccountName `
                      -StorageAccountKey $StorageAccountKey `
                      -ContainerName $ContainerName `
                      -BlobName $BlobName

    if($result.StatusCode -eq "OK")
    {
        return $true
    }
    else
    {
        return $false
    }
}

function GetBlobProperties
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)

    $resource = "$ContainerName/$BlobName"

    InvokeRequest -StorageAccountName $StorageAccountName `
                      -StorageAccountKey $StorageAccountKey `
                      -Method "HEAD" `
                      -Resource $resource
}

<#
    .SYNOPSIS
    Returns all system properties and user-defined metadata on the blob.
#>
function Get-BlobProperties
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179394.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)

    $result = GetBlobProperties -StorageAccountName $StorageAccountName `
                      -StorageAccountKey $StorageAccountKey `
                      -ContainerName $ContainerName `
                      -BlobName $BlobName

    if($result.StatusCode -eq "OK")
    {
         return  $result.Headers
    }
}

function GetBlob
{
    [OutputType([object])] 
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)

    $resource = "$ContainerName/$BlobName"

    InvokeRequest -StorageAccountName $StorageAccountName `
                      -StorageAccountKey $StorageAccountKey `
                      -Method "GET" `
                      -Resource $resource
}

<#
    .SYNOPSIS
    Reads or downloads a blob from the Blob service, including its user-defined metadata and system properties.
#>
function Get-Blob
{
 [CmdletBinding(
        HelpURI='http://msdn.microsoft.com/en-us/library/azure/dd179440.aspx'
    )]
	param(		 
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountName,  
        [parameter(Mandatory=$true)]  
        [string]  
        $StorageAccountKey,  
		[parameter(Mandatory=$true)] 
        [string] 
        $ContainerName,
        [parameter(Mandatory=$true)] 
        [string] 
        $BlobName
	)

    $result = GetBlob -StorageAccountName $StorageAccountName `
                      -StorageAccountKey $StorageAccountKey `
                      -ContainerName $ContainerName `
                      -BlobName $BlobName

    if($result.StatusCode -eq "OK")
    {
        return  $result.Content
    }                      
}

export-modulemember *-*
