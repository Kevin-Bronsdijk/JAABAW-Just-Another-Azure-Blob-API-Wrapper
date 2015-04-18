#JAABAW

######Just Another Azure Blob API Wrapper

This is just a very simple PowerShell module which allows querying and manipulating azure Blob entries. I needed something lightweight which was able to run within Azure’s automation runtime. Given the limitations of the current PowerShell API, it was necessary to create something to simplify the REST plumbing.
Additional details can be found within this blogpost: [http://devslice.net/2015/01/jaabaw-just-another-azure-blob-api-wrapper/](http://devslice.net/2015/01/jaabaw-just-another-azure-blob-api-wrapper/)
  
* Iterate though Blob containers and Blobs
* Read, add and alter Blob Metadata and properties.
* Create and delete Blob containers
* Move and delete Blobs
* Run within Azure Automation

######Using JAABAW
Code sample:
```powershell
$G_SAN = "xyz"
$G_SAK = "xyz" 

Get-Containers  -StorageAccountName $G_SAN -StorageAccountKey $G_SAK

New-Container   -StorageAccountName $G_SAN -StorageAccountKey $G_SAK -ContainerName "samplecontainer1"

Get-ContainerProperties -StorageAccountName $G_SAN -StorageAccountKey $G_SAK -ContainerName "samplecontainer1"

$Metadata = @{"x-ms-meta-test1"= "22222";"x-ms-meta-test2" = "111111"}
Set-ContainerMetadata   -StorageAccountName $G_SAN -StorageAccountKey $G_SAK -ContainerName "samplecontainer1" -Metadata $Metadata

Get-Blobs   -StorageAccountName $G_SAN -StorageAccountKey $G_SAK -ContainerName "samplecontainer1" -MaxResults 3 -Prefix "Bn"

Set-BlobProperties  -StorageAccountName $G_SAN -StorageAccountKey $G_SAK -ContainerName "samplecontainer1" -BlobName "testimage.jpg" -ContentType "image/jpeg"

```

