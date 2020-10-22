Param(
    [parameter(Mandatory=$false)][string]$acrName,
    [parameter(Mandatory=$false)][string]$gitUser,
    [parameter(Mandatory=$false)][string]$repoName="farmizo",
    [parameter(Mandatory=$false)][string]$gitBranch="dev",
    [parameter(Mandatory=$true)][string]$patToken
)

$gitContext = "https://github.com/$gitUser/$repoName"

$services = @( 
    @{ Name="farmizocatalog"; Image="farmizo/catalog.api"; File="src/Services/Catalog/Catalog.API/Dockerfile" },
    @{ Name="farmizoidentity"; Image="farmizo/identity.api"; File="src/Services/Identity/Identity.API/Dockerfile" },
    @{ Name="farmizowebmvc"; Image="farmizo/webmvc"; File="src/Web/WebMVC/Dockerfile" },
    @{ Name="farmizowebstatus"; Image="farmizo/webstatus"; File="src/Web/WebStatus/Dockerfile" },
    @{ Name="farmizolocations"; Image="farmizo/locations.api"; File="src/Services/Location/Locations.API/Dockerfile" },
    @{ Name="farmizoocelotapigw"; Image="farmizo/ocelotapigw"; File="src/ApiGateways/ApiGw-Base/Dockerfile" },
    @{ Name="farmizowebshoppingagg"; Image="farmizo/webshoppingagg"; File="src/ApiGateways/Web.Bff.Shopping/aggregator/Dockerfile" },
)

$services |% {
    $bname = $_.Name
    $bimg = $_.Image
    $bfile = $_.File
    Write-Host "Setting ACR build $bname ($bimg)"    
    az acr build-task create --registry $acrName --name $bname --image ${bimg}:$gitBranch --context $gitContext --branch $gitBranch --git-access-token $patToken --file $bfile
}

# Basket.API
