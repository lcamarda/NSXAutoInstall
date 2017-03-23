<#
.SYNOPSIS
  Deploy NSXv on an existing vSphere environment
.DESCRIPTION
  This script automate the deployment of NSXv on an existing vSphere enviroment. 
  Reccomended implementation and design choices have been cincorporated as part of the script.
.NOTES
  Author: Luca Camarda
.LINK
     https://github.com/vmware/powernsx
#>

$ErrorActionPreference = "Stop"

#####Edit Below this line######

#region Inputs

#License
$nsxLicense = “xxxx-xxxx-xxxx-xxxx-xxxx”

#GlobalParameters
$dns = "192.168.110.10"
$ntp = "192.168.100.2"
$domain = "corp.local"
$syslog = "192.168.110.24"

#vCenter/PSC information
$vcenterFqdn = "vcsa-01a.corp.local"
$vcUser = "administrator@vsphere.local"
$vcPass = "VMware1!"
$ssoServer = "vcsa-01a.corp.local"

#NSX Manager Deployment parameters
$nsxOvfPath = "E:\VMware-NSX-Manager-6.3.0-5007049.ova"
$nsxMgrHostname = "nsxmgr-01a"
$nsxMgrIp = "192.168.110.15"
$nsxMgrPass = "VMware1!"
$nsxMgrNetmask = "255.255.255.0"
$nsxMgrGateway = "192.168.110.2"
$nsxMgrNetmask = "255.255.255.0"
$nsxMgrCluster = "RegionA01-EDGE01" #Cluster where NSX Manager will be deplyed
$nsxMgrDatastoreName = "RegionA01-ISCSI01-EDGE01" #Datastore where where NSX manager will be deployed
$nsxMgrPortGroupName = "VM-RegionA01-vDS-EDGE" #Port-group where where NSX manager will be deployed

#Controllers Deployment
$ctrlPoolStart = "192.168.110.101"
$ctrlPoolEnd = "192.168.110.110"
$ctrlPoolPrefixLen = "24"
$ctrlPoolGw = "192.168.110.2"
$ctrlCluster = "RegionA01-EDGE01"
$ctrlDatastoreName = "RegionA01-ISCSI01-EDGE01"
$ctrlNetwork = "VM-RegionA01-vDS-EDGE"
$ctrlPassword = "VMware1!VMware1!"

#Host VIBs Installation and VXLAN Configuration
$nsxClusterList = "RegionA01-EDGE01", "RegionA01-COMP01" #List clusters where VIBs must be deployed
$vxlanVds = @{"RegionA01-EDGE01" = "RegionA01-vDS-EDGE" ; "RegionA01-COMP01" = "RegionA01-vDS-COMP"} #VDS to be prepared for vxlan on each cluster
$vxlanVlanId = "0"
$vxlanPoolStart = "192.168.130.101"
$vxlanPoolEnd = "192.168.130.140"
$vxlanPoolPrefixLen = "24"
$vxlanPoolGw = "192.168.130.1"

#Logical Switches Configuration
$segmentIdRange = @(5000 ; 6000) #Start and end of the range for VXLAN segments allocation
$transportZoneName = "Local_Transport_Zone" #A single Transport Zone will deployed 

#Physical Network Integration
$edgePassword = "VMware1!VMware1!" #Password for ESGs. DLR psw must be manually updated after deployment
$edgeCluster = "RegionA01-EDGE01" #Cluster where ECMP edges for physical integration will be deployed
$edgeDatastore = "RegionA01-ISCSI01-EDGE01"# Datastore where ECMP ESGs will be deployed
$dlrCluster = "RegionA01-COMP01" #Cluster where DLR VM will be deployed. In this case the compute cluster has been chosen because the minimun of 4 hosts in the edge cluster is not met
$dlrDatastore = "RegionA01-ISCSI01-COMP01" #Datastore where DLR Control VM will be deployed
$dlrMgmtNetwork = "VM-RegionA01-vDS-COMP" #Management port-group for the DLR Control VM 
$formFactor = "compact" #Form factor for all the edges
$vlanIdp2p1 = "0" #Vlan Id of the point to point lik to the first physical router. Used for dynamic routing peering
$vlanIdp2p2 = "0" #Vlan Id of the point to point lik to the second physical router. Used for dynamic routing peering
$p2p1Uplink = "1" #Uplink # for the first routed link for P2V integration. i.e. "1" means "Uplink 1" of the DVS. DVS is assumed to be the same one that was prepared for VXLAN
$p2p2Uplink = "2" #Uplink # for the first routed link for P2V integration. i.e. "2" means "Uplink 2" of the DVS. DVS is assumed to be the same one that was prepared for VXLAN

#IP addresses 
#Specify IPs for the two ECMP ESG for P2V integration, Format is @("Interface IP" ; "Netmask")
$edge1IP1 = @("10.0.1.1" ; 24) #ESG1 IP on Routed Port-Group 1 VLAN backed
$edge1IP2 = @("10.0.2.1" ; 24) #ESG1 IP on Routed Port-Group 2 VLAN backed
$edge2IP1 = @("10.0.1.2" ; 24) #ESG2 IP on Routed Port-Group 1 VLAN backed
$edge2IP2 = @("10.0.2.2" ; 24) #ESG2 IP on Routed Port-Group 2 VLAN backed

#Specify IPs for every component residing on the ruted transit between the two ECMP ESGs and the DLR
$transitEdge1 = @("10.0.3.1" ; 24) #Edge1
$transitEdge2 = @("10.0.3.2" ; 24) #Edge2
$transitDlrFrw = @("10.0.3.3" ; 24) #DLR Forwarding Address
$transitDlrPrt = @("10.0.3.4" ; 24) #DLR Protcol Address

$workloadNetworkIp = @("10.1.0.1"; 24) #Test VM Network connected to the DLR
$workloadRange = @("10.1.0.0"; 16) #IP range covering all VM network that will be connected to the DLR

#BGP Routing
$nsxAs = "65001" #NSX domain Autonomous System
$torAs = "65002" # Physical Network Autonomous System
$edge1RouterId = "10.255.255.1" #ESG1 BGP Router ID
$edge2RouterId = "10.255.255.2" #ESG2 BGP Router ID
$dlrRouterId = "10.255.255.3" #DLR BGP Router ID
$tor1Ip = "10.0.1.254" # Top Of Rack Switch 1 IP used for BGP session termination 
$tor2Ip = "10.0.2.254" # Top Of Rack Switch 2 IP used for BGP session termination 


#endregion

#####DO NOT Edit Below this line######


#region Environment Preparation. Add PowerCLI and PowerNSX modules, add functions by Arnim van Lieshout to manage DRS rules
Write-Host "Adding PowerCLIand PowerNSX Modules"



if ( !(Get-Module -Name VMware.VimAutomation.Core -ErrorAction SilentlyContinue) ) {
. 'C:\Program Files (x86)\VMware\Infrastructure\PowerCLI\Scripts\Initialize-PowerCLIEnvironment.ps1'
}



#region Functions for DRS rules management

Function New-DrsVmGroup {
<#
.SYNOPSIS
  Creates a new DRS VM group
.DESCRIPTION
  This function creates a new DRS VM group in the DRS Group Manager
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VM
  The VMs to add to the group. Supports objects from the pipeline.
.PARAMETER Cluster
  The cluster to create the new group on.
.PARAMETER Name
  The name for the new group.
.EXAMPLE
  PS> Get-VM VM001,VM002 | New-DrsVmGroup -Name "VmGroup01" -Cluster CL01
.EXAMPLE
  PS> New-DrsVmGroup -VM VM001,VM002 -Name "VmGroup01" -Cluster (Get-CLuster CL01)
#>

	Param(
		[parameter(valuefrompipeline = $true, mandatory = $true,
		HelpMessage = "Enter a vm entity")]
			[PSObject]$VM,
		[parameter(mandatory = $true,
		HelpMessage = "Enter a cluster entity")]
			[PSObject]$Cluster,
		[parameter(mandatory = $true,
		HelpMessage = "Enter a name for the group")]
			[String]$Name)

	begin {
	    switch ($Cluster.gettype().name) {
      		"String" {$cluster = Get-Cluster $cluster | Get-View}
      		"ClusterImpl" {$cluster = $cluster | Get-View}
      		"Cluster" {}
      		default {throw "No valid type for parameter -Cluster specified"}
		}
		$spec = New-Object VMware.Vim.ClusterConfigSpecEx
		$group = New-Object VMware.Vim.ClusterGroupSpec
		$group.operation = "add"
		$group.Info = New-Object VMware.Vim.ClusterVmGroup
		$group.Info.Name = $Name
	}

	Process {
		switch ($VM.gettype().name) {
      		"String" {Get-VM -Name $VM | %{$group.Info.VM += $_.Extensiondata.MoRef}}
      		"UniversalVirtualMachineImpl" {$group.Info.VM += $VM.Extensiondata.MoRef}
      		"VirtualMachine" {$group.Info.VM += $VM.MoRef}
      		default {throw "No valid type for parameter -VM specified"}
	    }
	}

	End {
		if ($group.Info.VM) {
			$spec.GroupSpec += $group
			$cluster.ReconfigureComputeResource_Task($spec,$true)
		}
		else {
      		throw "No valid VMs specified"
		}
	}
}


Function New-DrsHostGroup {
<#
.SYNOPSIS
  Creates a new DRS host group
.DESCRIPTION
  This function creates a new DRS host group in the DRS Group Manager
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VMHost
  The hosts to add to the group. Supports objects from the pipeline.
.PARAMETER Cluster
  The cluster to create the new group on.
.PARAMETER Name
  The name for the new group.
.EXAMPLE
  PS> Get-VMHost ESX001,ESX002 | New-DrsHostGroup -Name "HostGroup01" -Cluster CL01
.EXAMPLE
  PS> New-DrsHostGroup -Host ESX001,ESX002 -Name "HostGroup01" -Cluster (Get-CLuster CL01)
#>
 
    Param(
        [parameter(valuefrompipeline = $true, mandatory = $true,
        HelpMessage = "Enter a host entity")]
            [PSObject]$VMHost,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a cluster entity")]
            [PSObject]$Cluster,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a name for the group")]
            [String]$Name)
 
    begin {
        switch ($Cluster.gettype().name) {
            "String" {$cluster = Get-Cluster $cluster | Get-View}
            "ClusterImpl" {$cluster = $cluster | Get-View}
            "Cluster" {}
            default {throw "No valid type for parameter -Cluster specified"}
        }
        $spec = New-Object VMware.Vim.ClusterConfigSpecEx
        $group = New-Object VMware.Vim.ClusterGroupSpec
        $group.operation = "add"
        $group.Info = New-Object VMware.Vim.ClusterHostGroup
        $group.Info.Name = $Name
    }
 
    Process {
        switch ($VMHost.gettype().name) {
            "String" {Get-VMHost -Name $VMHost | %{$group.Info.Host += $_.Extensiondata.MoRef}}
            "VMHostImpl" {$group.Info.Host += $VMHost.Extensiondata.MoRef}
            "HostSystem" {$group.Info.Host += $VMHost.MoRef}
            default {throw "No valid type for parameter -VMHost specified"}
        }
    }
 
    End {
        if ($group.Info.Host) {
            $spec.GroupSpec += $group
            $cluster.ReconfigureComputeResource_Task($spec,$true)
        }
        else {
            throw "No valid hosts specified"
        }
    }
}


Function New-DRSVMToHostRule{
<#
.SYNOPSIS
  Creates a new DRS VM to host rule
.DESCRIPTION
  This function creates a new DRS vm to host rule
.NOTES
  Author: Arnim van Lieshout
.PARAMETER VMGroup
  The VMGroup name to include in the rule.
.PARAMETER HostGroup
  The VMHostGroup name to include in the rule.
.PARAMETER Cluster
  The cluster to create the new rule on.
.PARAMETER Name
  The name for the new rule.
.PARAMETER AntiAffine
  Switch to make the rule an AntiAffine rule. Default rule type is Affine.
.PARAMETER Mandatory
  Switch to make the rule mandatory (Must run rule). Default rule is not mandatory (Should run rule)
.EXAMPLE
  PS> New-DrsVMToHostRule -VMGroup "VMGroup01" -HostGroup "HostGroup01" -Name "VMToHostRule01" -Cluster CL01 -AntiAffine -Mandatory
#>
 
    Param(
        [parameter(mandatory = $true,
        HelpMessage = "Enter a VM DRS group name")]
            [String]$VMGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a host DRS group name")]
            [String]$HostGroup,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a cluster entity")]
            [PSObject]$Cluster,
        [parameter(mandatory = $true,
        HelpMessage = "Enter a name for the group")]
            [String]$Name,
            [Switch]$AntiAffine,
            [Switch]$Mandatory)
 
    switch ($Cluster.gettype().name) {
        "String" {$cluster = Get-Cluster $cluster | Get-View}
        "ClusterImpl" {$cluster = $cluster | Get-View}
        "Cluster" {}
        default {throw "No valid type for parameter -Cluster specified"}
    }
 
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $rule = New-Object VMware.Vim.ClusterRuleSpec
    $rule.operation = "add"
    $rule.info = New-Object VMware.Vim.ClusterVmHostRuleInfo
    $rule.info.enabled = $true
    $rule.info.name = $Name
    $rule.info.mandatory = $Mandatory
    $rule.info.vmGroupName = $VMGroup
    if ($AntiAffine) {
        $rule.info.antiAffineHostGroupName = $HostGroup
    }
    else {
        $rule.info.affineHostGroupName = $HostGroup
    }
    $spec.RulesSpec += $rule
    $cluster.ReconfigureComputeResource_Task($spec,$true)
}


#endregion


#endregion

#region connect to vCenter
try
{
Connect-VIServer -Username $vcUser -Password $vcPass $vcenterFqdn
}
catch
{ 
throw "Connection to vCenter failed.Please verify vCenter FQDN and credentials"
}
#endregion

#region Input Verification#########

try
{
 [ipaddress]$dns | Out-Null
}
catch
{ 
throw $dns + " :dns value is not a valid IP address"
}

try
{
 [ipaddress]$ntp | Out-Null
}
catch
{ 
throw $ntp + " :NTP value is not a valid IP address"
}

try
{
 [ipaddress]$syslog | Out-Null
}
catch
{ 
throw $syslog + " :Syslog value is not a valid IP address"
}

try
{
 [ipaddress]$nsxMgrIp | Out-Null
 [ipaddress]$nsxMgrNetmask | Out-Null
 [ipaddress]$nsxMgrGateway | Out-Null
}
catch
{ 
throw "There is an error in the IP settings for NSX Manager"
}

try
{
 Get-Cluster -Name $nsxMgrCluster | Out-Null
}
catch
{ 
throw $nsxMgrCluster + " is not a valid cluster to deploy NSX Manager. Verify `$nsxManagerCluster` parameter "
}

try
{
 Get-Datastore -Name $nsxMgrDatastoreName | Out-Null
}
catch
{ 
throw $nsxMgrDatastoreName + " is not a valid datastore to deploy NSX Manager. Verify `$nsxManagerDatastoreName` parameter "
}

try
{
 Get-VDPortgroup -name $nsxMgrPortGroupName | Out-Null
}
catch
{ 
throw $nsxMgrPortGroupName + " is not a valid distributed port group to deploy NSX Manager. Verify `$nsxMgrPortGroupName` parameter "
}

try
{
 [ipaddress]$vxlanPoolStart | Out-Null
 [ipaddress]$vxlanPoolEnd | Out-Null
 [ipaddress]$vxlanPoolGw | Out-Null
}
catch
{ 
throw "There is an error in the IP settings for NSX VXLAN Pool"
}


try
{
 Get-Cluster -Name $ctrlCluster | Out-Null
}
catch
{ 
throw $ctrlCluster + " is not a valid cluster to deploy NSX Controllers. Verify `$nsxCtrlCluster` parameter "
}

try
{
 Get-Datastore -Name $ctrlDatastoreName | Out-Null
}
catch
{ 
throw $ctrlDatastoreName + " is not a valid datastore to deploy NSX Controllers. Verify `$ctrlDatastoreName` parameter "
}

try
{
 Get-VDPortgroup -name $ctrlNetwork | Out-Null
}
catch
{ 
throw $ctrlNetwork + " is not a valid distributed port group to deploy NSX Controllers. Verify `$ctrlNetwork` parameter "
}

try
{
 Get-Cluster -Name $edgeCluster | Out-Null
}
catch
{ 
throw $edgeCluster + " is not a valid clusterfor the Edge Cluster. Verify `$edgeCluster` parameter "
}

try
{
 Get-Cluster -name $edgeCluster | Get-Datastore -Name $edgeDatastore | Out-Null
}
catch
{ 
throw $edgeDatastore + " is not a valid datastore to deploy ESGs in the edge cluster. Verify `$ctrlDatastoreName` parameter "
}

try
{
for ($i=0 ; $i -le ($nsxClusterList.Length - 1) ; $i++) {
        Get-Cluster -name $nsxClusterList[$i] | Out-Null
        }
}
catch
{ 
throw "List of cluster where NSX VIBs will be deployed is incorrect. Please check paramter `$nsxClusterList` "
}



try
{
for ($i=0 ; $i -le ($vxlanVds.Count - 1) ; $i++) {
        Get-Cluster -name $nsxClusterList[$i] | Get-VMHost | Get-VDSwitch -name $vxlanVds.Get_Item($nsxClusterList[$i]) | Out-Null
        }
}
catch
{ 
throw "List of VDS to be prepared for VXLAN on each cluster  is incorrect. Please check paramter `$vxlanVds` "
}


try
{
 Get-Cluster -Name $dlrCluster | Out-Null
}
catch
{ 
throw $dlrCluster + " is not a valid cluster to deploy the DLR. Verify `$dlrCluster` parameter "
}

try
{
 Get-Datastore -Name $dlrDatastore | Out-Null
}
catch
{ 
throw $dlrDatastore + " is not a valid datastore to deploy the DLR. Verify `$dlrDatastore` parameter "
}

try
{
 Get-VDPortgroup -name $dlrMgmtNetwork | Out-Null
}
catch
{ 
throw $dlrMgmtNetwork + " is not a valid distributed port group to deploy NSX Controllers. Verify `$dlrMgmtNetwork` parameter "
}


try
{
 [ipaddress]$edge1IP1[0] | Out-Null
 [ipaddress]$edge2IP1[0] | Out-Null
 [ipaddress]$edge1IP2[0] | Out-Null
 [ipaddress]$edge2IP2[0] | Out-Null
}
catch
{ 
throw "There is an error in the IP settings for the section #Specify IPs for the two ECMP ESG for P2V integration"
}

try
{
 [ipaddress]$transitEdge1[0] | Out-Null
 [ipaddress]$transitEdge2[0] | Out-Null
 [ipaddress]$transitDlrFrw[0] | Out-Null
 [ipaddress]$transitDlrPrt[0] | Out-Null
 [ipaddress]$workloadNetworkIp[0] | Out-Null
 [ipaddress]$workloadRange[0] | Out-Null
}
catch
{ 
throw "There is an error in the IP settings for the section #Specify IPs for every component residing on the ruted transit between the two ECMP ESGs and the DLR"
}

try
{
 [ipaddress]$edge1RouterId | Out-Null
 [ipaddress]$edge2RouterId | Out-Null
 [ipaddress]$dlrRouterId | Out-Null
 [ipaddress]$tor1Ip | Out-Null
 [ipaddress]$tor2Ip | Out-Null
 [ipaddress]$workloadRange[0] | Out-Null
}
catch
{ 
throw "There is an error in the IP settings for the section BGP ROuting"
}



#endregion

#region Deploy NSX Manager#####

New-NSXManager -NsxManagerOVF $nsxOvfPath -Name $nsxMgrHostname -ClusterName $nsxMgrCluster -ManagementPortGroupName $nsxMgrPortGroupName -DatastoreName $nsxMgrDatastoreName -FolderName vm -CliPassword $nsxMgrPass -CliEnablePassword $nsxMgrPass -Hostname $nsxMgrHostname -IpAddress $nsxMgrIp -Netmask $nsxMgrNetmask -Gateway $nsxMgrGateway -DnsServer $dns -DnsDomain $domain -NtpServer $ntp -EnableSsh -StartVm -wait
 
Write-Host "$nsxMgrHostname has booted up successfully, Proceeding" -foregroundcolor 'Green'

$nsxServer = $nsxMgrHostname + "." + $domain

Connect-NsxServer -Username "admin" -Password $nsxMgrPass  $nsxServer

Set-NsxManager -SsoServer $ssoServer -SsoUserName $vcUser -SsoPassword $vcPass

Set-NsxManager -vcenterusername $vcUser -vcenterpassword $vcPass -vcenterserver $vcenterFqdn

Set-NsxManager -SyslogServer $syslog

#endregion

#region Deploy Controllers####

$ctrlPool = New-NsxIpPool -Name Controllers_IP_Pool -Gateway $ctrlPoolGw  -SubnetPrefixLength $ctrlPoolPrefixLen  -StartAddress $ctrlPoolStart -EndAddress  $ctrlPoolEnd

$ControllerCluster = Get-Cluster -name $ctrlCluster
$ControllerDatastore = Get-Datastore $ctrlDatastoreName 
$ControllerPortGroup = Get-VDPortGroup $ctrlNetwork 


for($i=1 ; $i -le 3 ; $i++){
       New-NsxController -ipPool $ctrlPool -cluster $ControllerCluster -datastore $ControllerDatastore -PortGroup $ControllerPortGroup -password $ctrlPassword  -confirm:$false -wait
       Write-Host "Controller number "$i" has been deployed" -foregroundcolor 'Green'
       }
     

$controllers = Get-NsxController

#Create VM DRS Groups for NSX Controllers VMs
for($i=0 ; $i -le 2 ; $i++){
        get-vm -name $controllers[$i].virtualMachineInfo.name | New-DrsVMgroup -name ("NSX_Controller0" + ($i+1) ) -cluster $ControllerCluster
        Write-Host "VM DRS Group for Controller "($i+1)" has been created" -foregroundcolor 'Green'
        }


$ControllerClusterHosts = Get-Cluster $ControllerCluster | Get-VMHost

#Create Host DRS Groups for hosts where NSX Controllers VMs are deployed
for($i=0 ; $i -lt $controllers.Length ; $i++){
        Get-VMHost  $ControllerClusterHosts[$i].name | New-DrsHostGroup -Name $ControllerClusterHosts[$i].Name -Cluster $ControllerCluster
        Write-Host "Host DRS Group for "$ControllerClusterHosts[$i].name" has been created" -foregroundcolor 'Green'
        }

#Create AntiAffinity rules for NSX Controllers VMs
for($i=0 ; $i -lt $Controllers.Length ; $i++){
        New-DRSVMToHostRule -VMGroup ("NSX_Controller0" + ($i+1) ) -HostGroup $ControllerClusterHosts[$i].name  -Cluster $ControllerCluster -Name (("NSX_Controller0" + ($i+1) )+"_should_run_on_"+$ControllerClusterHosts[$i].name)
        Write-Host "VM to Host Affinity rule for Controller "($i+1)" has been created" -foregroundcolor 'Green'
        }

#endregion

#region Add License to NSX
$LicenseManager = get-view ($global:DefaultVIServer.ExtensionData.content.LicenseManager)
$LicenseManager.AddLicense($nsxLicense,$null)
$LicenseAssignmentManager = get-view ($LicenseManager.licenseAssignmentManager)
$LicenseAssignmentManager.UpdateAssignedLicense("nsx-netsec",$nsxLicense,$Null)
#endregion

#region Host preparation: 
#Install VIBs on hosts
for($i=0 ; $i -lt $nsxClusterList.Length ; $i++){
       Install-NsxCluster -Cluster (get-cluster -name $nsxClusterList[$i]) -VxlanPrepTimeout 240
       Write-Host "Host preparation has been completed for cluster " $nsxClusterList[$i] -foregroundcolor 'Green'
        }

#Host Preparation: VXLAN Configuration

$vxlanPool = New-NsxIpPool -Name Vxlan_IP_Pool -Gateway $vxlanPoolGw  -SubnetPrefixLength $vxlanPoolPrefixLen  -StartAddress $vxlanPoolStart -EndAddress  $vxlanPoolEnd

for($i=0 ; $i -lt $nsxClusterList.Length ; $i++){
       $tempVDS=$vxlanVds.Get_Item($nsxClusterList[$i])
       New-NsxVdsContext -VirtualDistributedSwitch (Get-VDSwitch -Name $tempVDS) -Teaming LOADBALANCE_SRCID -Mtu 1600
       New-NsxClusterVxlanConfig -Cluster (get-cluster -name $nsxClusterList[$i]) -VirtualDistributedSwitch ( Get-VDSwitch -name  $tempVDS) -VlanId $vxlanVlanId -IpPool $vxlanPool -VtepCount 2
       Write-Host "vxlan Configuration has been completed for cluster " $nsxClusterList[$i] -foregroundcolor 'Green'
        }

#endregion

#region Transport Zone Preparation

New-NsxSegmentIdRange -Name VxlanId_Range -Begin $segmentIdRange[0] -End $segmentIdRange[1] 
New-NsxTransportZone -Name $transportZoneName -Cluster (Get-Cluster $nsxClusterList) -ControlPlaneMode UNICAST_MODE

#endregion

#region Physical Network Integration

$edgeVds = Get-VDSwitch -name ($vxlanVds.get_item($edgeCluster))
$routedLink1 = New-VDPortGroup -Name Routed_Link_1 -VLanId $vlanIdp2p1 -VDSwitch $edgeVds
$routedLink2 = New-VDPortGroup -Name Routed_Link_2 -VLanId $vlanIdp2p2 -VDSwitch $edgeVds

#Set Uplink Configuration for the first routed link portgroup 
$activeUplinks = "Uplink " + $p2p1Uplink
$unusedUplinks = @()

for($i=1 ; $i -le $edgeVds.NumUplinkPorts ; $i++){
        if ($i -ne $p2p1Uplink) { $unusedUplinks += ("Uplink " + $i)}
        }

$routedLink1 | Get-VDUplinkTeamingPolicy | Set-VDUplinkTeamingPolicy -ActiveUplinkPort $activeUplinks -UnusedUplinkPort $unusedUplinks

#Set Uplink Configuration for the second routed link portgroup 
$activeUplinks = "Uplink " + $p2p2Uplink
$unusedUplinks = @()

for($i=1 ; $i -le $edgeVds.NumUplinkPorts ; $i++){
        if ($i -ne $p2p2Uplink) { $unusedUplinks += ("Uplink " + $i)}
        }

$routedLink2 | Get-VDUplinkTeamingPolicy | Set-VDUplinkTeamingPolicy -ActiveUplinkPort $activeUplinks -UnusedUplinkPort $unusedUplinks

$LSTransit = Get-NsxTransportZone -name $transportZoneName | New-NsxLogicalSwitch -Name TransitEdgesToDlr
$WorkLoadNetwork = Get-NsxTransportZone -name $transportZoneName | New-NsxLogicalSwitch -Name WorkLoadNetwork


#endregion

#region Defining the uplink and internal interfaces to be used when deploying ESG 1.
$ESG1vNic0 = New-NsxEdgeinterfacespec `
  -index 0 `
  -Name "P2P Routed Uplink1" `
  -type Uplink `
  -ConnectedTo $routedLink1 `
  -PrimaryAddress $edge1IP1[0] `
  -SubnetPrefixLength $edge1IP1[1]

  $ESG1vNic1 = New-NsxEdgeinterfacespec `
  -index 1 `
  -Name "P2P Routed Uplink2" `
  -type Uplink `
  -ConnectedTo $routedLink2 `
  -PrimaryAddress $edge1IP2[0] `
  -SubnetPrefixLength $edge1IP2[1]

  $ESG1vNic2 = New-NsxEdgeinterfacespec `
  -index 2 `
  -Name TransitEdgesToDlr `
  -type Internal `
  -ConnectedTo $LSTransit `
  -PrimaryAddress $transitEdge1[0] `
  -SubnetPrefixLength $transitEdge1[1]
  
  #endregion

  #Deploy Edge 1
   $Edge1 = New-NsxEdge `
  -Name ecmpEdge01 `
  -Cluster (get-cluster $edgeCluster) `
  -Datastore (get-datastore $edgeDatastore) `
  -Interface $ESG1vNic0, $ESG1vNic1, $ESG1vNic2 `
  -Password $edgePassword `
  -FormFactor $formFactor `
  -EnableSSH `
  -EnableSyslog `
  -SyslogServer $syslog `
  -FwEnabled:$false

  

  #region Defining the uplink and internal interfaces to be used when deploying ESG 2.
$ESG2vNic0 = New-NsxEdgeinterfacespec `
  -index 0 `
  -Name "P2P Routed Uplink1" `
  -type Uplink `
  -ConnectedTo $routedLink1 `
  -PrimaryAddress $edge2IP1[0] `
  -SubnetPrefixLength $edge2IP1[1]

  $ESG2vNic1 = New-NsxEdgeinterfacespec `
  -index 1 `
  -Name "P2P Routed Uplink2" `
  -type Uplink `
  -ConnectedTo $routedLink2 `
  -PrimaryAddress $edge2IP2[0] `
  -SubnetPrefixLength $edge2IP2[1]

  $ESG2vNic2 = New-NsxEdgeinterfacespec `
  -index 2 `
  -Name TransitEdgesToDlr `
  -type Internal `
  -ConnectedTo $LSTransit `
  -PrimaryAddress $transitEdge2[0] `
  -SubnetPrefixLength $transitEdge2[1]
  
  #endregion

  #Deploy Edge 2
   $Edge2 = New-NsxEdge `
  -Name ecmpEdge02 `
  -Cluster (get-cluster $edgeCluster) `
  -Datastore (get-datastore $edgeDatastore) `
  -Interface $ESG2vNic0, $ESG2vNic1, $ESG2vNic2 `
  -Password $edgePassword `
  -FormFactor $formFactor `
  -EnableSSH `
  -EnableSyslog `
  -SyslogServer $syslog `
  -FwEnabled:$false


  #Create Antiaffinity rule to kep the two ECMP edges on separate hosts
  $edge1VM = get-vm -name ecmpEdge01*
  $edge2VM = get-vm -name ecmpEdge02*
  New-DrsRule -Cluster (Get-Cluster $edgeCluster) -Name KeepEcmpEdgesSeparate -KeepTogether $false -VM @($edge1VM,$edge2VM)


#region DLR Creation

# DLR Appliance has the uplink router interface created first.
Write-Host "Creating NSX DLR"
$DLRvNic0 = New-NsxLogicalRouterInterfaceSpec `
  -type Uplink `
  -Name "TransitEdgesToDlr" `
  -ConnectedTo $LSTransit `
  -PrimaryAddress $transitDlrFrw[0] `
  -SubnetPrefixLength $transitDlrFrw[1] 

# The DLR is created with the first vNic defined, and the datastore and cluster 
# on which the Control VM will be deployed.
$DLR = New-NsxLogicalRouter `
  -Name dlr01 `
  -ManagementPortGroup ( Get-VDPortgroup $dlrMgmtNetwork) `
  -Interface $DLRvNic0 `
  -Cluster (Get-Cluster  $dlrCluster) `
  -Datastore (Get-Datastore  $dlrDatastore) `
  -EnableHA:$true `


## Adding DLR interfaces after the DLR has been deployed.
Write-Host "Adding  LIF to DLR"
$DLR | New-NsxLogicalRouterInterface `
  -Type Internal `
  -name "WorkloadNetwork" `
  -ConnectedTo $WorkLoadNetwork `
  -PrimaryAddress $workloadNetworkIp[0] `
  -SubnetPrefixLength $workloadNetworkIp[1]

  #endregion

  #region Set Routing ecmpEdge01

  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting| Set-NsxEdgeRouting -EnableBGP -RouterId $edge1RouterId -LocalAS $nsxAs -EnableEcmp:$true -EnableLogging:$true -Confirm:$false

  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting| Set-NsxEdgeRouting -Confirm:$false -EnableBgpRouteRedistribution
  
  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting | Set-NsxEdgeBgp -GracefulRestart:$false -Confirm:$false 

  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting | New-NsxEdgeBgpNeighbour -IpAddress $tor1Ip -RemoteAS $torAs -Confirm:$false -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting | New-NsxEdgeBgpNeighbour -IpAddress $tor2Ip -RemoteAS $torAs -Confirm:$false -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting | New-NsxEdgeBgpNeighbour -IpAddress $transitDlrPrt[0] -RemoteAS $nsxAs -Confirm:$false -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting | New-NsxEdgeRedistributionRule -Learner bgp -FromStatic -FromConnected -Action permit -Confirm:$false

  Get-NsxEdge ecmpEdge01 | Get-NsxEdgeRouting | New-NsxEdgeStaticRoute -Network ( $workloadRange[0] + "/" + $workloadRange[1] ) -NextHop $transitDlrFrw[0] -Confirm:$false

  #endregion

  #region Set Routing ecmpEdge02

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting| Set-NsxEdgeRouting -EnableBGP -RouterId $edge2RouterId -LocalAS $nsxAs -EnableEcmp:$true -EnableLogging:$true -Confirm:$false 

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting| Set-NsxEdgeRouting -Confirm:$false -EnableBgpRouteRedistribution

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting | Set-NsxEdgeBgp -GracefulRestart:$false -Confirm:$false 

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting | New-NsxEdgeBgpNeighbour -IpAddress $tor1Ip -RemoteAS $torAs -Confirm:$false -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting | New-NsxEdgeBgpNeighbour -IpAddress $tor2Ip -RemoteAS $torAs -Confirm:$false -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting | New-NsxEdgeBgpNeighbour -IpAddress $transitDlrPrt[0] -RemoteAS $nsxAs -Confirm:$false -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting | New-NsxEdgeRedistributionRule -Learner bgp -FromStatic -FromConnected -Action permit -Confirm:$false

  Get-NsxEdge ecmpEdge02 | Get-NsxEdgeRouting | New-NsxEdgeStaticRoute -Network ( $workloadRange[0] + "/" + $workloadRange[1] ) -NextHop $transitDlrFrw[0] -Confirm:$false

  #endregion

  #region Set DLR Routing

  Get-NsxLogicalRouter dlr01 | Get-NsxLogicalRouterRouting | Set-NsxLogicalRouterRouting -Confirm:$false -EnableBgp -RouterId $dlrRouterId -LocalAS $nsxAs -EnableEcmp:$true -EnableLogging

  Get-NsxLogicalRouter dlr01 | Get-NsxLogicalRouterRouting | Set-NsxLogicalRouterRouting -EnableBgpRouteRedistribution -Confirm:$false

  Get-NsxLogicalRouter dlr01 | Get-NsxLogicalRouterRouting | New-NsxLogicalRouterBgpNeighbour -IpAddress $transitEdge1[0] -RemoteAS $nsxAs -Confirm:$false -ForwardingAddress $transitDlrFrw[0] -ProtocolAddres $transitDlrPrt[0] -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxLogicalRouter dlr01 | Get-NsxLogicalRouterRouting | New-NsxLogicalRouterBgpNeighbour -IpAddress $transitEdge2[0] -RemoteAS $nsxAs -Confirm:$false -ForwardingAddress $transitDlrFrw[0] -ProtocolAddres $transitDlrPrt[0] -HoldDownTimer 3 -KeepAliveTimer 1

  Get-NsxLogicalRouter dlr01 | Get-NsxLogicalRouterRouting | New-NsxLogicalRouterRedistributionRule -Learner bgp -FromConnected -Action permit -Confirm:$false

  #endregion
