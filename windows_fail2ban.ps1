 # This Powershell script blocks all ip's with unsuccesful remote logins 
 # Sergei Korneev 2024
 
 
 # Get latest n records
 $LatestRecords = 2000

 # Ip Regexp
 $IpRegexp = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

 # SubNet regexp
 $SubnetRegexp = '\d{1,3}\.\d{1,3}\.\d{1,3}\.'

 # CIDR 
 $Cidr = 24
 
 # Firewall Ip Name
 $FirewallRuleName = 'Fail2Ban (Sergei Korneev)'

 # Unsuccesful logins
 $CountToBan  = 3


 # Block Network
 $BlockSubNet = 1

 
 # Exclusions list 
 #$Exclusions = @('80.66.88.214')
 $Exclusions = @()

Write-Host "

Searching for Firewall rule named"  $FirewallRuleName  "

"
 


$ips = ( Get-NetFirewallRule -DisplayName $FirewallRuleName  | Get-NetFirewallAddressFilter ).RemoteAddress 
   
 
if ($ips -eq $null) {
    Write-Host "Creating new Firewall rul..."
    New-NetFirewallRule -DisplayName  $FirewallRuleName  -Direction Inbound
    $ips = @()
}
  
 
 Get-EventLog -LogName Security   -Newest $LatestRecords |
   where {$_.EntryType -eq "FailureAudit" }  |
   Select-Object -Property *  |
   Out-String -Stream  |
   Select-String -Pattern $IpRegexp  | 
   foreach { [regex]::match($_, $IpRegexp).Groups[0].Value}  |
   group  |
   foreach {
     if ($_.Count -gt $CountToBan) {
      
       $Subnet = [regex]::match($_.Name,$SubnetRegexp).Groups[0].Value + "0/"+$Cidr

       if ($ips.Contains($_.Name) -or $ips.Contains($Subnet) ){
         Write-Host "The ip" $_.Name "has" $_.Count "unsuccesful login attempts (already added)."
       }
       else{
         Write-Host "The ip" $_.Name "has" $_.Count "unsuccesful login attempts. Adding to list."
          if ( $Exclusions.Contains($_.Name)){
             Write-Host "The ip" $_.Name "found in exclusions. Skipping."
              
          }
          else{
             if ($BlockSubNet -eq 1 ){
                $ips +=  $Subnet
             }
             else{
                $ips += $_.Name
             }
             
          }
         
       }
      

     }
   }

 

Write-Host "

Updating Firewall rule named"  $FirewallRuleName
 


Set-NetFirewallRule -DisplayName $FirewallRuleName  -Action Block -RemoteAddress $ips

