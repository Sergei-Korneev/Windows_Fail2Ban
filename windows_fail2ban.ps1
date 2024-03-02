 # This Powershell script blocks all ip's with unsuccesful remote logins 
 # Sergei Korneev 2024
 
 
 # Get latest n records
 $LatestRecords = 3000

 # Ip Regexp
 $IpRegexp = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

 # SubNet regexp
 $SubnetRegexp = '\d{1,3}\.\d{1,3}\.\d{1,3}\.'

 # Mask 
 $Mask = '255.255.255.0'
 
 # Firewall Ip Name
 $FirewallRuleName = 'Fail2Ban (Sergei Korneev)'

 # Unsuccesful logins
 $CountToBan  = 3


 # Block Network
 $BlockSubNet = 1

 
 # Exclusions list 
 #$Exclusions = @('80.66.88.214')
 $Exclusions = @('91.188.144.0/21', '91.188.144.0/24')

Write-Host "

Current subnet setting (block subnet) is" $BlockSubNet  " 

Searching for Firewall rule named"  $FirewallRuleName  "

"
 


$ips = ( Get-NetFirewallRule -DisplayName $FirewallRuleName  | Get-NetFirewallAddressFilter ).RemoteAddress 
   
 
if ($ips -eq $null) {
    Write-Host "Creating new Firewall rul..."
    New-NetFirewallRule -DisplayName  $FirewallRuleName  -Direction Inbound
    $ips = @()
}elseif ($ips -eq 'Any'){
    $ips = @()
}
  
 
 Write-Host  $ips

 Get-EventLog -LogName Security   -Newest $LatestRecords |
   where {$_.EntryType -eq "FailureAudit" }  |
   Select-Object -Property *  |
   Out-String -Stream  |
   Select-String -Pattern $IpRegexp  | 
   foreach { [regex]::match($_, $IpRegexp).Groups[0].Value}  |
   group  |
   foreach {
     if ($_.Count -gt $CountToBan) {
      



      $CIDR = (
         (-join (
      $Mask.ToString().split('.') | 
           foreach {[convert]::ToString($_,2)} #convert each octet to binary
                ) #and join to one string
          ).ToCharArray() | where {$_ -eq '1'} #then only keep '1'
        ).Count


       $SubnetCIDR = [regex]::match($_.Name,$SubnetRegexp).Groups[0].Value + "0/"+$CIDR
       $SubnetM = [regex]::match($_.Name,$SubnetRegexp).Groups[0].Value + "0/"+$Mask

       if ($BlockSubNet -eq 1 ){
         $IpToBlock = $SubnetCIDR
       }else{
         $IpToBlock = $_.Name
       }



       if ($ips.Contains($_.Name) -or $ips.Contains($SubnetM) ){
       

         Write-Host "The ip" $_.Name "has" $_.Count "unsuccesful login attempts (already added)."
       }
       else{
         
          if ( $Exclusions.Contains($IpToBlock)){
             Write-Host "The ip" $IpToBlock "found in exclusions. Skipping."
              
          }
          else{
                Write-Host "The ip" $_.Name "has" $_.Count "unsuccesful login attempts. Adding " $IpToBlock " to list."
                $ips += $IpToBlock
             
             
          }
         
       }
      

     }
   }

 

Write-Host "

Updating Firewall rule named"  $FirewallRuleName
 
  
 Write-Host  $ips

Set-NetFirewallRule -DisplayName $FirewallRuleName  -Action Block -RemoteAddress $ips

