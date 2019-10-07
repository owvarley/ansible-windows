echo "Forcing global HTTP firewall access"
# this is a fairly naive implementation; could be more sophisticated about rule matching/collapsing
$fw = New-Object -ComObject HNetCfg.FWPolicy2

# try to find/enable the default rule first
$add_rule = $false
$matching_rules = $fw.Rules | Where-Object  { $_.Name -eq "Windows Remote Management (HTTP-In)" }
$rule = $null
If ($matching_rules) {
    If ($matching_rules -isnot [Array]) {
        echo "Editing existing single HTTP firewall rule"
        $rule = $matching_rules
    }
    Else {
        # try to find one with the All or Public profile first
        echo "Found multiple existing HTTP firewall rules..."
        $rule = $matching_rules | ForEach-Object { $_.Profiles -band 4 }[0]

        If (-not $rule -or $rule -is [Array]) {
            echo "Editing an arbitrary single HTTP firewall rule (multiple existed)"
            # oh well, just pick the first one
            $rule = $matching_rules[0]
        }
    }
}

If (-not $rule) {
    echo "Creating a new HTTP firewall rule"
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Name = "Windows Remote Management (HTTP-In)"
    $rule.Description = "Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]"
    $add_rule = $true
}

$rule.Profiles = 0x7FFFFFFF
$rule.Protocol = TCP, UDP
$rule.LocalPorts = 5985
$rule.RemotePorts = "*"
$rule.LocalAddresses = "*"
$rule.RemoteAddresses = "*"
$rule.Enabled = $true
$rule.Direction = 1
$rule.Action = 1
$rule.Grouping = "Windows Remote Management"

If ($add_rule) {
    $fw.Rules.Add($rule)
}

echo "HTTP firewall rule $($rule.Name) updated"
