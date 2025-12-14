# Set all firewall CVEs to false positive

.vulnerabilities |= map(
  if (.properties[]?.value == "firewall@1.0") then
    (
      .affects[].versions[].status = "unaffected"
      | .analysis.state = "false_positive"
      | .analysis |= del(.justification)
      | .analysis |= del(.response)
      | .analysis |= del(.detail)
    )
  else
    .
  end
)
