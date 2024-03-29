If ([Environment]::Is64BitOperatingSystem) {
    $PFPATH="C:\Program Files (x86)"
} else {
    $PFPATH="C:\Program Files"
}

if ( -Not ( Select-String -Path "$PFPATH\ossec-agent\ossec.conf" -Pattern ' Added Wazuh 2022 Root CA ' ) ) {
	$FirstConfigToWrite = @"   
		-----BEGIN CERTIFICATE-----
		MIIDxTCCAq2gAwIBAgIUGWyk0+lURWSWsJhd1vE7G2hbgUUwDQYJKoZIhvcNAQEL
		BQAwcjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExETAPBgNVBAcM
		CFNhbiBKb3NlMRIwEAYDVQQKDAlXYXp1aCBJbmMxFDASBgNVBAsMC0VuZ2luZWVy
		aW5nMREwDwYDVQQDDAhXYXp1aCBDQTAeFw0yMjA4MTgxNTQxMjhaFw0yNzA4MTcx
		NTQxMjhaMHIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMREwDwYD
		VQQHDAhTYW4gSm9zZTESMBAGA1UECgwJV2F6dWggSW5jMRQwEgYDVQQLDAtFbmdp
		bmVlcmluZzERMA8GA1UEAwwIV2F6dWggQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB
		DwAwggEKAoIBAQDThxBFPo90nODJ81CVDXtCr9yHzPWzzQo0QnyzzKd69yaIz6FH
		VZhgbv5w6c0lsxRoJFKxtMJS3HCWijIAPAfB2qPn/Z7ftOjaxoH8nJuWUpjkBP0/
		O1Qm42S1MZpiuUPC9pXt6AMQHyBwSWgJmDcsF7BVrkR7WHv4XwtNN27pAS427te9
		lb0m635ZYbH0t8D2VCEtBmQ3wvlUxR1hI/FLwFJvCQb7j6pfm7ZpV+JN4NYYnq3L
		3nFXkfVRQsDrcRzidQMHvWr1BoP4FCm507g2ZBHJoTN+WKgpzKhFEZPdvoVIFfJU
		GPRjzWNvDniQG6U0YAQglXDo/7c4G3tSgvbxAgMBAAGjUzBRMB0GA1UdDgQWBBRU
		Q9m4p3d8qnueS+iEVeXF8x5PpDAfBgNVHSMEGDAWgBRUQ9m4p3d8qnueS+iEVeXF
		8x5PpDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQACmQaHimVB
		hQJmmgrVWtwOjRSCsSOj3EcCN6mpiYZAzU3wT6Y+/M5a1UzWdpuAYzV8FVkyn7kR
		+PcQRduFTbhraPA5Z9Lk+C7KkqqezABg3dqOEMsAvCTZDYUjAAm1iirvePPmF/nh
		56aigQAgJI9XhtS532ONvwV2HK9CrtlHW8cFDr2cb1JRFhzQDiloSFQ2WhZywN15
		O9qxZSYXaVfHe+spexZMa4Eu+u1yYRYNO4qKyecD7DYp05zl+lXH1d2aq5foCofA
		N353E+bKFRK7Dk+naVj1xIj8PqHW8mH22AxAOiote+QUHKcc+dHIuwPIimAo1rSX
		DyJn7XWZZiTF
		-----END CERTIFICATE-----
		"@
	$FirstConfigToWrite | Out-File -FilePath "$PFPATH\ossec-agent\wpk_root_2022.pem" -Encoding ASCII
	$SecondConfigToWrite = @"   
		<!-- Added Wazuh 2022 Root CA -->
		<ossec_config>
		   <agent-upgrade>
			  <ca_verification>
				 <enabled>yes</enabled>
				 <ca_store>wpk_root.pem</ca_store>
				 <ca_store>wpk_root_2022.pem</ca_store>
			  </ca_verification>
		   </agent-upgrade>
		</ossec_config>
		"@
	$SecondConfigToWrite | Out-File -Append -FilePath "$PFPATH\ossec-agent\ossec.conf" -Encoding ASCII
}

Restart-Service WazuhSvc
