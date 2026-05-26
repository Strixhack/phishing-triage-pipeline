rule Phishing_CredentialHarvest {
    meta:
        description = "Credential harvesting page indicators"
        severity    = "high"
        mitre       = "T1566.002"
        tags        = "phishing,credential,harvest"
    strings:
        $s1 = "password" nocase
        $s2 = "username" nocase
        $s3 = "login" nocase
        $s4 = "verify your account" nocase
        $s5 = "account suspended" nocase
        $s6 = "update your information" nocase
        $url1 = "http://"
        $url2 = "https://"
    condition:
        (2 of ($s*)) and (1 of ($url*))
}

rule Phishing_UrgencyKeywords {
    meta:
        description = "High-urgency social engineering language"
        severity    = "medium"
        mitre       = "T1566.001"
        tags        = "phishing,social-engineering,urgency"
    strings:
        $u1 = "urgent" nocase
        $u2 = "immediate action" nocase
        $u3 = "within 24 hours" nocase
        $u4 = "account will be closed" nocase
        $u5 = "legal action" nocase
        $u6 = "final notice" nocase
        $u7 = "act now" nocase
        $u8 = "limited time" nocase
    condition:
        2 of ($u*)
}

rule Malware_OfficeMacro {
    meta:
        description = "Office document macro execution indicators"
        severity    = "critical"
        mitre       = "T1566.001"
        tags        = "malware,macro,office"
    strings:
        $m1 = "AutoOpen" nocase
        $m2 = "Document_Open" nocase
        $m3 = "Shell(" nocase
        $m4 = "WScript.Shell" nocase
        $m5 = "CreateObject" nocase
        $m6 = "PowerShell" nocase
        $m7 = "cmd.exe" nocase
    condition:
        2 of ($m*)
}

rule Malware_Dropper {
    meta:
        description = "Dropper behaviour - downloads and executes payload"
        severity    = "critical"
        mitre       = "T1105"
        tags        = "malware,dropper,execution"
    strings:
        $d1 = "DownloadFile" nocase
        $d2 = "URLDownloadToFile" nocase
        $d3 = "Invoke-WebRequest" nocase
        $d4 = "certutil" nocase
        $d5 = "bitsadmin" nocase
        $exe1 = ".exe"
        $exe2 = ".ps1"
        $exe3 = ".vbs"
    condition:
        (1 of ($d*)) and (1 of ($exe*))
}

rule Ransomware_Keywords {
    meta:
        description = "Ransomware payment demand indicators"
        severity    = "critical"
        mitre       = "T1486"
        tags        = "ransomware,extortion"
    strings:
        $r1 = "bitcoin" nocase
        $r2 = "cryptocurrency" nocase
        $r3 = "your files have been encrypted" nocase
        $r4 = "decrypt" nocase
        $r5 = "ransom" nocase
        $r6 = "wallet address" nocase
        $r7 = "BTC"
    condition:
        2 of ($r*)
}

rule BEC_WireTransfer {
    meta:
        description = "Business Email Compromise wire transfer fraud"
        severity    = "high"
        mitre       = "T1566.001"
        tags        = "bec,fraud,wire-transfer"
    strings:
        $b1 = "wire transfer" nocase
        $b2 = "bank transfer" nocase
        $b3 = "IBAN" nocase
        $b4 = "confidential" nocase
        $b5 = "do not discuss" nocase
        $b6 = "urgent payment" nocase
        $b7 = "new bank details" nocase
        $b8 = "change of account" nocase
    condition:
        2 of ($b*)
}

rule Phishing_FakeLoginPage {
    meta:
        description = "Fake login page HTML indicators"
        severity    = "high"
        mitre       = "T1056.003"
        tags        = "phishing,fake-login,html"
    strings:
        $h1 = "<form" nocase
        $h2 = "type=\"password\"" nocase
        $brand1 = "PayPal" nocase
        $brand2 = "Microsoft" nocase
        $brand3 = "Google" nocase
        $brand4 = "Apple" nocase
        $brand5 = "Amazon" nocase
    condition:
        ($h1 and $h2) and (1 of ($brand*))
}
