rule Suspicious_PowerShell_Downloader
{
    meta:
        description = "PowerShell indirme ve kod çalıştırma kalıpları"
        severity = "high"
    strings:
        $a = "DownloadString" nocase ascii wide
        $b = "Invoke-Expression" nocase ascii wide
        $c = "FromBase64String" nocase ascii wide
    condition:
        2 of them
}

rule Suspicious_Process_Injection_APIs
{
    meta:
        description = "İşlem enjeksiyonunda sık görülen Windows API dizisi"
        severity = "high"
    strings:
        $a = "VirtualAllocEx" ascii wide
        $b = "WriteProcessMemory" ascii wide
        $c = "CreateRemoteThread" ascii wide
    condition:
        2 of them
}

rule Suspicious_Persistence_RunKey
{
    meta:
        description = "Windows başlangıç kalıcılığı göstergesi"
        severity = "medium"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide
    condition:
        $run
}

rule Suspicious_Script_Obfuscation
{
    meta:
        description = "Komut dosyasında gizleme ve dinamik kod çalıştırma kalıpları"
        severity = "high"
    strings:
        $a = "-EncodedCommand" nocase ascii wide
        $b = "FromBase64String" nocase ascii wide
        $c = "Invoke-Expression" nocase ascii wide
        $d = "eval(" nocase ascii
        $e = "charCodeAt" ascii
    condition:
        2 of them
}

rule Suspicious_Credential_Access
{
    meta:
        description = "Kimlik bilgisi veya tarayıcı oturumu hedefleyen dizeler"
        severity = "high"
    strings:
        $a = "Login Data" ascii wide
        $b = "Local State" ascii wide
        $c = "CryptUnprotectData" ascii wide
        $d = "password_value" ascii wide
        $e = "cookies.sqlite" nocase ascii wide
    condition:
        2 of them
}

rule Suspicious_Ransomware_Behavior
{
    meta:
        description = "Fidye yazılımında görülen dosya şifreleme ve not bırakma dizileri"
        severity = "high"
    strings:
        $a = "your files have been encrypted" nocase ascii wide
        $b = "decrypt your files" nocase ascii wide
        $c = "bitcoin" nocase ascii wide
        $d = "vssadmin delete shadows" nocase ascii wide
        $e = "wbadmin delete catalog" nocase ascii wide
    condition:
        2 of them
}

rule Suspicious_Android_Abuse
{
    meta:
        description = "Android üzerinde SMS, erişilebilirlik ve paket yükleme kötüye kullanımı"
        severity = "high"
    strings:
        $a = "android.permission.SEND_SMS" ascii wide
        $b = "android.permission.REQUEST_INSTALL_PACKAGES" ascii wide
        $c = "BIND_ACCESSIBILITY_SERVICE" ascii wide
        $d = "android.permission.READ_SMS" ascii wide
    condition:
        3 of them
}
