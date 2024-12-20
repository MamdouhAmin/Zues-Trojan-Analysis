rule Windows_Malware_Zeus : Zeus_1134
{
    meta:
        author = "Project Team"
        description = "Detect Zeus Malware"
        date = "2024-12-19"
    strings:
        $mz = {4D 5A}
        $url = "/gate.php"
        $string1 = "InitializeSecurityDescriptor"
        $string2 = "Mozilla/4.0"
    condition:
        $mz and any of ($url, $string1, $string2)
}
