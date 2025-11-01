rule _Detect_mbcheck_
{
    meta:
        description = "Detect mbcheck.exe loader/backdoor"
	author = "Thien Tran"
        date = "02-10-2025"
        sha256 = "9570F1B0DDE6B5DA4FA0C9028B1FCC69E9777280BED31EB009E79C7DD87B04AA"

    strings:
        $a1 = "WSAStartup" ascii
        $a2 = "gethostbyname" ascii
        $a3 = "WNetEnumResourceW" ascii
        $a4 = "VirtualAlloc" ascii
        $s1 = "5.39.123.4" ascii 

    condition:
        uint16(0) == 0x5A4D and
        (all of ($a*) or any of ($s*))
}
