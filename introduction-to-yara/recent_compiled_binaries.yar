import "pe"
import "time"

rule _Detect_Recent_Compiled_Binaries_
{
    meta:
        studentID = "5xG7GvEvdzQnkoKAFUrZ1jkrDA42"
        author = "Thien Tran"
        email = "thientran@example.com"
        description = "Detects Portable Executables compiled in the last 24 hours"
        date = "07-03-2025"
        version = "1.0"
    
    condition:
        pe.timestamp >= time.now() - 86400 and
	pe.timestamp < time.now()
}
