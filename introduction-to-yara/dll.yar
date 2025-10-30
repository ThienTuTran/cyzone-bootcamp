import "pe"

rule _Detect_Windows_DLLs_
{
    meta:
        studentID = "5xG7GvEvdzQnkoKAFUrZ1jkrDA42"
        author = "Thien Tran"
        description = "Detects Windows DLLs"
        date = "07-03-2025"
        version = "1.0"

    condition:
        //pe.characteristics & pe.DLL != 0
	    pe.is_dll()
}
