rule _Hex_Wildcard_Search_
{
    meta:
        author = "Thien Tran"
        description = "Detects malicious patterns using hexadecimal strings, wildcards, and variable-length gaps."
        date = "06-03-2025"
        version = "1.0"

    strings:
        $hex1 = { 55 8B EC } // Function prologue (PUSH EBP, MOV EBP, ESP)
        $hex2 = { E8 ?? ?? ?? ?? C3 } // CALL function followed by RETN
        $hex3 = { 90 90 [1-4] 90 90 } // NOP sled with variable-length padding
        
    condition:
        any of ($hex*)
}
