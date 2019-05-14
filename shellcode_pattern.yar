/* Hard coding yara file for functional testing. */

rule detect_shellcode
{
    meta:
        author = "swpose"
        type = "XOR pattern"
        filetype = "Shellcode"
        version = "1.0"
        date = "2019-02-12"
        md5 = "DE9FCCC2AD15037220F82EDB1554A1FA"
        description = "Rule to detect Shellcode in the BinData"

    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
        $a3 = {30 32 38 46 43 42 37 44 44}
        $a4 = {39 30 30 30 30 33 30 30 30 30 30 30 30 34 30 30 30 30 30 30 46 46 46 46 30 30 30 30 42}

    condition:
        any of them
}
