rule _Detect_Ordered_Strings_
{
    meta:
        author = "Thien Tran"
        description = "Detects strings that appear in a specific order"
        date = "07-03-2025"
        version = "1.0"

    strings:
        $s1 = "blue"
        $s2 = "red"
        $s3 = "purple"

    condition:
        @s1 < @s2 and @s2 < @s3
}