import "math"

rule LowEntropy
{
    condition:
        math.entropy(0, filesize) < 4.5
}

rule MediumLowEntropy
{
    condition:
        math.entropy(0, filesize) >= 4.5 and math.entropy(0, filesize) < 5.5
}

rule MediumEntropy
{
    condition:
        math.entropy(0, filesize) >= 5.5 and math.entropy(0, filesize) < 6.5
}

rule MediumHighEntropy
{
    condition:       
	math.entropy(0, filesize) >= 6.5 and math.entropy(0, filesize) < 7.5
}

rule HighEntropy
{
    condition:
        math.entropy(0, filesize) >= 7.5
}

