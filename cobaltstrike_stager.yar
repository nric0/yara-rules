rule CobaltStrike_VBA_Powershell : CobaltStrike VBScript Powershell
{
	meta:
		description = "Detects the Cobalt Strike VBScript stager"
		author = "@nric0"
		version = "2"
		date = "2018-04-11"
	strings:
		$a1 = "VBScript" nocase ascii
		$a2 = "var_func()" nocase ascii
		$a3 = "var_shell" nocase ascii
		$a4 = "Wscript.Shell" nocase ascii
		$a5 = "powershell" nocase ascii
		$a6 = "hidden" nocase ascii
		$a7 = "-enc" nocase ascii
		$a8 = "-nop" nocase ascii

	condition:
		6 of ($a*)
}

