rule CobaltStrike_Malleable_C2_GIF : CobaltStrike GIF
{
	meta:
		description = "Detects the Cobalt Strike Malleable C2 fake GIF"
		author = "@nric0"
		reference = "https://github.com/rsmudge/Malleable-C2-Profiles/blob/master/normal/webbug_getonly.profile" 
		version = "1"
		date = "2018-04-03"

	strings:
		$gifmagic = { 47 49 46 38 39 61 01 00 01 00 80 00 00 00 00 FF FF FF 21 F9 04 01 00 00 00 2C 00 00 00 00 01 00 01 00 00 02 01 44 00 3B }

	condition:
		filesize > 10KB and $gifmagic at 0
}
