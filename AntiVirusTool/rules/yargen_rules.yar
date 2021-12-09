/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2021-11-10
   Identifier: malware
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule Cheat_Engine_1981358_26984 {
   meta:
      description = "malware - file Cheat+Engine@1981358_26984.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2021-11-10"
      hash1 = "1b31490835f87b02aad6abed2fcb3ee4826280eb6b8ee29d6b5c52d564d4491a"
   strings:
      $s1 = "OQP.penKeyEx" fullword ascii
      $s2 = "http://www.digicert.com/CPS0" fullword ascii
      $s3 = "*Anhui Shabake Network Technology Co., Ltd.0" fullword ascii
      $s4 = "*Anhui Shabake Network Technology Co., Ltd.1" fullword ascii
      $s5 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii
      $s6 = " $KPIPEWAITqQh8" fullword ascii
      $s7 = "2~.dllT1" fullword ascii
      $s8 = "; MSIE 9S" fullword ascii
      $s9 = "IFYHOSTZl" fullword ascii
      $s10 = "?DllD#0h" fullword ascii
      $s11 = "ctionary" fullword ascii
      $s12 = "iphlpapii" fullword ascii
      $s13 = "lftgobmnx" fullword ascii
      $s14 = "_Fcomphib" fullword ascii
      $s15 = "'i:\\eE" fullword ascii
      $s16 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s17 = "comc~l325" fullword ascii
      $s18 = "bAUTHu+N" fullword ascii
      $s19 = "$_~winhttpX" fullword ascii
      $s20 = "xpageT" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

