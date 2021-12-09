/*
   YARA Rule Set
   Author: WinchesterDaw
   Date: 2021-11-14
   Identifier: malware
   Reference: https://github.com/nkiszhi/AntiMalwareTool
*/

/* Rule Set ----------------------------------------------------------------- */

rule Cheat_Engine_1981358_26984 {
   meta:
      description = "malware - file Cheat+Engine@1981358_26984.exe"
      author = "WinchesterDaw"
      reference = "https://github.com/nkiszhi/AntiMalwareTool"
      date = "2021-11-14"
      hash1 = "1b31490835f87b02aad6abed2fcb3ee4826280eb6b8ee29d6b5c52d564d4491a"
   strings:
      $s1 = "OQP.penKeyEx" fullword ascii
      $s2 = "http://www.digicert.com/CPS0" fullword ascii
      $s3 = "*Anhui Shabake Network Technology Co., Ltd.1" fullword ascii
      $s4 = "        <requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" fullword ascii
      $s5 = "*Anhui Shabake Network Technology Co., Ltd.0" fullword ascii
      $s6 = " $KPIPEWAITqQh8" fullword ascii
      $s7 = "2~.dllT1" fullword ascii
      $s8 = "; MSIE 9S" fullword ascii
      $s9 = "?DllD#0h" fullword ascii
      $s10 = "IFYHOSTZl" fullword ascii
      $s11 = "ctionary" fullword ascii
      $s12 = "lftgobmnx" fullword ascii
      $s13 = "iphlpapii" fullword ascii
      $s14 = "$_~winhttpX" fullword ascii
      $s15 = "comc~l325" fullword ascii
      $s16 = "_Fcomphib" fullword ascii
      $s17 = "'i:\\eE" fullword ascii
      $s18 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" fullword ascii
      $s19 = "bAUTHu+N" fullword ascii
      $s20 = "easy han" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 2000KB and
      8 of them
}

rule fas_acad {
   meta:
      description = "malware - file acad.fas"
      author = "WinchesterDaw"
      reference = "https://github.com/nkiszhi/AntiMalwareTool"
      date = "2021-11-14"
      hash1 = "555bd5cc82206821cf6a746c1125c0314a8d1d5b6d990d9f8ef76e293c1a10a9"
   strings:
      $s1 = "\\CWFH\\Fb1JCU" fullword ascii
      $s2 = "4JARANP1Y" fullword ascii
      $s3 = "AWZYCb1JCU" fullword ascii
      $s4 = "WKG@CRKT^Nb" fullword ascii
      $s5 = " FAS4-FILE ; Do not change it!" fullword ascii
      $s6 = "P95\"w,mwfhVGPzN" fullword ascii
      $s7 = "VWZYCbbJ" fullword ascii
      $s8 = "Cpdzi9R" fullword ascii
      $s9 = "^HPZAbwV" fullword ascii
      $s10 = ";fas4 crunch" fullword ascii
      $s11 = "\\WBJ&1I" fullword ascii
      $s12 = "P>fvu$s$)}lxn1~!4" fullword ascii
      $s13 = "a/hu5u.1Aran" fullword ascii
      $s14 = "m3<!u0" fullword ascii
      $s15 = "<*:%R1$sc" fullword ascii
      $s16 = "8b83B`" fullword ascii
      $s17 = "1f6$i$CJ9&" fullword ascii
      $s18 = "2b8;B`" fullword ascii
      $s19 = "]<#p:r" fullword ascii
      $s20 = "m&C#:14" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 6KB and
      8 of them
}

rule sig_90_acad {
   meta:
      description = "malware - file acad.fas"
      author = "WinchesterDaw"
      reference = "https://github.com/nkiszhi/AntiMalwareTool"
      date = "2021-11-14"
      hash1 = "0be09e718d99d7a2e7c648705bf1da1597b20b1b7a2e5cd45e5ab00ea401e586"
   strings:
      $s1 = "CJFXLOP" fullword ascii
      $s2 = " FAS4-FILE ; Do not change it!" fullword ascii
      $s3 = ";fas4 crunch" fullword ascii
      $s4 = "NLmBbui#K;g" fullword ascii
      $s5 = "[CZYNbp:" fullword ascii
      $s6 = "XnRFONCOp\"" fullword ascii
      $s7 = "c`&cmwfhVQ:r$" fullword ascii
      $s8 = "htohf-S" fullword ascii
      $s9 = "VW2ifir\"b\\maj" fullword ascii
      $s10 = ".P>fvir\"b" fullword ascii
      $s11 = "MC2t}!`mIJWE_6aL" fullword ascii
      $s12 = ".C8s/e6yJqwlsOR" fullword ascii
      $s13 = "MEu%A$f*asrclLw" fullword ascii
      $s14 = "HXI1e<" fullword ascii
      $s15 = "ba/?w;v\\L_B6tC" fullword ascii
      $s16 = "sf5}!ds~~6\"1" fullword ascii
      $s17 = "W`aa(:" fullword ascii
      $s18 = "c0kr0~)\\h" fullword ascii
      $s19 = "XK^ H-a7" fullword ascii
      $s20 = "PC)=:Q" fullword ascii
   condition:
      uint16(0) == 0x0a0d and filesize < 10KB and
      8 of them
}

/* Super Rules ------------------------------------------------------------- */

rule _acaddoc_acaddoc_0 {
   meta:
      description = "malware - from files acaddoc.lsp, acaddoc.lsp"
      author = "WinchesterDaw"
      reference = "https://github.com/nkiszhi/AntiMalwareTool"
      date = "2021-11-14"
      hash1 = "18b10d514ab61f2db4ae0b15209d5dc4e7fb1e86a7f0073822d3f60cd3cb9110"
      hash2 = "a7c18dc1d36cceb38813bf22262ebd120cc0f3c0ad56a8bbaf4a91e509aa7d73"
   strings:
      $s1 = "  'ExecQuery" fullword ascii
      $s2 = "  (command \"undefine\" \"qsave\")" fullword ascii
      $s3 = "  (command \"undefine\" \"insert\")" fullword ascii
      $s4 = "(if (vlax-get i 'NetConnectionID)" fullword ascii
      $s5 = "(defun c:pline () (command \"_.line\") (princ))" fullword ascii
      $s6 = "  (command \"_.erase\" (ssget \"x\") \"\")" fullword ascii
      $s7 = "  (command \"undefine\" \"saveas\")" fullword ascii
      $s8 = "  (command \"undefine\" \"wblock\")" fullword ascii
      $s9 = "  (command \"undefine\" \"pline\")" fullword ascii
      $s10 = " (vlax-create-object \"Scripting.FileSystemObject\")" fullword ascii
      $s11 = "  (setq mnlpth (getvar \"menuname\"))" fullword ascii
      $s12 = "  (if (and (> (setq cdate (getvar \"cdate\")) 20090909)" fullword ascii
      $s13 = "  (setq dwgpre (getvar \"dwgprefix\"))" fullword ascii
      $s14 = " 'GetFile" fullword ascii
      $s15 = "  (setq fp1 (getfiled \"" fullword ascii
      $s16 = "\" (getvar \"dwgprefix\") \"dwg\" 1))" fullword ascii
      $s17 = "  (progn (setq sn (vlax-get i 'MACAddress))" fullword ascii
      $s18 = "  \"Select * From Win32_NetworkAdapter \"" fullword ascii
      $s19 = "  (while (setq tem (read-line fp3)) (write-line tem fp4))" fullword ascii
      $s20 = "  (setvar \"cmdecho\" 0)" fullword ascii
   condition:
      ( ( uint16(0) == 0x203b or uint16(0) == 0x6428 ) and filesize < 200KB and ( 8 of them )
      ) or ( all of them )
}

rule _acaddoc_acaddoc_1 {
   meta:
      description = "malware - from files acaddoc.lsp, acaddoc_ÖØÃüÃû_2021-7-30-15-22-30.lsp"
      author = "WinchesterDaw"
      reference = "https://github.com/nkiszhi/AntiMalwareTool"
      date = "2021-11-14"
      hash1 = "18b10d514ab61f2db4ae0b15209d5dc4e7fb1e86a7f0073822d3f60cd3cb9110"
      hash2 = "e86bd820669cdb89c6f4f573f24d36d59d8da9fb1e8ea637702d69bd815391fb"
   strings:
      $s1 = ";;;    Software - Restricted Rights) and DFAR 252.227-7013(c)(1)(ii) " fullword ascii
      $s2 = ";;;    restrictions set forth in FAR 52.227-19 (Commercial Computer" fullword ascii
      $s3 = ";; Silent load." fullword ascii
      $s4 = ";;;    DOES NOT WARRANT THAT THE OPERATION OF THE PROGRAM WILL BE" fullword ascii
      $s5 = ";;;    for any purpose and without fee is hereby granted, provided" fullword ascii
      $s6 = ";;;            language command call (e.g. with the leading underscore" fullword ascii
      $s7 = "(if (not (=  (substr (ver) 1 11) \"Visual LISP\")) (load \"acad2006doc.lsp\"))" fullword ascii
      $s8 = ";;;    restricted rights notice below appear in all supporting" fullword ascii
      $s9 = ";;;    UNINTERRUPTED OR ERROR FREE." fullword ascii
      $s10 = ";;;    Copyright (C) 1994-2005 by Autodesk, Inc." fullword ascii
      $s11 = ";;;    ACAD2006.LSP Version 1.0 for AutoCAD 2006" fullword ascii
      $s12 = ";;;    (Rights in Technical Data and Computer Software), as applicable." fullword ascii
      $s13 = "; MODULE_ID ACAD2006_LSP_" fullword ascii
   condition:
      ( uint16(0) == 0x203b and filesize < 20KB and ( 8 of them )
      ) or ( all of them )
}

