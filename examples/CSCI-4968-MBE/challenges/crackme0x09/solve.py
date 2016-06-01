#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

# from IPython import embed # pop iPython at the end

def main():
	proj = angr.Project('crackme0x09', load_options={"auto_load_libs": False}) 

	cfg = proj.analyses.CFG()
	# embed()
	FIND_ADDR = 0x8048410 # cfg.kb.functions.function(name="exit").addr
	# AVOID_ADDR =  # cfg.kb.functions.function(name="printf").addr

	path_group = proj.factory.path_group()
	path_group.explore(find=FIND_ADDR) # avoid=AVOID_ADDR

	# embed()
	print path_group.found[0].state.posix.dumps(1) 
	return path_group.found[0].state.posix.dumps(0) # .lstrip('+0').rstrip('B')

def test():
	assert main() == ''

if __name__ == '__main__':
	print(repr(main()))

"""
[0x08048620]> pdf @ main 
╒ (fcn) main 120
│           ; arg int arg_10h @ ebp+0x10
│           ; var int arg_4h @ esp+0x4
│           ; UNKNOWN XREF from 0x08048438 (entry0)
│           ; DATA XREF from 0x08048437 (entry0)
│           0x080486ee      55             push ebp
│           0x080486ef      89e5           ebp = esp
│           0x080486f1      53             push ebx
│           0x080486f2      81ec84000000   esp -= 0x84
│           0x080486f8      e869000000     fcn.08048766 ()
│           0x080486fd      81c3f7180000   ebx += 0x18f7
│           0x08048703      83e4f0         esp &= 0xfffffff0
│           0x08048706      b800000000     eax = 0
│           0x0804870b      83c00f         eax += 0xf
│           0x0804870e      83c00f         eax += 0xf
│           0x08048711      c1e804         eax >>>= 4
│           0x08048714      c1e004         eax <<<= 4
│           0x08048717      29c4           esp -= eax
│           0x08048719      8d8375e8ffff   eax = [ebx - 0x178b]
│           0x0804871f      890424         dword [esp] = eax
│           0x08048722      e8b9fcffff     sym.imp.printf ()
│           0x08048727      8d838ee8ffff   eax = [ebx - 0x1772]
│           0x0804872d      890424         dword [esp] = eax
│           0x08048730      e8abfcffff     sym.imp.printf ()
│           0x08048735      8d4588         eax = [ebp - local_78h]
│           0x08048738      89442404       dword [esp + arg_4h] = eax
│           0x0804873c      8d8399e8ffff   eax = [ebx - 0x1767]
│           0x08048742      890424         dword [esp] = eax
│           0x08048745      e876fcffff     sym.imp.scanf ()
│           0x0804874a      8b4510         eax = dword [ebp + arg_10h] ; [0x10:4]=0x30002
│           0x0804874d      89442404       dword [esp + arg_4h] = eax
│           0x08048751      8d4588         eax = [ebp - local_78h]
│           0x08048754      890424         dword [esp] = eax
│           0x08048757      e8bafeffff     sub.strlen_616 ()
│           0x0804875c      b800000000     eax = 0
│           0x08048761      8b5dfc         ebx = dword [ebp - local_4h]
│           0x08048764      c9             
╘           0x08048765      c3             
╒ (fcn) sub.strlen_616 216
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_9h @ ebp+0x9
│           ; arg int arg_ch @ ebp+0xc
│           ; arg int arg_10h @ ebp+0x10
│           ; arg int arg_13h @ ebp+0x13
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x08048757 (main)
│           0x08048616      55             push ebp
│           0x08048617      89e5           ebp = esp
│           0x08048619      53             push ebx
│           0x0804861a      83ec24         esp -= 0x24
│           0x0804861d      e844010000     0x8048766 ()                ; fcn.08048766
│           0x08048622      81c3d2190000   ebx += 0x19d2
│           0x08048628      c745f4000000.  dword [ebp - local_ch] = 0
│           0x0804862f      c745f0000000.  dword [ebp - local_10h] = 0
│           ; JMP XREF from 0x08048693 (sub.strlen_616)
│       ┌─> 0x08048636      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│       │   0x08048639      890424         dword [esp] = eax
│       │   0x0804863c      e88ffdffff     0x80483d0 ()                ; sym.imp.strlen
│       │   0x08048641      3945f0         if (dword [ebp - local_10h] == eax ; [0x13:4]=256
│      ┌──< 0x08048644      734f           jae 0x8048695 
│      ││   0x08048646      8b45f0         eax = dword [ebp - local_10h]
│      ││   0x08048649      034508         eax += dword [ebp + arg_8h]
│      ││   0x0804864c      0fb600         eax = byte [eax]
│      ││   0x0804864f      8845ef         byte [ebp - local_11h] = al
│      ││   0x08048652      8d45f8         eax = [ebp - local_8h]
│      ││   0x08048655      89442408       dword [esp + arg_8h] = eax
│      ││   0x08048659      8d835ee8ffff   eax = [ebx - 0x17a2]
│      ││   0x0804865f      89442404       dword [esp + arg_4h] = eax
│      ││   0x08048663      8d45ef         eax = [ebp - local_11h]
│      ││   0x08048666      890424         dword [esp] = eax
│      ││   0x08048669      e882fdffff     0x80483f0 ()                ; sym.imp.sscanf
│      ││   0x0804866e      8b55f8         edx = dword [ebp - local_8h]
│      ││   0x08048671      8d45f4         eax = [ebp - local_ch]
│      ││   0x08048674      0110           dword [eax] += edx
│      ││   0x08048676      837df410       if (dword [ebp - local_ch] == 0x10 ; [0x10:4]=0x30002
│     ┌───< 0x0804867a      7512           notZero 0x804868e)
│     │││   0x0804867c      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│     │││   0x0804867f      89442404       dword [esp + arg_4h] = eax
│     │││   0x08048683      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│     │││   0x08048686      890424         dword [esp] = eax
│     │││   0x08048689      e8fbfeffff     0x8048589 ()                ; sub.sscanf_589
│     └───> 0x0804868e      8d45f0         eax = [ebp - local_10h]
│      ││   0x08048691      ff00           dword [eax]++
│      │└─< 0x08048693      eba1           goto 0x8048636
│      └──> 0x08048695      e8c3feffff     0x804855d ()                ; sub.printf_55d
│           0x0804869a      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│           0x0804869d      89442404       dword [esp + arg_4h] = eax
│           0x080486a1      8b45f8         eax = dword [ebp - local_8h]
│           0x080486a4      890424         dword [esp] = eax
│           0x080486a7      e828feffff     0x80484d4 ()                ; sub.strncmp_4d4
│           0x080486ac      85c0           if (eax == eax
│       ┌─< 0x080486ae      7438           isZero 0x80486e8)
│       │   0x080486b0      c745f0000000.  dword [ebp - local_10h] = 0
│       │   ; JMP XREF from 0x080486e6 (sub.strlen_616)
│      ┌──> 0x080486b7      837df009       if (dword [ebp - local_10h] == 9 ; [0x9:4]=0
│     ┌───< 0x080486bb      7f2b           isGreater 0x80486e8)
│     │││   0x080486bd      8b45f8         eax = dword [ebp - local_8h]
│     │││   0x080486c0      83e001         eax &= 1
│     │││   0x080486c3      85c0           if (eax == eax
│    ┌────< 0x080486c5      751a           notZero 0x80486e1)
│    ││││   0x080486c7      8d836fe8ffff   eax = [ebx - 0x1791]
│    ││││   0x080486cd      890424         dword [esp] = eax
│    ││││   0x080486d0      e80bfdffff     0x80483e0 ()                ; sym.imp.printf
│    ││││   0x080486d5      c70424000000.  dword [esp] = 0
│    ││││   0x080486dc      e82ffdffff     0x8048410 ()                ; sym.imp.exit
│    └────> 0x080486e1      8d45f0         eax = [ebp - local_10h]
│     │││   0x080486e4      ff00           dword [eax]++
│     │└──< 0x080486e6      ebcf           goto 0x80486b7
│     └─└─> 0x080486e8      83c424         esp += 0x24
│           0x080486eb      5b             pop ebx
│           0x080486ec      5d             pop ebp
╘           0x080486ed      c3   
[0x08048720]> pdf @ sub.strncmp_4d4
╒ (fcn) sub.strncmp_4d4 137
│           ; arg int arg_ch @ ebp+0xc
│           ; var int local_8h @ ebp-0x8
│           ; var int local_ch @ ebp-0xc
│           ; CALL XREF from 0x080486a7 (sub.strlen_616)
│           ; CALL XREF from 0x080485c4 (sub.sscanf_589)
│           0x080484d4      55             push ebp
│           0x080484d5      89e5           ebp = esp
│           0x080484d7      53             push ebx
│           0x080484d8      83ec14         esp -= 0x14
│           0x080484db      e886020000     fcn.08048766 ()
│           0x080484e0      81c3141b0000   ebx += 0x1b14
│           0x080484e6      c745f8000000.  dword [ebp - local_8h] = 0
│       ┌─> 0x080484ed      8b45f8         eax = dword [ebp - local_8h]
│       │   0x080484f0      8d1485000000.  edx = [eax*4]
│       │   0x080484f7      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│       │   0x080484fa      833c0200       if (dword [edx + eax] == 0
│      ┌──< 0x080484fe      7448           isZero 0x8048548)
│      ││   0x08048500      8b45f8         eax = dword [ebp - local_8h]
│      ││   0x08048503      8d1485000000.  edx = [eax*4]
│      ││   0x0804850a      8b4d0c         ecx = dword [ebp + arg_ch]  ; [0xc:4]=0
│      ││   0x0804850d      8d45f8         eax = [ebp - local_8h]
│      ││   0x08048510      ff00           dword [eax]++
│      ││   0x08048512      8d8344e8ffff   eax = [ebx - 0x17bc]
│      ││   0x08048518      c74424080300.  dword [esp + 8] = 3
│      ││   0x08048520      89442404       dword [esp + 4] = eax
│      ││   0x08048524      8b040a         eax = dword [edx + ecx]
│      ││   0x08048527      890424         dword [esp] = eax
│      ││   0x0804852a      e8d1feffff     sym.imp.strncmp ()
│      ││   0x0804852f      85c0           if (eax == eax
│      │└─< 0x08048531      75ba           notZero 0x80484ed)
│      │    0x08048533      8b83fcffffff   eax = dword [ebx - 4]
│      │    0x08048539      c70001000000   dword [eax] = 1
│      │    0x0804853f      c745f4010000.  dword [ebp - local_ch] = 1
│      │┌─< 0x08048546      eb0c           goto 0x8048554
│      └──> 0x08048548      c70424ffffff.  dword [esp] = loc.imp.__gmon_start__ ; [0xffffffff:4]=-1 LEA loc.imp.__gmon_start__ ; loc.imp.__gmon_start__
│       │   0x0804854f      e8bcfeffff     sym.imp.exit ()
│       │   ; JMP XREF from 0x08048546 (sub.strncmp_4d4)
│       └─> 0x08048554      8b45f4         eax = dword [ebp - local_ch]
│           0x08048557      83c414         esp += 0x14
│           0x0804855a      5b             pop ebx
│           0x0804855b      5d             pop ebp
╘           0x0804855c      c3             

"""
