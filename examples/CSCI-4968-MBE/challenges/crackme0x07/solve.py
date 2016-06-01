#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

# from IPython import embed # pop iPython at the end

def main():
	proj = angr.Project('crackme0x07', load_options={"auto_load_libs": False}) 

	cfg = proj.analyses.CFG()
	FIND_ADDR = 0x08048598 # cfg.kb.functions.function(name="exit").addr
	AVOID_ADDR = 0x08048524

	path_group = proj.factory.path_group()
	path_group.explore(find=FIND_ADDR, avoid=AVOID_ADDR)

	# embed()
	print path_group.found[0].state.posix.dumps(1) 
	return path_group.found[0].state.posix.dumps(0) # .lstrip('+0').rstrip('B')

def test():
	assert main() == ''

if __name__ == '__main__':
	print(repr(main()))

"""
[0x08048400]> pdf @ main
╒ (fcn) main 99
│           ; arg int arg_10h @ ebp+0x10
│           ; var int arg_4h @ esp+0x4
│           ; UNKNOWN XREF from 0x08048418 (entry0)
│           ; DATA XREF from 0x08048417 (entry0)
│           0x0804867d      55             push ebp
│           0x0804867e      89e5           ebp = esp
│           0x08048680      81ec88000000   esp -= 0x88
│           0x08048686      83e4f0         esp &= 0xfffffff0
│           0x08048689      b800000000     eax = 0
│           0x0804868e      83c00f         eax += 0xf
│           0x08048691      83c00f         eax += 0xf
│           0x08048694      c1e804         eax >>>= 4
│           0x08048697      c1e004         eax <<<= 4
│           0x0804869a      29c4           esp -= eax
│           0x0804869c      c70424d98704.  dword [esp] = str.IOLI_Crackme_Level_0x07_n ; [0x80487d9:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x07_n ; "IOLI Crackme Level 0x07." @ 0x80487d9
│           0x080486a3      e810fdffff     sym.imp.printf ()
│           0x080486a8      c70424f28704.  dword [esp] = str.Password: ; [0x80487f2:4]=0x73736150 LEA str.Password: ; "Password: " @ 0x80487f2
│           0x080486af      e804fdffff     sym.imp.printf ()
│           0x080486b4      8d4588         eax = [ebp - local_78h]
│           0x080486b7      89442404       dword [esp + arg_4h] = eax
│           0x080486bb      c70424fd8704.  dword [esp] = 0x80487fd     ; [0x80487fd:4]=0x7325 ; "%s" @ 0x80487fd
│           0x080486c2      e8d1fcffff     sym.imp.scanf ()
│           0x080486c7      8b4510         eax = dword [ebp + arg_10h] ; [0x10:4]=0x30002
│           0x080486ca      89442404       dword [esp + arg_4h] = eax
│           0x080486ce      8d4588         eax = [ebp - local_78h]
│           0x080486d1      890424         dword [esp] = eax
│           0x080486d4      e8e0feffff     sub.strlen_5b9 ()
│           0x080486d9      b800000000     eax = 0
│           0x080486de      c9             
╘           0x080486df      c3          
[0x08048400]> pdf @ sub.strlen_5b9 | more
╒ (fcn) sub.strlen_5b9 196
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x080486d4 (main)
│           0x080485b9      55             push ebp
│           0x080485ba      89e5           ebp = esp
│           0x080485bc      83ec28         esp -= 0x28
│           0x080485bf      c745f8000000.  dword [ebp - local_8h] = 0
│           0x080485c6      c745f4000000.  dword [ebp - local_ch] = 0
│           ; JMP XREF from 0x08048628 (sub.strlen_5b9)
│       ┌─> 0x080485cd      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│       │   0x080485d0      890424         dword [esp] = eax
│       │   0x080485d3      e8d0fdffff     sym.imp.strlen ()
│       │   0x080485d8      3945f4         if (dword [ebp - local_ch] == eax ; [0x13:4]=256
│      ┌──< 0x080485db      734d           jae 0x804862a 
│      ││   0x080485dd      8b45f4         eax = dword [ebp - local_ch]
│      ││   0x080485e0      034508         eax += dword [ebp + arg_8h]
│      ││   0x080485e3      0fb600         eax = byte [eax]
│      ││   0x080485e6      8845f3         byte [ebp - local_dh] = al
│      ││   0x080485e9      8d45fc         eax = [ebp - local_4h]
│      ││   0x080485ec      89442408       dword [esp + arg_8h] = eax
│      ││   0x080485f0      c7442404c287.  dword [esp + arg_4h] = 0x80487c2 ; [0x80487c2:4]=0x50006425 ; "%d" @ 0x80487c2
│      ││   0x080485f8      8d45f3         eax = [ebp - local_dh]
│      ││   0x080485fb      890424         dword [esp] = eax
│      ││   0x080485fe      e8c5fdffff     sym.imp.sscanf ()
│      ││   0x08048603      8b55fc         edx = dword [ebp - local_4h]
│      ││   0x08048606      8d45f8         eax = [ebp - local_8h]
│      ││   0x08048609      0110           dword [eax] += edx
│      ││   0x0804860b      837df810       if (dword [ebp - local_8h] == 0x10 ; [0x10:4]=0x30002
│     ┌───< 0x0804860f      7512           notZero 0x8048623)
│     │││   0x08048611      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│     │││   0x08048614      89442404       dword [esp + arg_4h] = eax
│     │││   0x08048618      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│     │││   0x0804861b      890424         dword [esp] = eax
│     │││   0x0804861e      e81fffffff     sub.sscanf_542 ()
│     └───> 0x08048623      8d45f4         eax = [ebp - local_ch]
│      ││   0x08048626      ff00           dword [eax]++
│      │└─< 0x08048628      eba3           goto 0x80485cd
│      └──> 0x0804862a      e8f5feffff     sub.printf_524 ()
│           0x0804862f      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│           0x08048632      89442404       dword [esp + arg_4h] = eax
│           0x08048636      8b45fc         eax = dword [ebp - local_4h]
│           0x08048639      890424         dword [esp] = eax
│           0x0804863c      e873feffff     sub.strncmp_4b4 ()
│           0x08048641      85c0           if (eax == eax
│       ┌─< 0x08048643      7436           isZero 0x804867b)
│       │   0x08048645      c745f4000000.  dword [ebp - local_ch] = 0
│       │   ; JMP XREF from 0x08048679 (sub.strlen_5b9)
│      ┌──> 0x0804864c      837df409       if (dword [ebp - local_ch] == 9 ; [0x9:4]=0
│     ┌───< 0x08048650      7f29           isGreater 0x804867b)
│     │││   0x08048652      8b45fc         eax = dword [ebp - local_4h]
│     │││   0x08048655      83e001         eax &= 1
│     │││   0x08048658      85c0           if (eax == eax
│    ┌────< 0x0804865a      7518           notZero 0x8048674)
│    ││││   0x0804865c      c70424d38704.  dword [esp] = str.wtf__n    ; [0x80487d3:4]=0x3f667477 LEA str.wtf__n ; "wtf?." @ 0x80487d3
│    ││││   0x08048663      e850fdffff     sym.imp.printf ()
│    ││││   0x08048668      c70424000000.  dword [esp] = 0
│    ││││   0x0804866f      e874fdffff     sym.imp.exit ()
│    └────> 0x08048674      8d45f4         eax = [ebp - local_ch]
│     │││   0x08048677      ff00           dword [eax]++
│     │└──< 0x08048679      ebd1           goto 0x804864c
│     └─└─> 0x0804867b      c9             
╘           0x0804867c      c3             
[0x08048400]> pdf @ sub.printf_524 
╒ (fcn) sub.printf_524 30
│           ; CALL XREF from 0x0804862a (sub.strlen_5b9)
│           0x08048524      55             push ebp
│           0x08048525      89e5           ebp = esp
│           0x08048527      83ec08         esp -= 8
│           0x0804852a      c70424ad8704.  dword [esp] = str.Password_Incorrect__n ; [0x80487ad:4]=0x73736150 LEA str.Password_Incorrect__n ; "Password Incorrect!." @ 0x80487ad
│           0x08048531      e882feffff     sym.imp.printf ()
│           0x08048536      c70424000000.  dword [esp] = 0
╘           0x0804853d      e8a6feffff     sym.imp.exit ()
[0x08048400]> pdf @ sub.sscanf_542
╒ (fcn) sub.sscanf_542 119
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_9h @ ebp+0x9
│           ; arg int arg_ch @ ebp+0xc
│           ; var int local_4h @ ebp-0x4
│           ; var int local_8h @ ebp-0x8
│           ; CALL XREF from 0x0804861e (sub.strlen_5b9)
│           0x08048542      55             push ebp
│           0x08048543      89e5           ebp = esp
│           0x08048545      83ec18         esp -= 0x18
│           0x08048548      8d45fc         eax = [ebp - local_4h]
│           0x0804854b      89442408       dword [esp + 8] = eax
│           0x0804854f      c7442404c287.  dword [esp + 4] = 0x80487c2 ; [0x80487c2:4]=0x50006425 ; "%d" @ 0x80487c2
│           0x08048557      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│           0x0804855a      890424         dword [esp] = eax
│           0x0804855d      e866feffff     sym.imp.sscanf ()
│           0x08048562      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│           0x08048565      89442404       dword [esp + 4] = eax
│           0x08048569      8b45fc         eax = dword [ebp - local_4h]
│           0x0804856c      890424         dword [esp] = eax
│           0x0804856f      e840ffffff     sub.strncmp_4b4 ()
│           0x08048574      85c0           if (eax == eax
│       ┌─< 0x08048576      743f           isZero 0x80485b7)
│       │   0x08048578      c745f8000000.  dword [ebp - local_8h] = 0
│       │   ; JMP XREF from 0x080485b5 (sub.sscanf_542)
│      ┌──> 0x0804857f      837df809       if (dword [ebp - local_8h] == 9 ; [0x9:4]=0
│     ┌───< 0x08048583      7f32           isGreater 0x80485b7)
│     │││   0x08048585      8b45fc         eax = dword [ebp - local_4h]
│     │││   0x08048588      83e001         eax &= 1
│     │││   0x0804858b      85c0           if (eax == eax
│    ┌────< 0x0804858d      7521           notZero 0x80485b0)
│    ││││   ; DATA XREF from 0x0804a02c (unk)
│    ││││   0x0804858f      833d2ca00408.  if (dword [0x804a02c] == 1  ; [0x1:4]=0x1464c45
│   ┌─────< 0x08048596      750c           notZero 0x80485a4)
│   │││││   0x08048598      c70424c58704.  dword [esp] = str.Password_OK__n ; [0x80487c5:4]=0x73736150 LEA str.Password_OK__n ; "Password OK!." @ 0x80487c5
│   │││││   0x0804859f      e814feffff     sym.imp.printf ()
│   └─────> 0x080485a4      c70424000000.  dword [esp] = 0
│    ││││   0x080485ab      e838feffff     sym.imp.exit ()
│    └────> 0x080485b0      8d45f8         eax = [ebp - local_8h]
│     │││   0x080485b3      ff00           dword [eax]++
│     │└──< 0x080485b5      ebc8           goto 0x804857f
│     └─└─> 0x080485b7      c9             
╘           0x080485b8      c3 
"""
