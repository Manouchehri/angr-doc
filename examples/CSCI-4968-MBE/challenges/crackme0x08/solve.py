#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

# from IPython import embed # pop iPython at the end

def main():
	proj = angr.Project('crackme0x08', load_options={"auto_load_libs": False}) 

	cfg = proj.analyses.CFG()
	# embed()
	FIND_ADDR = cfg.kb.functions.function(name="exit").addr
	AVOID_ADDR = cfg.kb.functions.function(name="che").addr

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
            ;-- main:
╒ (fcn) sym.main 99
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
│           0x0804869c      c70424d98704.  dword [esp] = str.IOLI_Crackme_Level_0x08_n ; [0x80487d9:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x08_n ; "IOLI Crackme Level 0x08." @ 0x80487d9
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
│           0x080486d4      e8e0feffff     sym.check ()
│           0x080486d9      b800000000     eax = 0
│           0x080486de      c9             
╘           0x080486df      c3        
╒ (fcn) sym.check 196
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_9h @ ebp+0x9
│           ; arg int arg_ch @ ebp+0xc
│           ; arg int arg_10h @ ebp+0x10
│           ; arg int arg_13h @ ebp+0x13
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x080486d4 (sym.main)
│           0x080485b9      55             push ebp
│           0x080485ba      89e5           ebp = esp
│           0x080485bc      83ec28         esp -= 0x28
│           0x080485bf      c745f8000000.  dword [ebp - local_8h] = 0
│           0x080485c6      c745f4000000.  dword [ebp - local_ch] = 0
│           ; JMP XREF from 0x08048628 (sym.check)
│       ┌─> 0x080485cd      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│       │   0x080485d0      890424         dword [esp] = eax
│       │   0x080485d3      e8d0fdffff     0x80483a8 ()                ; sym.imp.strlen
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
│      ││   0x080485fe      e8c5fdffff     0x80483c8 ()                ; sym.imp.sscanf
│      ││   0x08048603      8b55fc         edx = dword [ebp - local_4h]
│      ││   0x08048606      8d45f8         eax = [ebp - local_8h]
│      ││   0x08048609      0110           dword [eax] += edx
│      ││   0x0804860b      837df810       if (dword [ebp - local_8h] == 0x10 ; [0x10:4]=0x30002
│     ┌───< 0x0804860f      7512           notZero 0x8048623)
│     │││   0x08048611      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│     │││   0x08048614      89442404       dword [esp + arg_4h] = eax
│     │││   0x08048618      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│     │││   0x0804861b      890424         dword [esp] = eax
│     │││   0x0804861e      e81fffffff     0x8048542 ()                ; sym.parell
│     └───> 0x08048623      8d45f4         eax = [ebp - local_ch]
│      ││   0x08048626      ff00           dword [eax]++
│      │└─< 0x08048628      eba3           goto 0x80485cd
│      └──> 0x0804862a      e8f5feffff     0x8048524 ()                ; sym.che
│           0x0804862f      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│           0x08048632      89442404       dword [esp + arg_4h] = eax
│           0x08048636      8b45fc         eax = dword [ebp - local_4h]
│           0x08048639      890424         dword [esp] = eax
│           0x0804863c      e873feffff     0x80484b4 ()                ; sym.dummy
│           0x08048641      85c0           if (eax == eax
│       ┌─< 0x08048643      7436           isZero 0x804867b)
│       │   0x08048645      c745f4000000.  dword [ebp - local_ch] = 0
│       │   ; JMP XREF from 0x08048679 (sym.check)
│      ┌──> 0x0804864c      837df409       if (dword [ebp - local_ch] == 9 ; [0x9:4]=0
│     ┌───< 0x08048650      7f29           isGreater 0x804867b)
│     │││   0x08048652      8b45fc         eax = dword [ebp - local_4h]
│     │││   0x08048655      83e001         eax &= 1
│     │││   0x08048658      85c0           if (eax == eax
│    ┌────< 0x0804865a      7518           notZero 0x8048674)
│    ││││   0x0804865c      c70424d38704.  dword [esp] = str.wtf__n    ; [0x80487d3:4]=0x3f667477 LEA str.wtf__n ; "wtf?." @ 0x80487d3
│    ││││   0x08048663      e850fdffff     0x80483b8 ()                ; sym.imp.printf
│    ││││   0x08048668      c70424000000.  dword [esp] = 0
│    ││││   0x0804866f      e874fdffff     0x80483e8 ()                ; sym.imp.exit
│    └────> 0x08048674      8d45f4         eax = [ebp - local_ch]
│     │││   0x08048677      ff00           dword [eax]++
│     │└──< 0x08048679      ebd1           goto 0x804864c
│     └─└─> 0x0804867b      c9             
╘           0x0804867c      c3   
[0x08048400]> pdf @ sym.che
╒ (fcn) sym.che 30
│           ; CALL XREF from 0x0804862a (sym.check)
│           0x08048524      55             push ebp
│           0x08048525      89e5           ebp = esp
│           0x08048527      83ec08         esp -= 8
│           0x0804852a      c70424ad8704.  dword [esp] = str.Password_Incorrect__n ; [0x80487ad:4]=0x73736150 LEA str.Password_Incorrect__n ; "Password Incorrect!." @ 0x80487ad
│           0x08048531      e882feffff     sym.imp.printf ()
│           0x08048536      c70424000000.  dword [esp] = 0
╘           0x0804853d      e8a6feffff     sym.imp.exit ()

"""
