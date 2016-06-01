#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

import angr

# from IPython import embed # pop iPython at the end

def main():
	proj = angr.Project('crackme0x06', load_options={"auto_load_libs": False}) 

	cfg = proj.analyses.CFG()
	FIND_ADDR = 0x08048567 # cfg.kb.functions.function(name="exit").addr
	AVOID_ADDR = 0x080485f9 # dword [esp] = str.Password_Incorrect__n ; [0x804874e:4]=0x73736150 LEA str.Password_Incorrect__n ; "Password Incorrect!." @ 0x804874e

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
│           0x08048607      55             push ebp
│           0x08048608      89e5           ebp = esp
│           0x0804860a      81ec88000000   esp -= 0x88
│           0x08048610      83e4f0         esp &= 0xfffffff0
│           0x08048613      b800000000     eax = 0
│           0x08048618      83c00f         eax += 0xf
│           0x0804861b      83c00f         eax += 0xf
│           0x0804861e      c1e804         eax >>>= 4
│           0x08048621      c1e004         eax <<<= 4
│           0x08048624      29c4           esp -= eax
│           0x08048626      c70424638704.  dword [esp] = str.IOLI_Crackme_Level_0x06_n ; [0x8048763:4]=0x494c4f49 LEA str.IOLI_Crackme_Level_0x06_n ; "IOLI Crackme Level 0x06." @ 0x8048763
│           0x0804862d      e886fdffff     sym.imp.printf ()
│           0x08048632      c704247c8704.  dword [esp] = str.Password: ; [0x804877c:4]=0x73736150 LEA str.Password: ; "Password: " @ 0x804877c
│           0x08048639      e87afdffff     sym.imp.printf ()
│           0x0804863e      8d4588         eax = [ebp - local_78h]
│           0x08048641      89442404       dword [esp + arg_4h] = eax
│           0x08048645      c70424878704.  dword [esp] = 0x8048787     ; [0x8048787:4]=0x7325 ; "%s" @ 0x8048787
│           0x0804864c      e847fdffff     sym.imp.scanf ()
│           0x08048651      8b4510         eax = dword [ebp + arg_10h] ; [0x10:4]=0x30002
│           0x08048654      89442404       dword [esp + arg_4h] = eax
│           0x08048658      8d4588         eax = [ebp - local_78h]
│           0x0804865b      890424         dword [esp] = eax
│           0x0804865e      e825ffffff     sym.check ()
│           0x08048663      b800000000     eax = 0
│           0x08048668      c9             
╘           0x08048669      c3    
[0x08048400]> pdf @ sym.check 
╒ (fcn) sym.check 127
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_ch @ ebp+0xc
│           ; arg int arg_10h @ ebp+0x10
│           ; arg int arg_13h @ ebp+0x13
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x0804865e (sym.main)
│           0x08048588      55             push ebp
│           0x08048589      89e5           ebp = esp
│           0x0804858b      83ec28         esp -= 0x28
│           0x0804858e      c745f8000000.  dword [ebp - local_8h] = 0
│           0x08048595      c745f4000000.  dword [ebp - local_ch] = 0
│           ; JMP XREF from 0x080485f7 (sym.check)
│       ┌─> 0x0804859c      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│       │   0x0804859f      890424         dword [esp] = eax
│       │   0x080485a2      e801feffff     sym.imp.strlen ()
│       │   0x080485a7      3945f4         if (dword [ebp - local_ch] == eax ; [0x13:4]=256
│      ┌──< 0x080485aa      734d           jae 0x80485f9 
│      ││   0x080485ac      8b45f4         eax = dword [ebp - local_ch]
│      ││   0x080485af      034508         eax += dword [ebp + arg_8h]
│      ││   0x080485b2      0fb600         eax = byte [eax]
│      ││   0x080485b5      8845f3         byte [ebp - local_dh] = al
│      ││   0x080485b8      8d45fc         eax = [ebp - local_4h]
│      ││   0x080485bb      89442408       dword [esp + arg_8h] = eax
│      ││   0x080485bf      c74424043d87.  dword [esp + arg_4h] = 0x804873d ; [0x804873d:4]=0x50006425 ; "%d" @ 0x804873d
│      ││   0x080485c7      8d45f3         eax = [ebp - local_dh]
│      ││   0x080485ca      890424         dword [esp] = eax
│      ││   0x080485cd      e8f6fdffff     sym.imp.sscanf ()
│      ││   0x080485d2      8b55fc         edx = dword [ebp - local_4h]
│      ││   0x080485d5      8d45f8         eax = [ebp - local_8h]
│      ││   0x080485d8      0110           dword [eax] += edx
│      ││   0x080485da      837df810       if (dword [ebp - local_8h] == 0x10 ; [0x10:4]=0x30002
│     ┌───< 0x080485de      7512           notZero 0x80485f2)
│     │││   0x080485e0      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│     │││   0x080485e3      89442404       dword [esp + arg_4h] = eax
│     │││   0x080485e7      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│     │││   0x080485ea      890424         dword [esp] = eax
│     │││   0x080485ed      e828ffffff     sym.parell ()
│     └───> 0x080485f2      8d45f4         eax = [ebp - local_ch]
│      ││   0x080485f5      ff00           dword [eax]++
│      │└─< 0x080485f7      eba3           goto 0x804859c
│      └──> 0x080485f9      c704244e8704.  dword [esp] = str.Password_Incorrect__n ; [0x804874e:4]=0x73736150 LEA str.Password_Incorrect__n ; "Password Incorrect!." @ 0x804874e
│           0x08048600      e8b3fdffff     sym.imp.printf ()
│           0x08048605      c9             
╘           0x08048606      c3    
[0x08048400]> pdf @ sym.parell   
╒ (fcn) sym.parell 110
│           ; arg int arg_8h @ ebp+0x8
│           ; arg int arg_9h @ ebp+0x9
│           ; arg int arg_ch @ ebp+0xc
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x080485ed (sym.check)
│           0x0804851a      55             push ebp
│           0x0804851b      89e5           ebp = esp
│           0x0804851d      83ec18         esp -= 0x18
│           0x08048520      8d45fc         eax = [ebp - local_4h]
│           0x08048523      89442408       dword [esp + arg_8h] = eax
│           0x08048527      c74424043d87.  dword [esp + arg_4h] = 0x804873d ; [0x804873d:4]=0x50006425 ; "%d" @ 0x804873d
│           0x0804852f      8b4508         eax = dword [ebp + arg_8h]  ; [0x8:4]=0
│           0x08048532      890424         dword [esp] = eax
│           0x08048535      e88efeffff     sym.imp.sscanf ()
│           0x0804853a      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│           0x0804853d      89442404       dword [esp + arg_4h] = eax
│           0x08048541      8b45fc         eax = dword [ebp - local_4h]
│           0x08048544      890424         dword [esp] = eax
│           0x08048547      e868ffffff     sym.dummy ()
│           0x0804854c      85c0           if (eax == eax
│       ┌─< 0x0804854e      7436           isZero 0x8048586)
│       │   0x08048550      c745f8000000.  dword [ebp - local_8h] = 0
│       │   ; JMP XREF from 0x08048584 (sym.parell)
│      ┌──> 0x08048557      837df809       if (dword [ebp - local_8h] == 9 ; [0x9:4]=0
│     ┌───< 0x0804855b      7f29           isGreater 0x8048586)
│     │││   0x0804855d      8b45fc         eax = dword [ebp - local_4h]
│     │││   0x08048560      83e001         eax &= 1
│     │││   0x08048563      85c0           if (eax == eax
│    ┌────< 0x08048565      7518           notZero 0x804857f)
│    ││││   0x08048567      c70424408704.  dword [esp] = str.Password_OK__n ; [0x8048740:4]=0x73736150 LEA str.Password_OK__n ; "Password OK!." @ 0x8048740
│    ││││   0x0804856e      e845feffff     sym.imp.printf ()
│    ││││   0x08048573      c70424000000.  dword [esp] = 0
│    ││││   0x0804857a      e869feffff     sym.imp.exit ()
│    └────> 0x0804857f      8d45f8         eax = [ebp - local_8h]
│     │││   0x08048582      ff00           dword [eax]++
│     │└──< 0x08048584      ebd1           goto 0x8048557
│     └─└─> 0x08048586      c9             
╘           0x08048587      c3      
[0x08048500]> pdf @ sym.dummy   
╒ (fcn) sym.dummy 102
│           ; arg int arg_ch @ ebp+0xc
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_8h @ esp+0x8
│           ; CALL XREF from 0x08048547 (sym.parell)
│           0x080484b4      55             push ebp
│           0x080484b5      89e5           ebp = esp
│           0x080484b7      83ec18         esp -= 0x18
│           0x080484ba      c745fc000000.  dword [ebp - local_4h] = 0
│       ┌─> 0x080484c1      8b45fc         eax = dword [ebp - local_4h]
│       │   0x080484c4      8d1485000000.  edx = [eax*4]
│       │   0x080484cb      8b450c         eax = dword [ebp + arg_ch]  ; [0xc:4]=0
│       │   0x080484ce      833c0200       if (dword [edx + eax] == 0
│      ┌──< 0x080484d2      743a           isZero 0x804850e)
│      ││   0x080484d4      8b45fc         eax = dword [ebp - local_4h]
│      ││   0x080484d7      8d0c85000000.  ecx = [eax*4]
│      ││   0x080484de      8b550c         edx = dword [ebp + arg_ch]  ; [0xc:4]=0
│      ││   0x080484e1      8d45fc         eax = [ebp - local_4h]
│      ││   0x080484e4      ff00           dword [eax]++
│      ││   0x080484e6      c74424080300.  dword [esp + arg_8h] = 3
│      ││   0x080484ee      c74424043887.  dword [esp + arg_4h] = str.LOLO ; [0x8048738:4]=0x4f4c4f4c LEA str.LOLO ; "LOLO" @ 0x8048738
│      ││   0x080484f6      8b0411         eax = dword [ecx + edx]
│      ││   0x080484f9      890424         dword [esp] = eax
│      ││   0x080484fc      e8d7feffff     sym.imp.strncmp ()
│      ││   0x08048501      85c0           if (eax == eax
│      │└─< 0x08048503      75bc           notZero 0x80484c1)
│      │    0x08048505      c745f8010000.  dword [ebp - local_8h] = 1
│      │┌─< 0x0804850c      eb07           goto 0x8048515
│      └──> 0x0804850e      c745f8000000.  dword [ebp - local_8h] = 0
│       │   ; JMP XREF from 0x0804850c (sym.dummy)
│       └─> 0x08048515      8b45f8         eax = dword [ebp - local_8h]
│           0x08048518      c9             
╘           0x08048519      c3      
"""
