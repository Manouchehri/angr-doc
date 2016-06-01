#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri <manouchehri@protonmail.com>
# Modern Binary Exploitation
# http://security.cs.rpi.edu/courses/binexp-spring2015/

from IPython import embed # pop iPython at the end

import angr

FIND_ADDR = 0x080484d7 # mov dword [esp], str.Congrats_ ; [0x80485e5:4]=0x676e6f43 LEA str.Congrats_ ; "Congrats!" @ 0x80485e5
AVOID_ADDR = 0x080484eb # mov dword [esp], str.Wrong_ ; [0x80485ef:4]=0x6e6f7257 LEA str.Wrong_ ; "Wrong!" @ 0x80485ef

def main():
	proj = angr.Project('crackme0x00b', load_options={"auto_load_libs": True}) # use_sim_procedures=False

	path_group = proj.factory.path_group()
	path_group.explore(find=FIND_ADDR, avoid=AVOID_ADDR)
	found = path_group.found[0]
	found_state = found.state
	s = found_state

	addr_to_input  = s.memory.load(s.regs.esp + 4, 4, endness='Iend_LE') # 
	# return s.se.any_str(s.memory.load(addr_to_input, 32)) # All nulls. =( 

	addr_to_rodata = s.memory.load(s.regs.esp,     4, endness='Iend_LE')
	# return s.se.any_str(s.memory.load(addr_to_rodata, 32))[0::4] # Works as expected.
	
	embed()

def test():
	assert main() == 'w0wgreat'
	"""
	[0x080483e0]> px 32 @ obj.pass.1964
	- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
	0x0804a040  7700 0000 3000 0000 7700 0000 6700 0000  w...0...w...g...
	0x0804a050  7200 0000 6500 0000 6100 0000 7400 0000  r...e...a...t...
	"""

if __name__ == '__main__':
	print(main())

"""
            ;-- main:
╒ (fcn) sym.main 101
│           ; var int arg_4h @ esp+0x4
│           ; var int arg_1ch @ esp+0x1c
│           ; UNKNOWN XREF from 0x080483f8 (entry0)
│           ; DATA XREF from 0x080483f7 (entry0)
│           0x08048494      55             push ebp
│           0x08048495      89e5           ebp = esp
│           0x08048497      83e4f0         esp &= 0xfffffff0
│           0x0804849a      83c480         esp += -0x80
│           ; JMP XREF from 0x080484f7 (sym.main)
│       ┌─> 0x0804849d      b8d0850408     eax = str.Enter_password:   ; "Enter password: " @ 0x80485d0
│       │   0x080484a2      890424         dword [esp] = eax
│       │   0x080484a5      e8d6feffff     sym.imp.printf ()
│       │   0x080484aa      b8e1850408     eax = 0x80485e1
│       │   0x080484af      8d54241c       edx = [esp + arg_1ch]       ; 0x1c
│       │   0x080484b3      89542404       dword [esp + arg_4h] = edx
│       │   0x080484b7      890424         dword [esp] = eax
│       │   0x080484ba      e811ffffff     sym.imp.__isoc99_scanf ()
│       │   0x080484bf      8d44241c       eax = [esp + arg_1ch]       ; 0x1c
│       │   0x080484c3      89442404       dword [esp + arg_4h] = eax
│       │   0x080484c7      c7042440a004.  dword [esp] = obj.pass.1964 ; [0x804a040:4]=119 LEA obj.pass.1964 ; "w" @ 0x804a040
│       │   0x080484ce      e8bdfeffff     sym.imp.wcscmp ()
│       │   0x080484d3      85c0           if (eax == eax
│      ┌──< 0x080484d5      7514           notZero 0x80484eb)
│      ││   0x080484d7      c70424e58504.  dword [esp] = str.Congrats_ ; [0x80485e5:4]=0x676e6f43 LEA str.Congrats_ ; "Congrats!" @ 0x80485e5
│      ││   0x080484de      e8bdfeffff     sym.imp.puts ()
│      ││   0x080484e3      90             
│      ││   0x080484e4      b800000000     eax = 0
│      ││   0x080484e9      c9             
│      ││   0x080484ea      c3             
│      └──> 0x080484eb      c70424ef8504.  dword [esp] = str.Wrong_    ; [0x80485ef:4]=0x6e6f7257 LEA str.Wrong_ ; "Wrong!" @ 0x80485ef
│       │   0x080484f2      e8a9feffff     sym.imp.puts ()
╘       └─< 0x080484f7      eba4           goto 0x804849d

"""
