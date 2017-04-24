#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Runtime: ~? minutes

import angr, string, simuvex
START_ADDR=0x4009c0
FIND_ADDR=0x400e93
AVOID_ADDRS=(0x400a85, 0x4010df, 0x400bb1, 0x400b6d, 0x4010f3, 0x400ebf, 0x40110c, 0x400b8f)

import IPython # Remove this before merging.

def main():
	proj = angr.Project('./license', load_options={"auto_load_libs": False})

	key_length = 8196
	key_name = "_a\nb\tc_"

	# state = proj.factory.full_init_state()
	# state = proj.factory.blank_state(remove_options={simuvex.s_options.LAZY_SOLVES})
	state = proj.factory.entry_state(addr=START_ADDR, remove_options={simuvex.s_options.LAZY_SOLVES}, args=["./license"])

	key = state.se.BVS('key_bytes', key_length * 8)
	content = simuvex.SimSymbolicMemory(memory_id='file_{}'.format(key_name))

	#for byte in key.chop(8):
	#	state.add_constraints(byte != '\x00') # null
	#	state.add_constraints(byte >= ' ') # '\x20'
	#	state.add_constraints(byte <= '~') # '\x7e'

	# state.add_constraints(key.chop(8)[0] == 'A')
	# state.add_constraints(key.chop(8)[1] == 'S')
	# state.add_constraints(key.chop(8)[2] == 'I')
	# state.add_constraints(key.chop(8)[3] == 'S')
	# state.add_constraints(key.chop(8)[4] == '{')

	content.set_state(state)
	content.store(0, key)

	key_file = simuvex.SimFile(key_name, 'r', content=content, size=key_length)
	fs = {
		key_name: key_file
	}
	state.posix.fs = fs

	path = proj.factory.path(state)  # Set up the first path.
	path_group = proj.factory.path_group(path)  # Create the path group.

	def correcter(path):
		try:
			return 'successfully' in path.state.posix.dumps(1)  # If we found the flag, return true.
		except:
			return False  # If the string isn't in stdout, then we haven't found the solution yet.

	def avoider(path):
		try:
			return 'not found' or 'wrong' or 'fail' in path.state.posix.dumps(1)  # If we see these strings, then it's definitely wrong.
		except:
			return False

	while path_group.active:
		path_group.explore(find=FIND_ADDR, avoid=AVOID_ADDRS, n=1)
		# path_group.explore(find=correcter, avoid=avoider, n=1)
		try:
			for a in path_group.active:
				print a
				print str(a.callstack_backtrace)
				# print a.state.se.state.posix.dumps(1)
				print repr(a.state.se.state.posix.dumps(3))
				#print filter(lambda x: x in string.printable, a.state.se.state.posix.dumps(3)).split()[0]
		except:
			pass

		print path_group
		# IPython.embed()

	# IPython.embed()

	found = path_group.found[-1]
	stdin = found.state.posix.dumps(0)
	stdout = found.state.posix.dumps(1)

	# This trims off anything that's not printable.
	flag1 = filter(lambda x: x in string.printable, stdin).split()[0]
	flag2 = filter(lambda x: x in string.printable, stdout).split()[0]

	print flag1
	print flag2

	# (•_•) ( •_•)>⌐■-■ (⌐■_■)
	return flag

def test():
	assert main() == 'ASIS{8d2cc30143831881f94cb05dcf0b83e0}'

if __name__ == '__main__':
	print(main())

