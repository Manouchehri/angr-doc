#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Runtime: ~? minutes

import angr, string, simuvex
START_ADDR=0x400810
FIND_ADDR=0x401500
AVOID_ADDRS=(0x401291, 0x4012d1, 0x40137e, 0x4014cd)

import IPython # Remove this before merging.

BUF_LEN = 40

# def char(state, c):
# 	'''returns constraints s.t. c is printable'''
# 	return state.se.And(c <= '~', c >= ' ')

# def char(state, n):
# 	"""Returns a symbolic BitVector and contrains it to printable chars for a given state."""
# 	vec = state.se.BVS('c{}'.format(n), 8, explicit_name=True)
# 	return vec, state.se.And(vec >= ord(' '), vec <= ord('~'))

def main():
	proj = angr.Project('./definitely_maybe_fb594f5bd4bfaf0c685a69b5bae84573', load_options={"auto_load_libs": False, 'force_load_libs': ['liblapacke.so.3']})

	key_length = 2304
	key_name = "key"

	state = proj.factory.entry_state(addr=START_ADDR, args=["./definitely_maybe_fb594f5bd4bfaf0c685a69b5bae84573", key_name])

	key = state.se.BVS('key_bytes', key_length * 8)
	content = simuvex.SimSymbolicMemory(memory_id='file_{}'.format(key_name))

	# bytes = None
	# constraints = [ ]

	# for i in range(key_length):
	# 	c = state.se.BVS('key_file_byte_%d_%d' % (i, i), 8)
	# 	state.se.add(char(state, c))

	for byte in key.chop(8):
		state.add_constraints(byte != '\x00') # null
		state.add_constraints(byte >= ' ') # '\x20'
		state.add_constraints(byte <= '~') # '\x7e'

	# content = simuvex.SimSymbolicMemory(memory_id="file_%s" % key_name)
	state.add_constraints(key.chop(8)[0] == 'P')
	state.add_constraints(key.chop(8)[1] == 'C')
	state.add_constraints(key.chop(8)[2] == 'T')
	state.add_constraints(key.chop(8)[3] == 'F')
	state.add_constraints(key.chop(8)[4] == '{')

	content.set_state(state)
	content.store(0, key)
	# IPyrhon.embed()

	# for i in range(key_length):
	# 	c, cond = char(state, i)
	# 	# the first command line argument is copied to INPUT_ADDR in memory
	# 	# so we store the BitVectors for angr to manipulate
	# 	state.memory.store(0 + i, c)
	# 	state.add_constraints(cond)

	# content.store(0, key)

	key_file = simuvex.SimFile(key_name, 'rw', content=content, size=key_length)

	fs = {
		key_name: key_file
	}
	state.posix.fs = fs


	# for i in range(12):
	#  	c = state.posix.files[0].read_from(3)
	#  	state.se.add(char(state, c))

	# state.posix.files[0].seek(0)
	# state.posix.files[0].length = BUF_LEN

	path = proj.factory.path(state)  # Set up the first path.
	path_group = proj.factory.path_group(path)  # Create the path group.

	while path_group.active:
		path_group.explore(find=FIND_ADDR, avoid=AVOID_ADDRS, n=10)  # This will take a couple minutes. Ignore the warning message(s), it's fine.
		try:
			for a in path_group.active:
				print filter(lambda x: x in string.printable, a.state.se.state.posix.dumps(3)).split()[0]
				print a.state.se.state.posix.dumps(1)
		except:
			pass
		print path_group
		# IPython.embed()

	# IPython.embed()

	found = path_group.found[-1]
	stdin = found.state.posix.dumps(0)

	# This trims off anything that's not printable.
	flag = filter(lambda x: x in string.printable, stdin).split()[0]

	# (•_•) ( •_•)>⌐■-■ (⌐■_■)
	return flag

def test():
	assert main() == '*shrug*'

if __name__ == '__main__':
	print(main())