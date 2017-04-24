#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Runtime: ~? minutes

import angr, string, simuvex
# START_ADDR=
# FIND_ADDR=
# AVOID_ADDRS=()

import IPython # Remove this before merging.


def main():
	proj = angr.Project('./license', load_options={"auto_load_libs": False})

	key_length = 1024
	key_name = "_a\nb\tc_"

	state = proj.factory.entry_state(addr=START_ADDR, args=["./definitely_maybe_fb594f5bd4bfaf0c685a69b5bae84573", key_name])

	key = state.se.BVS('key_bytes', key_length * 8)
	content = simuvex.SimSymbolicMemory(memory_id='file_{}'.format(key_name))
	content.set_state(state)
	content.store(0, key)
	key_file = simuvex.SimFile(key_name, 'rw', content=content, size=key_length)
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
		path_group.explore(find=corrector, avoid=avoider, n=10)
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