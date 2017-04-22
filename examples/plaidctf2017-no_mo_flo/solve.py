#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Runtime: ~? minutes

import angr, string
START_ADDR=0x40272e
FIND_ADDR=0x4027f6
AVOID_ADDRS=(0x402758, 0x402c38)

import IPython # Remove this before merging.

BUF_LEN = 40

def char(state, c):
	'''returns constraints s.t. c is printable'''
	return state.se.And(c <= '~', c >= ' ')

def main():
	proj = angr.Project('./no_flo_f51e2f24345e094cd2080b7b690f69fb', load_options={"auto_load_libs": False})

	state = proj.factory.entry_state(addr=START_ADDR)

	for i in range(BUF_LEN):
		c = state.posix.files[0].read_from(1)
		state.se.add(char(state, c))

	state.posix.files[0].seek(0)
	state.posix.files[0].length = BUF_LEN

	path = proj.factory.path(state)  # Set up the first path.
	path_group = proj.factory.path_group(path)  # Create the path group.

	path_group.explore(find=FIND_ADDR, avoid=AVOID_ADDRS)  # This will take a couple minutes. Ignore the warning message(s), it's fine.

	# Path explosion I think?
	IPython.embed()

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
