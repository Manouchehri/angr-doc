#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri

import angr, simuvex, logging

angr.loggers.setall(logging.DEBUG)

AVOID_ADDR = 0xc14
FIND_ADDR = 0x1328  # This is shortly after the printf.

def main():
	proj = angr.Project('forkbomb', load_options={"auto_load_libs": False}) 
	
	proj.hook_symbol('fork', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
	proj.hook_symbol('rand', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
	proj.hook_symbol('srand', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
	proj.hook_symbol('waitpid', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])

	path_group = proj.factory.path_group()

	path_group.explore(find=FIND_ADDR)
	from IPython import embed
	embed()

	found = path_group.found[-1]
	stdin = found.state.posix.dumps(1)

	# This trims off anything that's not printable.
	flag = filter(lambda x: x in string.printable, stdin).split()[0]

	return flag

def test():
	assert main() == ''

if __name__ == '__main__':
	print(main())
