#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Author: David Manouchehri
# Binary origins unknown

import angr

proj = angr.Project('catalyst', load_options={"auto_load_libs": False}) 

def nuller(state):
	pass
	# return 0

import simuvex
# proj.hook_symbol('puts', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
# proj.hook_symbol('putchar', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])
# proj.hook_symbol('printf', simuvex.SimProcedures['stubs']['ReturnUnconstrained'])

proj.hook_symbol('puts', nuller)
proj.hook_symbol('putchar', nuller)
proj.hook_symbol('printf', nuller)

MAIN_ADDR=0x400d93
state = proj.factory.blank_state(addr=MAIN_ADDR) # Beginning of function
# state = proj.factory.full_init_state(addr=MAIN_ADDR) # Beginning of function

# initial_path = proj.factory.path(state)  # Is this needed?
path_group = proj.factory.path_group(state)

FIND_ADDR=0x400896
path_group.explore(find=FIND_ADDR)
e = path_group.errored[0]

from IPython import embed
embed()
