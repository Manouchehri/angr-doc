#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# Author: David Manouchehri
# Starter code for https://lists.cs.ucsb.edu/pipermail/angr/2017-May/000368.html

import logging
import pickle
import ana
logging.getLogger('ana').setLevel(logging.DEBUG)
ana.set_dl(ana.DirDataLayer("/tmp/") ) # Set this to an NVMe SSD instead of RAM.

import angr
logging.getLogger('angr').setLevel(logging.DEBUG)

import IPython

solution = ""  # TODO

def start_and_dump():
	proj = angr.Project('./baby-re',  load_options={'auto_load_libs': False})

	path_group = proj.factory.path_group()
	path_group.explore(find=0x40294b, avoid=0x402941, n=100)

	IPython.embed()

	with open("/tmp/path_group.pickle", 'wb') as outfile:
		pickle.dump(path_group, outfile, -1)
		# path_group.split(from_stash='active', to_stash='stashed', limit=1024)
		# pickle.dump(path_group.stashed, outfile, -1)
		# path_group.drop(stash='stashed')  # Not really needed in this example.
		outfile.close()

def resume():
	proj = angr.Project('./baby-re',  load_options={'auto_load_libs': False})

	path_group = proj.factory.path_group()

	with open("/tmp/path_group.pickle", 'rb') as infile:
		pickle.load(infile)
		infile.close()

	# path_group.move(from_stash='stashed', to_stash='active')
	
	IPython.embed()

	# solution = path_group.found[0].state.posix.dumps(1)

def main():
	start_and_dump()
	resume()
	return solution

def test():
	assert 'Math is hard!' in main()


if __name__ == '__main__':
	print(repr(main()))
