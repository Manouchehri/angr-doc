from collections import defaultdict

import angr
import simuvex
import claripy

import analysis

"""
Memory metadata we keep for each address, like the addresses of the malloc
and the free calls, and the addresses of the read or write instructions.
This is a global variable since we pass a SimProcedure *class*, not an instance,
as the hook callback.
"""

memhash = defaultdict(lambda: { "malloc_site": 0, "size": 0, "free_site": [],
                                "read_site": [], "write_site": [] })

class MallocHook(simuvex.SimProcedure):
    def run(self, size):
        caller = analysis.Analysis.get_caller(self.state)

        # We call angr's malloc simprocedure, we don't want to
        # mess with angr's internals.
        malloc = simuvex.SimProcedures['libc.so.6']['malloc']
        addrsym = malloc(self.state, arguments=[size]).ret_expr
        addr = self.state.se.any_int(addrsym)

        memhash[addr]["malloc_site"] = addr
        memhash[addr]["size"] = size
        return addrsym

class FreeHook(simuvex.SimProcedure):
    def run(self, ptrsym):
        # TODO: Check for double-free
        ptr = self.state.se.any_int(ptrsym)
        caller = analysis.Analysis.get_caller(self.state)
        memhash[ptr]["free_site"].append(caller)

class UseAfterFree(analysis.Analysis):
    def __init__(self, args):
        super(UseAfterFree, self).__init__(args)
        self.uaf_analysis(args)

    def uaf_analysis(self, args):
        """
        For Use-After-Free detection, we track all allocations and
        deallocations in the memhash. Then, on each memory read or
        write, we check if the operand is within a heap buffer that
        was previously freed.
        """

        # Here we have to pass a *class* of type SimProcedure
        self.project.hook_symbol('malloc', MallocHook)
        self.project.hook_symbol('free', FreeHook)

        def write_freed_addr_check(state):
            write_symaddr = state.inspect.mem_write_address

            # XXX: The search here can be faster if we use an ordered dict
            for addr, meminfo in memhash.viewitems():
                if len(meminfo["free_site"]) > 0:

                    # solve the system of
                    # addr <= write_symaddr <= addr+size

                    self.log.debug("CHECKING write @ {}".format(write_symaddr))
                    self.log.debug("addr: {}, size: {}, malloc call: {}, free call {}"
                            .format(hex(addr), meminfo["size"], meminfo["malloc_site"], meminfo["free_site"]))

                    in_range = claripy.And(
                            addr <= write_symaddr,
                            write_symaddr <= addr+meminfo["size"])

                    # XXX: We hit a 'NotImplementedTypeError' in some
                    # binaries with claripy.Solver().is_true
                    write_after_free = claripy.is_true(in_range)

                    if write_after_free:
                        self.log.info("Possible Write-After-Free Detected @ {}".format(write_symaddr))
                        self.log_disassembly_state(state)
                        self.log.info("addr: {}, size: {}, malloc call: {}, free call {}"
                                      .format(hex(addr), meminfo["size"], meminfo["malloc_site"], meminfo["free_site"]))


        # TODO: Do the same for mem_read
        self.start_state.inspect.b('mem_write', action=write_freed_addr_check)

        pg = self.project.factory.path_group(self.start_state)

        pg.explore()

        for addr, meminfo in memhash.viewitems():
            if len(meminfo["free_site"]) >= 2:
                self.log.info("Double-Free detected, free call sites: {}"
                              .format(','.join(hex(site) for site in meminfo["free_site"])))


angr.register_analysis(UseAfterFree, "UseAfterFree")