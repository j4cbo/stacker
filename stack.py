#!/usr/bin/python2.5
#
# Stack analyzer, copyright (c) 2007-2011 Jacob Potter.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2, as published by the Free Software Foundation.

import sys
import os
import functree
import disasm

MAX_TREES = 15

if len(sys.argv) < 2:
	print "usage: %s [object]" % sys.argv[0]
	sys.exit(1)

def is_start(name):
	if name == "main":
		return True
	if any(map(name.endswith, [ "_Handler", "_IRQHandler" ])):
		return True

def parse_file(fname):
	parser = disasm.Parser("arm-none-eabi-")
	funcs = {}

	for name, lines in parser.parse(fname).iteritems():
		f = functree.Func(name, lines)
		if f.confusing():
			f.dump()
		funcs[name] = f
	return funcs


def fixup(funcs):
	# Wire up function pointers
	for k, v in funcs.iteritems():
		if "_FPV_" not in k:
			continue
		src, suffix = k.split("_FPV_")
		if "FPA_" + suffix not in funcs:
			print "WARNING: FPA_%s not found" % (suffix, )
			continue

		funcs["FPA_" + suffix].calls.add(k)

	# Look for setup and mainloop initializers
	iin, iout = os.popen4("grep -Irh ^INITIALIZER .")
	inits = [ t.split('(', 1)[1].strip(' );').split(',')
                  for t in iout.read().split('\n') if ('(' in t) ]
	for group, val in inits:
		group = group.strip(' ')
		val = val.strip(' ')

		if val not in funcs:
			print "WARNING: non-linked initializer %s" % (val, )
			continue

		if group in [ "hardware", "protocol" ]:
			funcs["FPA_init"].calls.add(val)
		elif group == "poll":
			funcs["main"].calls.add(val)
		else:
			print "WARNING: group %s unknown" % (group, )


known_funcs = parse_file(sys.argv[1])
fixup(known_funcs)

functree = functree.grind_tree(known_funcs, is_start)

for startfunc, terminals in functree:
	print "Stack used from %s: " % (startfunc, )

	if len(terminals) > MAX_TREES:
		print "\t(%d call paths omitted)" % (len(terminals) - MAX_TREES)

	for funclist in terminals[-MAX_TREES:]:
		pathlist = []
		s = 0

		for i, (f, is_tc) in enumerate(funclist):
			if is_tc:
				pathlist.append(str(f) + " [TC]")
			else:
				pathlist.append(str(f))
				s += f.stack
			
		print "\tTotal %d: %s" % (s, " -> ".join(pathlist))

	print

