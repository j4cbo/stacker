#!/usr/bin/python
#
# Stack analyzer, copyright (c) 2007-2011 Jacob Potter.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2, as published by the Free Software Foundation.

import sys
import functree
import disasm
import fnmatch
import ConfigParser
import fixup

MAX_TREES = 10

if len(sys.argv) < 2:
	print "usage: %s [config]" % sys.argv[0]
	sys.exit(1)


def get_funcs(config):
	"""Given a config file, parse the binary and return a function dict.
	"""
	parser = disasm.Parser(config.get("stacker", "prefix"))
	fname = config.get("stacker", "binary")
	funcs = {}

	for name, lines in parser.parse(fname).iteritems():
		f = functree.Func(name, lines)
		funcs[name] = f
	return funcs


def print_tree(tree):
	for startfunc, paths in tree:
		print "Stack used from %s: " % (startfunc, )
	
		if len(paths) > MAX_TREES:
			print "\t(%d call paths omitted)" % (len(paths) - MAX_TREES)

		for funclist in paths[-MAX_TREES:]:
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


def entry_predicate(config):
	"""Produce a predicate to determine if a function is a start point.
	"""
	try:
		estr = config.get("entry", "entries")
	except ConfigParser.NoOptionError:
		estr = "main"

	entries = estr.split()

	return lambda name: any(
		fnmatch.fnmatch(name, pattern)
		for pattern
		in entries
	)


def main(configfile):
	config = ConfigParser.ConfigParser()
	config.optionxform = str
	config.read(configfile)

	if not config.items("stacker"):
		print "No stacker section found in config file."
		sys.exit(1)

	funcs = get_funcs(config)

	for ff in fixup.all_fixups:
		ff(config, funcs)

	for f in funcs.itervalues():
		if f.confusing():
			f.dump()

	tree = functree.grind_tree(funcs, entry_predicate(config))

	print_tree(tree)

if __name__ == "__main__":
	main(sys.argv[1])
