# Stack analyzer, copyright (c) 2007-2011 Jacob Potter.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2, as published by the Free Software Foundation.

import os
import re
import collections

def print_new_edges(fixup, new_edges):
	"""Print out the new edges added by a fixup.
	"""

	# Print out the edges we added
	if not new_edges:
		return

	print "Edges added by [%s] fixup:" % (fixup, )

	for name, targets in new_edges.iteritems():
		print "    %s -> %s" % (name, ", ".join(targets))


def fixup_ignore_callees(config, funcs):
	if "ignore_callees" not in config.sections():
		return

	for src, dest in config.items("ignore_callees"):
		if src not in funcs:
			print "WARNING: ignore_callees: %s not found" % src
			continue

		sf = funcs[src]

		dests = dest.split()
		for d in dests:
			sf.calls.remove(d)
			print "Ignoring call %s -> %s" % (src, d)


def fixup_by_name_regex(config, funcs):
	"""Add edges to the graph by regexes based on function name.

	This reads the "targets" section of the config file. Each line's key
	is a regex describing source function names. The value is a regex
	describing functions that the source has call edges to. Backreferences
	in the value refer to groups in the source. For example:

	    [targets]
	    FPA_(.*) = (.*)_FPV_\\1

	This indicates that for all foo and bar, FPA_foo may call bar_FPV_foo.
	"""

	if "targets" not in config.sections():
		return

	wiring = collections.defaultdict(set)
	for src, dest in config.items("targets"):
		# For each source glob, find all matching functions
		regex = re.compile(src + "$")

		for name in funcs.iterkeys():
			match = regex.match(name)
			if not match: continue

			# Now, produce a target regex.
			fdest = dest
			if match.lastindex:
				for i in range(1, min(match.lastindex, 9) + 1):
					fdest = fdest.replace("\\%s" % i, match.group(i))

			wiring[fdest + "$"].add(name)

	# Now, wiring is a dict mapping regexes to sets: "if a function
	# matches this regex, then this set of callers have edges to it."
	# Here we turn it into a list of (compiled regex, set) pairs:
	wiring = [ (re.compile(pat), s) for pat, s in wiring.iteritems() ]

	# Walk through the input and add all necessary edges
	new_edges = collections.defaultdict(set)
	for name, func in funcs.iteritems():
		for regex, srcs in wiring:
			if not regex.match(name):
				continue

			for src in srcs:
				funcs[src].calls.add(func.name)
				new_edges[src].add(func.name)

	print_new_edges("targets", new_edges)


source_extensions = [ ".c", ".h", ".S" ]


def read_all_files(srcpath):
	for path, dirs, files in os.walk(srcpath):
		for f in files:
			if not any(map(f.endswith, source_extensions)):
				continue

			f = os.path.join(path, f)

			for line in open(f).readlines():
				yield line
			

def fixup_by_table(config, funcs):
	# If there's no tables section, this fixup doesn't apply.
	try:
		line_regex = config.get("tables", "_pattern_")
	except:
		return

	line_re = re.compile(line_regex)

	if line_re.groups != 2:
		print "ERROR: table fixup pattern must have exactly 2 groups."
		return

	# Produce a dict mapping group names to the set of functions that
	# call all members of this group.
	group_callers = collections.defaultdict(set)
	for src, dests in config.items("tables"):
		if src == "_pattern_":
			continue
		if src not in funcs:
			print "WARNING: unknown caller %s" % (src, )
			continue
		for dest in dests.split():
			group_callers[dest].add(src)

	# Find all source files.
	new_edges = collections.defaultdict(set)
	for line in read_all_files(config.get("stacker", "src")):
		match = line_re.match(line)
		if not match:
			continue

		group, val = match.groups()

		if val not in funcs:
			print "WARNING: non-linked initializer %s" % (val, )
			continue

		if group not in group_callers:
			print "WARNING: unknown group %s" % (group, )
			continue

		for caller in group_callers[group]:
			funcs[caller].calls.add(val)
			new_edges[caller].add(val)
			
	print_new_edges("tables", new_edges)


all_fixups = [ fixup_by_name_regex, fixup_by_table, fixup_ignore_callees ]
