# Stack analyzer, copyright (c) 2007-2011 Jacob Potter.
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2, as published by the Free Software Foundation.

import os
import re
from subprocess import Popen, PIPE

# Parse lines out of objdump.
line_re = re.compile("""
  \\ *			# Leading whitespace
  [a-f0-9]+:\\\t	# Address
  [a-f0-9 ]+\\\t	# Assembled data
  ([a-z.]+)		# Instruction
  [ \t]*		# Gap
  ([^<]*)		# Parameters
  (?:<([^>]+)>)?	# Label, maybe.
""", re.VERBOSE)

dataline_re = re.compile("""
  \\ *			# Leading whitespace
  [a-f0-9]+:\\\t	# Address
  (
      ((([a-f0-9]{2})|(\\ {2}))\\ ){16}	# Sixteen bytes
    | ((([a-f0-9]{4})|(\\ {4}))\\ ){8}	# ... or eight 2-byte values
    | ((([a-f0-9]{8})|(\\ {8}))\\ ){4}	# ... or four 4-byte values
  )
""", re.VERBOSE)

function_re = re.compile("^[a-f0-9]+ <([^>]+)>:$")

def parse_functions(line_iter):
	while True:
		f = parse_function(line_iter)
		if f:
			yield f

class Parser:
	def __init__(self, prefix):
		self.prefix = prefix

	def parse(self, fname):
		cmd = ("%sobjdump" % (self.prefix, ), "-d", "-j.text", fname)
		objdump = Popen(cmd, stdin = PIPE, stdout = PIPE)
		objdump.stdin.close()
		lines = objdump.stdout.readlines()

		line_iter = (s.rstrip() for s in lines)

		return dict(parse_functions(line_iter))

def parse_function(line_iter):

	function_match = None

	# Read lines until we get a function header
	while True:
		line = line_iter.next()
		function_match = function_re.match(line)
		if function_match:
			break

	# If we ran out of file, just return None
	if not function_match:
		return None

	function_name = function_match.group(1)
	lines = []

	# Then, parse each line of it
	for line in line_iter:
		# Stop when we get something indicating the
		# end of the function
		if line == "\t...":
			continue
		if not line:
			break

		# If this is a data symbol, skip it completely
		if dataline_re.match(line):
			return None

		line_match = line_re.match(line)
		if not line_match:
			print "!!! UNMATCHED: %r" % (line, )
			continue

		# Pull out the instruction and args
		insn, args, label = line_match.groups()

		# Get rid of comments.
		args = args.split(";")[0].rstrip()

		lines.append((insn, args, label))

	return function_name, lines
