# Stack analyzer, copyright (c) 2007-2011 Jacob Potter.
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2, as published by the Free Software Foundation.

import os
import sys
import re
import disasm
from arch.arm import canonicalize_line
import itertools

class Func(object):
	def __init__(self, name, code):
		# Initialize members
		self.name = name
		self.stack = 0
		self.calls = set()
		self.tail_calls = set()
		self.confusions = set()
		self.code = code

		# Turn code into pseudocode
		self.pcode = list(canonicalize_function(name, code))

		# Parse out the body
		self.parse_pseudocode()


	def parse_pseudocode(self):
		"""Process the pseudocode of a function.

		This analyzes all the pseudo-ops in self.pcode, and finds
		the function's stack usage, callees, and tail-callees. It
		should only be called from __init__.
		"""

		peak = 0
		depth = 0

		# Helper
		confuse = self.confusions.add
		
		ret_with_stack_ok = False

		for op, v in self.pcode:
			if op == "stack":
				depth += v
				if (depth > peak):
					peak = depth

			elif op == "ret":
				# We should never return with anything still
				# on the stack!
				if depth:
					confuse("ret-with-stack")

				# We only understand conditional returns if
				# there was never anything on the stack.
				if peak and (not v):
					confuse("conditional-ret")

				# Reset to our peak depth.
				depth = peak

			elif op == "tablejump":
				# We can be pretty sure that a table jump when
				# we have an active stack frame is local-only.
				if not depth:
					confuse("tablejump-with-stack")

			elif op == "indirectjump":
				confuse("indirect-jump")

			elif op == "call":
				self.calls.add(v)

			elif op == "tailcall":
				self.tail_calls.add(v)
			
			elif op == "restore_fp":
				ret_with_stack_ok = True

			else:
				confuse("unknown-op")

		# If we use the frame pointer, it's okay to ret-with-stack.
		if ret_with_stack_ok and "ret-with-stack" in self.confusions:
			self.confusions.remove("ret-with-stack")
		
		# If we might tail-call or regular-call, count it as regular.
		self.tail_calls -= self.calls
		self.stack = peak


	def confusing(self):
		"""Return True if we were confused by this function."""
		return bool(self.confusions)


	def excuse(self, transgression):
		"""If we were confused because of something, forget it."""
		if transgression in self.confusions:
			self.confusions.remove(transgression)


	def walk_graph(self, func_dict, history = []):
		"""Find all the call paths starting at this function.

		This returns a generator that emits a list for each possible
		call path starting at this function and ending at a leaf. The 
		"history" parameter is prepended to each output list. Path
		lists are tuples of the form (func, is_tc); is_tc is True if
		func tail-calls the next function in the list.
		"""

		# We behave a little differently if we are in panic().  For
		# one, we are allowed to recur through the call tree if we
		# are a child of panic(), and for another, we stop at the
		# second call of panic() if we are a child of panic().
		ispanic = ("panic" in func_dict) and (func_dict["panic"] in [ f for f, is_tc in history ])

		# Detect cycles in the call graph
		if (not ispanic) and (self in [ f for f, is_tc in history ]):
			history += [ (self, False) ]
			raise Exception("You are a clown: " + str(history))

		# If this is the second time through panic(), assume that
		# can't really happen, and decide to leave things be.
		if ispanic and self.name == "panic":
			yield history
			return
		
		# If this is a leaf function, record the path that got us here
		if not (self.calls or self.tail_calls):
			yield history + [ (self, False) ]
			return

		# Otherwise, loop through each function this one calls
		for childname in self.calls | self.tail_calls:
			try:
				child = func_dict[childname]
			except KeyError:
				raise Exception("unknown function %s called from %s" % (childname, self.name))

			# Indicate whether or not our own stack frame should
			# be included as part of this path.
			nextstep = history + [ (self, childname in self.tail_calls) ]

			for p in child.walk_graph(func_dict, nextstep):
				yield p


	def dump(self, f = sys.stdout):
		"""Dump the result of analyzing this function.

		Normally, this will print the stack usage, callees, and
		tail-callees. If the function was confusing, then it will
		also dump the pseudocode.
		"""

		f.write("%s\n" % self.name)
		if self.confusions:
			f.write("    *** confusing: %s\n" %
				", ".join(set(self.confusions)))
			for op, v in self.pcode:
				f.write("        %s %s\n" % (op, v))

		f.write("    stack: %d\n" % self.stack)

		if self.calls:
			f.write("    calls: %s\n" % ", ".join(self.calls))
		if self.tail_calls:
			f.write("    tail calls: %s\n" % ", ".join(self.tail_calls))


	def __str__(self):
		return "%s (%d)" % (self.name, self.stack)

	def __repr__(self):
		return "<function %s>" % (self.name, )


def canonicalize_function(function_name, lines):
	"""Turn a list of instructions into a list of pseudo-ops.

	Call the architecture-specific canonicalize_line function for
	each line in the input, and returns a sequence of canonical lines.
	"""

	for line in lines:
		cline = canonicalize_line(function_name, line)
		if type(cline) is tuple:
			yield cline
		elif cline is not None:
			for cl in cline:
				yield cl


def path_length(paths):
	"""Return the total stack usage along a path.
	"""
	return sum(path.stack for path, is_tc in paths if not is_tc)


def grind_tree(funcs, start_predicate):
	"""Find all the paths through a program.

	Given a dict of all functions in the program and a predicate for
	determining by name whether a function is a start point, return
	a list of (start_function_name, paths).
	"""

	functree = (
		(name, sorted(func.walk_graph(funcs), key = path_length))
		for name, func
		in sorted(funcs.iteritems())
		if start_predicate(name)
	)

	return functree

