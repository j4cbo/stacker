# Stack analyzer, copyright (c) 2007-2011 Jacob Potter.
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2, as published by the Free Software Foundation.

# Which ARM instructions do we know *won't* affect control flow or stack?
safe_insn_bases = [
	"adc", "add", "adds", "and", "ands", "asr", "asrs",
	"bfi", "bfc", "bic", "bics", "bkpt",
	"clz", "cmn", "cmp", "cps", "cpsid", "cpsie", "cpy",
	"eor", "eors",
	"it", "ite", "itet", "itete", "itett", "itt", "itte", "ittet",
		"ittt", "itttt", "itee", "iteee", "ittte",
	"lsl", "lsls", "lsr", "lsrs", "sbfx",
	"ldrex", "ldrexb", "ldrexh",
	"mla", "mls", "mov", "movs", "movt", "movw", "mrs", "msr", "mul",
		"muls", "mvn", "mvns", "smull",
	"neg", "negs", "nop",
	"orn", "orr", "orrs",
	"rbit", "rev", "rev16", "revsh", "ror", "rsb", "rsbs",
	"sbc", "sbcs", "sdiv", "sev", "strex", "strexb", "strexh", "sub",
		"subs", "svc", "sxtb", "sxth",
	"teq", "tst",
	"ubfx", "udiv", "umull", "uxtb", "uxth",
	"wfe", "wfi",

	# NOTE: these are only safe because we translate ldmia and stmdb on sp to push and pop.
	"ldmia", "stmdb", "stmia", "ldmdb",

#	"ldr", "ldrb", "ldrd", "ldrh", "ldrsb", "ldrsh", "str", "strb", "strd", "strh",
]

suffixes = [
	"", "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"
]

safe_insns = []
for suffix in suffixes:
	safe_insns += [ insn + suffix for insn in safe_insn_bases ]

def is_safe_insn(insn, args):
	# Pseudo-ops like .byte, .short, .word may show up in the middle
	# of a function; they are of no interest to us.
	if insn[0] == ".":
		return True

	# Anything referring to pc or sp is unsafe
	if args[:2] in [ "pc", "sp" ]:
		return False

	# Remove .w and .n suffixes
	insn = insn.split(".")[0]

	# Is it a known-safe insn?
	if insn in safe_insns:
		return True

	# Loads or stores that don't writeback to sp are safe
	if insn[:3] in [ "ldr", "str" ]:
		# If it ends with "]", it can't writeback.
		if "sp" not in args or args.endswith("]"):
			return True

	# Otherwise...
	return False

def canonicalize_line(function_name, line):
	insn, args, target = line

	# Canonicalize push and pop
	if insn == "stmdb" and args.startswith("sp!, "):
		insn = "push"
		args = args[5:]
	if insn == "ldmia.w" and args.startswith("sp!, "):
		insn = "pop"
		args = args[5:]

	# There may or may not be a jump target attached to this insn.
	if target:
		target = target.split("+")[0]
	else:
		target = ""

	# If it's a safe insn, continue
	if is_safe_insn(insn, args):
		return None

	# If it's a branch into this function, we're fine
	if target == function_name:
		return None

	# If it's a call, make a note of that
	if insn == "bl" and target:
		return "call", target

	# Parse out the args a bit more
	pargs = args.strip("{}").split(", ")

	try:
		operand = int(pargs[1].split()[0][1:])
	except:
		operand = None

	if insn == "push":
		return "stack", 4 * len(pargs)
	elif insn == "pop":
		ret = [ ("stack", -4 * len(pargs)) ]
		if pargs[-1] == 'pc':
			ret.append(("ret", True))
		return ret
	elif insn == "stmia.w":
		ret = [ ("stack", -4 * (len(pargs) - 1)) ]
		if pargs[-1] == 'pc':
			ret.append(("ret", True))
		return ret
	elif insn == "add" and operand:
		return "stack", -operand
	elif insn == "sub" and operand:
		return "stack", operand
	elif insn == "add.w" and len(pargs) == 3 and pargs[0:2] == ["sp", "sp"]:
		return "stack", -int(pargs[2][1:])
	elif insn == "sub.w" and len(pargs) == 3 and pargs[0:2] == ["sp", "sp"]:
		return "stack", int(pargs[2][1:])
	elif insn in [ "b.n", "b.w" ] and target:
		return [
			("tailcall", target),
			("ret", True)
		]
	elif insn in [ "bne.n", "bne.w" ]:
		# XXX: This is a hack. We assume that all non-local
		# branches are conditional tail-calls; if this was
		# supposed to be something else, then the control flow
		# analysis pass will catch it and barf.
		return [
			("tailcall", target),
			("ret", False)
		]
	elif insn == "bx" and args == "lr":
		return "ret", True
	elif insn.startswith("bx") and args == "lr":
		return "ret", False
	elif insn in [ "tbb", "tbh" ] or (insn == "ldr.w" and pargs[0] == "pc"):
		# We're pretty sure that table jumps are OK, but let the
		# next stage know about them.
		return "tablejump", None
	elif insn[:3] in [ "ldr", "str" ] and len(pargs) == 3 \
			and pargs[2][0] == '#':
		offset = pargs[2][1:]
		if offset.endswith("]!"):
			offset = offset[:-2]
		return "stack", -int(offset)
	elif insn == "blx":
		return "indirectjump", args
	else:
		return "unknown", line

