# Annotate Qualcomm QDB hashed log strings
#@author CUB3D
#@category Qualcomm
#@runtime Jython

# There are two forms of log message seen so far
# 1 - Logs are a hash starting 0xf2 / 0xf3 / 0xf8 and are passed in a reg / constant into the log function
# 2 - Logs are in the program text, with a call to a log func, that func reads the log id from LR and returns to LR+4, this seems to be 0xf8 hashes in some firmwares
# 
# Before using this you will need to:
# - find the inline log function and rename it to `inline_log`
# - find the classic log function and rename it to `msg_v4_send_.*`, there will be multiple versions that take a different number of args
# * These will likely be some of the most referenced functions in the binary
# For the logs that take a struct argument with a pointer to the file and log msg / hash, you need to use the other qcom_logs script

import ghidra.app.decompiler.DecompInterface as DecompInterface
import ghidra.app.decompiler.ClangTokenGroup as ClangTokenGroup
import ghidra.app.decompiler.ClangStatement as ClangStatement
import ghidra.app.decompiler.ClangFuncNameToken as ClangFuncNameToken
import ghidra.app.decompiler.ClangVariableToken as ClangVariableToken
import ghidra.program.model.data.Pointer as Pointer
import json
import zlib
from collections import namedtuple


QdbEntry = namedtuple("QdbEntry", ["line", "file", "string"])

# Reduce logging for more speed
QUIET = True

# Write out a file with the logs that have none-number args e.g. registers
SAVE_NON_NUMBER = False

# For debugging
SAVE_DECOMPRESSED_QDB = False

# Timeout for function decompilation, in seconds
TIMEOUT = 1

def parse_qdb(path):
	"""
	Parse a QDB file
	"""
	with open(path, "rb") as f:
		data = f.read()
	compressed = data[64:]
	decompressed = zlib.decompress(compressed)
	
	if SAVE_DECOMPRESSED_QDB:
		with open("/tmp/decomp.qdb", "wb") as f:
			f.write(decompressed)
	decompressed = decompressed.decode("utf-8")
			

	lines = decompressed.split("\n")
	hashes = {}
	for idx,line in enumerate(lines):
		# end of hashes, start of MTraceContent and QtraceStrContent
		if line.strip() == "<\Content>":
			break
			
		if line.count(":") < 5 or line[0] == '#':
			continue
		parts = line.split(":")
		line_num = int(parts[3])
		file_name = parts[4]
		string = ":".join(parts[5:])

		hashes[int(parts[0])] = QdbEntry(line_num, file_name, string)
	return hashes

def get_functions():
	"""
	Get all the funcs in the binary
	"""
	return [f for f in currentProgram.getFunctionManager().getFunctions(True)]

def process_clang_token_group(ctg, results=[]):
	if ctg is None:
		return results
	tokens = (ctg.Child(i) for i in range(ctg.numChildren()))
	for token in tokens:
		# The body of a function is a token group as well as a statement is a token group
		if type(token) == ClangTokenGroup:
			results = process_clang_token_group(token, results=results)
		elif type(token) == ClangStatement:
			elements = (token.Child(i) for i in range(token.numChildren()))
			index = 0
			isFunc = False
			# Elements withing a statement, like a function call
			for element in elements:
				if type(element) == ClangFuncNameToken:
					# print('Function: {0}'.format(element))
					isFunc = True
					results.append({
							'address': str(element.getMinAddress()),
							'name': str(element),
							'params': []
					})
				elif type(element) == ClangVariableToken:
					# If we started in a function, continue processing parameters
					if isFunc:
						index += 1
						value = str(element)
						param = {'value': value,
								 'address': str(element.getMinAddress())}
						results[-1]['params'].append(param)
		else:
			pass
	return results

def log_msg_lookup(msg_id):
	kind = (msg_id >> 24) & 0xFF
	msg_idx = msg_id & 0xFFFFF
	if kind == 0xf3:
		msg_idx = (msg_idx >>4)
	elif kind == 0xf2:
		msg_idx = (msg_idx >>4) | (1<<14)
	elif kind == 0xf8:
		msg_idx = (msg_id & 0xFFFFFF) >> 3

	if msg_idx in HASHES:
		return HASHES[msg_idx]
	else:
		print("Failed to find ent for", hex(msg_id))
		return None

def process_code(di, func):
	global TOTAL
	global FAIL
	global SUCC
	global NOT_A_NUMBER
	global DONE

	dr = di.decompileFunction(func, TIMEOUT, monitor)
	df = dr.getDecompiledFunction()

	r = process_clang_token_group(dr.getCCodeMarkup())
	for p in r:
		if p["address"] in DONE:
			continue
		DONE.add(p["address"])
		if "msg_v4_send_" in p["name"] or p["name"] == "inline_log":
			TOTAL += 1
			# Address of the call instruction
			address_addr = toAddr(p["address"])

			# If this is an inline log
			if p["name"] == "inline_log":
				# Get the int located at the LR of this packet
				call_instruction = getInstructionAt(address_addr)
				if call_instruction is None:
					print("Failed to find instruction @ ", address_addr)
					continue
				msg_id = getLong(address_addr.add(call_instruction.getParsedLength())) & 0xFFFFFFFF

				msg = log_msg_lookup(msg_id)
				if msg is None:
					FAIL += 1
					print "Can't annotate", address_addr, "Can't find msg for id=", hex(msg_id)
					continue

				msg_fmt = msg.file + ":" + str(msg.line) + " | " + msg.string
				setPreComment(address_addr, msg_fmt)
				print "Annotated:", toAddr(p["address"])
				SUCC += 1
			else:
				prev_cmt = getPreComment(address_addr)
				if prev_cmt is not None and len(prev_cmt) != 0:
					if not QUIET:
						print "Cowerdly refusing to annotate", address_addr, "it already has a comment"
					continue

				params = p["params"]
				if len(params) < 1:
					FAIL += 1
					print "Can't annotate", address_addr, "decompiler didn't find params"
					continue

				arg0 = params[0]["value"]

				if arg0[:2] == "0x":
					msg_id = int(arg0, 16)
				else:
					FAIL += 1
					NOT_A_NUMBER += [p["address"]]
					print "Can't annotate", address_addr, "arg isn't a number (probably a var)"
					continue

				msg = log_msg_lookup(msg_id)
				if msg is None:
					FAIL += 1
					print "Can't annotate", address_addr, "Can't find msg for id=", hex(msg_id), "arg0=",arg0
					continue

				msg_fmt = msg.file + ":" + str(msg.line) + " | " + msg.string
				setPreComment(address_addr, msg_fmt)
				print "Annotated:", toAddr(p["address"])
				SUCC += 1


SUCC = 0
FAIL = 0
TOTAL = 0
NOT_A_NUMBER = []
DONE = set()


f = askFile("Select QDB file", "Load")
HASHES = parse_qdb(f.getPath())


print "Load decompiler"
di = DecompInterface()
di.openProgram(currentProgram)
print "Get functions"
funcs = get_functions()
print "Annotate functions"
num_funcs = len(funcs)
monitor.initialize(num_funcs, "Annotating log entries")
for f in funcs:
	monitor.incrementProgress()
	try:
		process_code(di, f)
	except Exception as e:
		print "Failed to process", f.getName(), "e=", e


if SAVE_NON_NUMBER:
	print "Save not number"
	with open("~/not_a_number.txt", "w") as f:
		for x in NOT_A_NUMBER:
			f.write(x + "\n")
	

print "Annotated ", SUCC, "/", TOTAL, "calls successfully, Failed to annotate ", FAIL, "/", TOTAL
