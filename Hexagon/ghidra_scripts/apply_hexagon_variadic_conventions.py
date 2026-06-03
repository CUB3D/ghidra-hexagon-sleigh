# Apply Hexagon variadic calling conventions and per-call-site overrides.
#
# Phase 1: Set __varargN calling convention + varargs flag on known variadic
#           functions (including thunks and thunked targets).
# Phase 2: For printf/scanf-family, scan each call site, parse format string,
#           apply a per-call-site signature override via the decompiler so
#           extra arguments show up in the decompiled output.
#
# Requires: hexagon.cspec with __vararg1..5 or __hexvar1..5 prototypes
#           (included in ghidra-hexagon-sleigh releases >= 12.0.4).
#
# Run in Ghidra: Script Manager -> Run

# @category Hexagon
# @author ghidra-hexagon-sleigh contributors

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import (
    PointerDataType, CharDataType, IntegerDataType,
    FunctionDefinitionDataType, ParameterDefinitionImpl
)
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp, HighFunctionDBUtil
import re

# --- Configuration ---

# Maps function base name -> number of named (non-variadic) parameters.
VARIADIC_FUNCTIONS = {
    'printf': 1, 'wprintf': 1, 'scanf': 1, 'wscanf': 1,
    'vprintf': 1, 'vwprintf': 1, 'vscanf': 1,
    'err': 1, 'errx': 1, 'warn': 1, 'warnx': 1,

    'fprintf': 2, 'sprintf': 2, 'fscanf': 2, 'sscanf': 2,
    'vfprintf': 2, 'vsprintf': 2, 'vfscanf': 2, 'vsscanf': 2,
    'swprintf': 2, 'syslog': 2, 'dprintf': 2,
    'ioctl': 2, 'fcntl': 2, 'open': 2, 'openat': 2,
    'execl': 2, 'execlp': 2, 'execle': 2,

    'snprintf': 3, 'vsnprintf': 3, 'swscanf': 3,
    'vswprintf': 3, 'vdprintf': 3, 'semctl': 3, 'msgctl': 3,

    'syscall': 4,
}

# Functions whose call sites can be resolved via format-string parsing.
# Value = 0-based index of the format string parameter.
FORMAT_STRING_FUNCTIONS = {
    'printf': 0, 'wprintf': 0, 'scanf': 0, 'wscanf': 0,
    'fprintf': 1, 'sprintf': 1, 'fscanf': 1, 'sscanf': 1,
    'swprintf': 1, 'snprintf': 2, 'swscanf': 2,
    'syslog': 1, 'dprintf': 1,
}

# Matches printf/scanf format specifiers, excluding literal %%.
FORMAT_SPEC_RE = re.compile(
    r'%'
    r'[-+ #0]*'
    r'(?:\*|\d*)'
    r'(?:\.(?:\*|\d*))?'
    r'(?:hh|h|ll|l|L|z|j|t)?'
    r'([diouxXeEfFgGaAcspn%])'
)


def get_clean_name(name):
    """Strip common thunk/underscore prefixes to find base function name."""
    n = name.lower()
    for prefix in ('thunk_', '__', '_'):
        if n.startswith(prefix):
            n = n[len(prefix):]
    return n


def resolve_thunk_chain(func):
    """Return list of [func, ...thunked targets] following the thunk chain."""
    result = [func]
    seen = set([func.getEntryPoint()])
    current = func
    while current.isThunk():
        target = current.getThunkedFunction(False)
        if target is None:
            break
        ep = target.getEntryPoint()
        if ep in seen:
            break
        seen.add(ep)
        result.append(target)
        current = target
    return result


def count_format_args(fmt_string):
    """Count variadic arguments implied by format specifiers."""
    count = 0
    for m in FORMAT_SPEC_RE.finditer(fmt_string):
        if m.group(1) == '%':
            continue
        count += 1
        count += m.group(0).count('*')
    return count


def parse_format_specifiers(fmt_string):
    """Return list of specifier chars for type mapping (excluding %%)."""
    specs = []
    for m in FORMAT_SPEC_RE.finditer(fmt_string):
        conv = m.group(1)
        if conv == '%':
            continue
        spec = m.group(0)
        for _ in range(spec.count('*')):
            specs.append('d')
        specs.append(conv)
    return specs


def read_string_at(addr):
    """Read null-terminated ASCII string from program memory."""
    if addr is None:
        return None
    mem = currentProgram.getMemory()
    result = []
    try:
        for i in range(512):
            b = mem.getByte(addr.add(i))
            if b == 0:
                break
            result.append(chr(b & 0xFF))
    except:
        return None
    if not result:
        return None
    return ''.join(result)


def get_format_string_from_callsite(call_addr, func_name):
    """Find the most likely format string near a call site."""
    clean = get_clean_name(func_name)
    if clean not in FORMAT_STRING_FUNCTIONS:
        return None

    listing = currentProgram.getListing()
    inst = listing.getInstructionAt(call_addr)
    if inst is None:
        inst = listing.getInstructionContaining(call_addr)
    if inst is None:
        return None

    # Scan backward for data references to strings containing '%'.
    # On Hexagon VLIW, the format address is loaded within ~30 instructions.
    candidates = []
    search_inst = inst
    for _ in range(30):
        if search_inst is None:
            break
        for ref in search_inst.getReferencesFrom():
            s = read_string_at(ref.getToAddress())
            if s and '%' in s:
                candidates.append(s)
        search_inst = search_inst.getPrevious()

    if not candidates:
        return None

    best = max(candidates, key=lambda s: len(FORMAT_SPEC_RE.findall(s)))
    if FORMAT_SPEC_RE.search(best):
        return best
    return None


def get_type_for_specifier(spec_char):
    """Map a printf conversion character to a Ghidra DataType."""
    if spec_char in ('s', 'p', 'n'):
        return PointerDataType(CharDataType.dataType)
    return IntegerDataType.dataType


def build_override_funcdef(target_func, fmt_string):
    """Build a FunctionDefinitionDataType with extra varargs resolved."""
    specs = parse_format_specifiers(fmt_string)
    if not specs:
        return None

    func_def = FunctionDefinitionDataType(target_func, False)
    new_args = list(func_def.getArguments())

    for i, spec in enumerate(specs):
        dt = get_type_for_specifier(spec)
        new_args.append(ParameterDefinitionImpl("vararg_{}".format(i), dt, None))

    func_def.setArguments(new_args)
    return func_def


# ============================================================
# Phase 1: Set calling conventions
# ============================================================

def phase1_set_conventions():
    """Set __varargN calling convention + varargs flag on known functions."""
    fm = currentProgram.getFunctionManager()
    compiler_spec = currentProgram.getCompilerSpec()

    cc_cache = {}
    for prefix in ('__vararg', '__hexvar'):
        for i in range(1, 6):
            cc_name = '{}{}'.format(prefix, i)
            try:
                cc = compiler_spec.getCallingConvention(cc_name)
                if cc is not None and i not in cc_cache:
                    cc_cache[i] = cc_name
            except:
                pass

    if not cc_cache:
        popup("ERROR: No variadic calling conventions found in hexagon.cspec.\n"
              "Expected __varargN or __hexvarN (N=1..5).\n"
              "Install the Hexagon extension release with variadic prototypes.")
        return None

    print("[Phase1] Available conventions: {}".format(cc_cache))

    count = 0
    skipped = 0
    already = 0
    all_targets = []
    seen_entries = set()

    for func in fm.getFunctions(True):
        name = func.getName()
        clean = get_clean_name(name)

        if clean not in VARIADIC_FUNCTIONS:
            continue
        if func.getEntryPoint() in seen_entries:
            continue
        seen_entries.add(func.getEntryPoint())

        n_named = VARIADIC_FUNCTIONS[clean]
        if n_named not in cc_cache:
            skipped += 1
            continue

        cc_name = cc_cache[n_named]
        chain = resolve_thunk_chain(func)
        func_changed = False

        for f in chain:
            f_changed = False
            if f.getCallingConventionName() != cc_name:
                try:
                    f.setCallingConvention(cc_name)
                    f_changed = True
                except Exception as e:
                    print("[Phase1] ERR {} @ {}: {}".format(
                        f.getName(), f.getEntryPoint(), e))

            if not f.hasVarArgs():
                f.setVarArgs(True)
                f_changed = True

            if f_changed:
                func_changed = True
                print("[Phase1] SET {} @ {} : cc={}, varargs=True{}".format(
                    f.getName(), f.getEntryPoint(), cc_name,
                    " (thunk)" if f.isThunk() else ""))

        if func_changed:
            count += 1
        else:
            already += 1

        all_targets.append((func, clean))

    print("[Phase1] Done: {} changed, {} already correct, {} skipped.".format(
        count, already, skipped))
    return all_targets


# ============================================================
# Phase 2: Per-call-site override via decompiler
# ============================================================

def phase2_override_callsites(targets):
    """Override call-site signatures by parsing format strings."""
    ref_mgr = currentProgram.getReferenceManager()
    listing = currentProgram.getListing()

    decomp = DecompInterface()
    decomp.openProgram(currentProgram)

    override_count = 0
    skip_count = 0
    error_count = 0
    no_fmt_count = 0

    # Group call sites by caller to decompile each caller only once.
    # Dedup by call_addr to avoid double-processing via thunk chains.
    caller_map = {}
    seen_calls = set()

    for func, clean in targets:
        if clean not in FORMAT_STRING_FUNCTIONS:
            continue

        chain = resolve_thunk_chain(func)
        all_entries = set(f.getEntryPoint() for f in chain)
        real_func = chain[-1]

        for entry in all_entries:
            for ref in ref_mgr.getReferencesTo(entry):
                if not ref.getReferenceType().isCall():
                    continue
                call_addr = ref.getFromAddress()
                if call_addr in seen_calls:
                    continue
                seen_calls.add(call_addr)
                caller_func = listing.getFunctionContaining(call_addr)
                if caller_func is None:
                    continue
                caller_entry = caller_func.getEntryPoint()
                if caller_entry not in caller_map:
                    caller_map[caller_entry] = []
                caller_map[caller_entry].append((call_addr, real_func, clean))

    print("[Phase2] {} unique caller functions to process.".format(len(caller_map)))

    processed = 0
    for caller_entry, call_sites in caller_map.items():
        caller_func = listing.getFunctionAt(caller_entry)
        if caller_func is None:
            continue

        try:
            result = decomp.decompileFunction(caller_func, 60, getMonitor())
            if result is None or not result.decompileCompleted():
                error_count += len(call_sites)
                continue
            hf = result.getHighFunction()
            if hf is None:
                error_count += len(call_sites)
                continue
        except:
            error_count += len(call_sites)
            continue

        processed += 1
        if processed % 50 == 0:
            print("[Phase2] Progress: {} / {} callers...".format(
                processed, len(caller_map)))

        for (call_addr, target_func, clean_name) in call_sites:
            fmt = get_format_string_from_callsite(call_addr, target_func.getName())
            if fmt is None:
                no_fmt_count += 1
                continue

            arg_count = count_format_args(fmt)
            if arg_count == 0:
                skip_count += 1
                continue

            func_def = build_override_funcdef(target_func, fmt)
            if func_def is None:
                skip_count += 1
                continue

            # Find the CALL PcodeOp at or near call_addr.
            # Hexagon VLIW packets can be up to 16 bytes; the reference
            # address may not match where the decompiler placed the CALL op.
            call_op = None
            for offset in range(-16, 20, 4):
                ops_iter = hf.getPcodeOps(call_addr.add(offset))
                while ops_iter.hasNext():
                    op = ops_iter.next()
                    opcode = op.getOpcode()
                    if opcode == PcodeOp.CALL or opcode == PcodeOp.CALLIND:
                        call_op = op
                        break
                if call_op is not None:
                    break

            if call_op is None:
                error_count += 1
                print("[Phase2] NO CALL OP {} @ {}".format(
                    target_func.getName(), call_addr))
                continue

            try:
                override_addr = call_op.getSeqnum().getTarget()
                HighFunctionDBUtil.writeOverride(
                    caller_func, override_addr, func_def)
                override_count += 1
                print("[Phase2] OK {} @ {} : \"{}\" -> +{} args".format(
                    target_func.getName(), call_addr,
                    fmt[:50].replace('\n', '\\n'), arg_count))
            except Exception as e:
                error_count += 1
                print("[Phase2] ERR {} @ {}: {}".format(
                    target_func.getName(), call_addr, e))

    decomp.dispose()
    print("[Phase2] Done: {} overridden, {} skipped, {} no format, {} errors.".format(
        override_count, skip_count, no_fmt_count, error_count))


# ============================================================

def main():
    print("=" * 60)
    print("Hexagon Variadic Convention Applier")
    print("=" * 60)

    targets = phase1_set_conventions()
    if targets is None:
        return
    if not targets:
        print("No variadic functions found in program.")
        return

    print("")
    print("--- Phase 2: Call-site signature overrides ---")
    phase2_override_callsites(targets)
    print("")
    print("Done.")

main()
