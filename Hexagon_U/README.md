## Ghidra Hexagon SLEIGH

This is a WIP implementation of the Qualcomm Hexagon "QDSP6" architecture in Ghidra SLEIGH

Features:
- Dissassembly of v66/v67/v68/v73/v75/v79/v81/v83/v85, including HVX v85 and HMX v81
- Most common extended immediates are supported
- No broken java plugins needed
- Support for hardware loops (The first implementation to do so)
- Includes support for redacted System/Monitor and System/Guest instructions
- Pcode implemented for most ops, (Only a few never-seen MPY and NV instructions are missing)
- Function start recovery
- Support for auto-and predicates
- Full undocumented HMX dissassembly
- Builtin scripts:
- - Q6ZIP and DELTA/DLPAGER decompression via emulation
- - Annotation of hashed log messages

Modern (12.1+) versions of Ghidra support Hexagon nativly, this plugin predates that. However, it has some advantages and some disadvantages compared to that plugin: see [this comment](https://github.com/CUB3D/ghidra-hexagon-sleigh/issues/49#issuecomment-4652321293) for details.

Currently broken / unimplemented:
- Some immediate extensions are missing for less common ops and some duplexes

### Includes scripts to help analysis of Qualcomm binaries:
- apply_hexagon_variadic_conventions -> Applies Qualcomm specific vararg calling convention overrides
- dlpager_emu -> Emulation based decompression of Delta/DLPager compression
- hexagon_emu -> Generic Hexagon emulation base
- mark_clade_tlvs -> Annotate TLVs defining CLADE properties
- mark_qcom_rtti -> Annotate c++ classes based on `typeid` and `dynamic_cast` metadata
- mark_qdb_logs -> Annotate hashed log strings
- mark_qurt_tasks -> Discover and find QuRT task structs
- mark_known_diag -> Find and annotate known Diag (`/dev/diag`) handler tables
- q6zip_emu -> Emulation based decompression of Q6Zip compressed code
- qcom_logs -> Annotate struct-based logs
- mark_qmi_handlers -> Find and annotate QMI message handler tables

### QDB Viewer
Adds a new window to the GUI that allows loading QDB files, decoding hashed log messages and finding thair usages.

### Configurable decompilation
There are flags to configure the behaviour of the generated pcode to either improve accuracy or quality of decompilation, (Select an address range and `Ctrl+R` to configure):

#### pedantic_pcode
Enables more accurate pcode at the cost of much worse decompilation. Changes include:
- Shifts support bi-directional operation

#### accurate_pred
Enable accurate emulation of predicate registers. Useful if the code uses vectorized comparisons or if you want to emulate the code. By default we use the values `0` and `1` for False and True for scalar comparisons. Hexagon typically uses `0` and `FF` but this produces bad decompilation in Ghidra due to an outstanding [decompiler bug](https://github.com/NationalSecurityAgency/ghidra/issues/9284)

- 0 (Default) -> Use innacurate predicate values
- 1 -> Use accurate predicate values

#### inline_data
Some compiler flags cause the compiler to store immediate values directly in the program text. Jumping to a function that reads the value at the address `LR` and returning past it. This breaks Ghidra's ability to fully disassemble functions or decompile them. This flag allows marking a value as an `inline data` instruction that will allow the disassembler to keep going.

- 0 (Default) -> do nothing
- 1 -> This instruction should be a `inline data`

Ghidra 12.0+ is recommended due to the fix for the "Overlapping Input Varnodes" error when functions take wide register inputs also affecting Hexagon 64-bit register pairs (GP-5863)

See notes at top of `Hexagon/data/languages/hexagon.slaspec` for additional details

### How to install
Grab the latest release from [releases](https://github.com/CUB3D/ghidra-hexagon-sleigh/releases/latest) for your Ghidra version (11.4.1 -> latest)

In Ghidra:
File -> Install Extensions -> Green plus -> Downloaded Zip. Then restart Ghidra
