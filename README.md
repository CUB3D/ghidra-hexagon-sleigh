### Ghidra Hexagon SLEIGH

This is an implementation of the Qualcomm Hexagon "QDSP6" architecture in Ghidra SLEIGH


Features:
- Disassembly of v66 through v81 (scalar + HVX); pcode semantics complete through v73, with the v79/v81 HVX FP8 / qf16 / qf32 / vcmp.eq families and the v81 Y2_tlbpp decoded as stubs
- Most commonly used constant extenders supported
- No broken java plugins needed
- Support for hardware loops (The first implementation to do so)
- Includes support for redacted System/Monitor and System/Guest instructions
- Pcode implemented for most ops, (Only a few never-seen MPY and NV instructions are missing)
- Function start recovery
- Builtin scripts: 
- - Q6ZIP and DELTA/DLPAGER decompression via emulation
- - Annotation of hashed log messages

Currently broken / unimplemented:
- Some immediate extensions are missing for less common ops and duplexes

(See notes at top of `Hexagon/data/languages/Hexagon.slaspec`) for up to date details:

Ghidra 12.0+ is recommended due to the fix for the "Overlapping Input Varnodes" error when functions take wide register inputs also affecting Hexagon 64-bit register pairs (GP-5863)

### How to install
Grab the latest release from [releases](https://github.com/CUB3D/ghidra-hexagon-sleigh/releases)

In Ghidra:
File -> Install Extensions -> Green plus -> Downloaded Zip
