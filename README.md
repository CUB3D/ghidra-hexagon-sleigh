### Ghidra Hexagon SLEIGH

This is an implementation of the Qualcomm Hexagon "QDSP6" architecture in Ghidra SLEIGH


Supports:
- Dissassembly of v66/v67/v68/v73/v75/v79, all instructions supported
- Most commonly used constant extenders supported
- No broken java plugins needed
- Support for hardware loops (The first implementation to do so)
- Includes support for redacted System/Monitor and System/Guest instructions
- Pcode implemented for most ops, (Only a few never-seen MPY and NV instructions are missing)
- Function start recovery
- Q6ZIP and DELTA/DLPAGER decompression via emulation, see scripts

Currently broken / unimplemented:
- Some immediate extensions are missing for less common ops and most duplexes

(See notes at top of `Hexagon/data/languages/Hexagon.slaspec`) for up to date details:

### How to install
Grab the latest release from [releases](https://github.com/CUB3D/ghidra-hexagon-sleigh/releases)

File -> Install Extensions -> Green plus -> Downloaded Zip
