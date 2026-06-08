all:
	~/Qualcomm/Hexagon_SDK/3.3.3/tools/HEXAGON_Tools/8.1.05/Tools/bin/hexagon-clang -Wall -target hexagon -g -c test.c -o test.o
	~/Qualcomm/Hexagon_SDK/3.3.3/tools/HEXAGON_Tools/8.1.05/Tools/bin/hexagon-clang -Wall -target hexagon -g -c test.c -o test_o1.o -O1
	~/Qualcomm/Hexagon_SDK/3.3.3/tools/HEXAGON_Tools/8.1.05/Tools/bin/hexagon-clang -Wall -target hexagon -g -c test.c -o test_o2.o -O2
	~/Qualcomm/Hexagon_SDK/3.3.3/tools/HEXAGON_Tools/8.1.05/Tools/bin/hexagon-clang -Wall -target hexagon -g -c test.c -o test_o3.o -O3
	~/Qualcomm/Hexagon_SDK/3.3.3/tools/HEXAGON_Tools/8.1.05/Tools/bin/hexagon-clang -Wall -target hexagon -g -c test.c -o test_o3.elf -static -O3
