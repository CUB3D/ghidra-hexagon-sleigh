/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package hexagon;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;

/**
 * 
 * This class handles dynamic pcode injection for modeling JVM bytecode.
 * 
 * There are some notable differences between a java .class file and an executable compiled for
 * a physical processor, which present some complications when modeling bytecode with pcode.
 * Some of the bigger differences are:
 *   1) The java compiler does not know the runtime layout of a class - that's up to the JVM implementer
 *      to decide.  Methods and fields of a class are accessed by name in a .class file - there are no
 *      vtables or field offsets in bytecode.  
 *   2) Each method gets its own area in memory called a method stack.  It is not assumed to be contiguous
 *      with other method stacks.  There is no concept of the address of a method. 
 *   3) Parameters are passed to a method on the operand stack in left to right order (first parameter pushed first).
 *      However, within a method body, parameters to that method are not read from the operand stack.  Instead,
 *      they are read from an area known as the "local variable array".  
 *   4) Many bytecode operations reference the constant pool.  For example, some of the bytes of an invoke 
 *      instruction encode an index in the constant pool.  By reading data at that index, you can determine
 *      the signature, name, and class of the method to be invoked.  
 *   5) In some instances, you must consult the constant pool to determine how an instruction changes the
 *      the stack.  For instance, a getfield operation can push either 4 or 8 bytes on to the stack, 
 *      depending on the "computational category" of the field (object references, integers, and floats are 
 *      4 bytes, longs and doubles are 8).  You cannot determine the computational category from the bytes 
 *      of the instruction, you must examine the element at the encoded index into the constant pool. 
 * 
 * The file JVM.slaspec contains definitions of fake registers which are not part of the JVM specification
 * but are necessary to model class files in pcode.  These registers include return_value, cat2_return_value,
 * switch_target, return_address
 * 
 * defined pcodeop naming schemes:
 *   ops ending in "CallOther" are used for pcode injection
 *   ops ending in "Op" are used as black-box ops.  
 * 
 * How to implement pcode injection for an operation "testop":
 * JVM.pspec:
 *   ensure that the processor spec properties includes:
 *      <property key="pcodeInjectLibraryClass" value="ghidra.app.util.pcodeInject.PcodeInjectLibraryJava"/>
 *   (this property needs to be there for injection to work.  It's included as a step here for
 *    general pcode injection documentation.  In the general case, modify the value as appropriate.)
 * JVM.slaspec: 
 *   define a new pcodeop testopCallOther
 *   define a new pcodeop testopOp, if necessary (if you need a black-box operation to model testop) 
 *   in the pcode for testop, emit a call to testopCallOther.
 * JVM.cspec:
 *   define a callotherfixup targetop "testopCallOther" - see the other callotherfixups
 * PcodeInectLibrary.java:
 *   define a constant string "testopCallOther"
 *   in the constructor for this class, add the newly-defined string to the set implementedOps 
 *   add a case statement restorePcodeXml
 * Create a subclass of InjectPayloadJava to generate/compile pcode
 *   (Use/add to PcodeTextEmitter.java to actually emit pcode text)
 * See ConstantPoolJava.java for examples of the use of the CPOOL pcode op.
 * 
  * possible improvements:
 *
 *   2) incorporate exceptions.
 *   6) decide how to display the information used in an invokedynamic instruction
 *   7) jsr/ret instructions are not modeled using pcode injection.  The jsr (jump to subroutine) 
 *      instruction is deprecated and can't appear in class files with version >= 51.0.  This is a 
 *      strange instruction which pushes the address of the following instruction onto the operand
 *      stack and then jumps to a subroutine.  The subroutine ends with a ret instruction, which
 *      retrieves the address from a local variable (not from the stack).  The JVM handles moving
 *      the address from the stack to the local variable.  In order to model this, you would need
 *      to determine which ret instruction is paired with a jsr instruction and inject pcode to move
 *      the address into the local variable that the ret instruction reads from.  You will need to
 *      follow flow from the beginning of the subroutine the corresponding ret instruction(s?).
 *     
 */

public class HexagonPcodeInjector extends PcodeInjectLibrary {
	
	public InjectLdc ldc;
	public InjectLdc ldc1;


	public HexagonPcodeInjector(SleighLanguage l) {
		super(l);
		System.out.println("HexagonPcodeInj::ctor");
		this.ldc = new InjectLdc("testCallOther", l, this.uniqueBase, 0);
		this.ldc1 = new InjectLdc("testCallOther", l, this.uniqueBase, 1);

		this.uniqueBase += 0x100;	
	}

	public HexagonPcodeInjector(HexagonPcodeInjector op2) {
		super(op2);
		System.out.println("HexagonPcodeInj::ctor2");
		this.ldc = op2.ldc;
		this.ldc1 = op2.ldc1;
	}

	@Override
	public PcodeInjectLibrary clone() {
		System.out.println("HexagonPcodeInj::clone");

		return new HexagonPcodeInjector(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		System.out.println("sn="+sourceName+", n="+name+", tp="+tp);
		
		if (tp == InjectPayload.CALLOTHERFIXUP_TYPE) {
			System.out.println("COF");

			if(name.equalsIgnoreCase("testCallOther")) {
				System.out.println("Use ldc");

				return this.ldc;
			}
			if(name.equalsIgnoreCase("testCallOther1")) {
				System.out.println("Use ldc1");

				return this.ldc1;
			}
		}
		return super.allocateInject(sourceName, name, tp);
	}

}
