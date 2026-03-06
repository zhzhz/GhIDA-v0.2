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
// Given a variable in the decompiler, walk backward through function calls to find any constants
//   that find their way directly into the variable.  Very useful for getting a list of all the
//   constants passed to a parameter, or to a parameter at a given location in the program.
//
//   The guts of this script past the main could be used to analyze
//   constants passed to any function on any processor.
//   It is not restricted to windows.
//
//@category Search

import java.util.*;

import generic.jar.ResourceFile;
import ghidra.app.decompiler.*;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.script.*;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;

public class FunctionDecompile extends GhidraScript {
	private DecompInterface decompInterface;
	DecompileResults decompileResults = null;
	TableChooserDialog tableDialog;
  private Address addr;

	@Override
	public void run() throws Exception {
		try {

      String[] args = getScriptArgs();

      String addr = args[0];

      long address = Long.parseLong(addr, 16);

			decompInterface = setUpDecompiler(currentProgram);


        FunctionManager functionManager = currentProgram.getFunctionManager();

        FunctionIterator functionIterator = functionManager.getFunctions(true);

        
        while (functionIterator.hasNext()) {
          Function function = functionIterator.next();

          if (function.getEntryPoint().getOffset() == address) {
            decompileResults = decompInterface.decompileFunction(
              function, 30, monitor);
            break;
          }
        }
        
        
          Map<String, String> response_dict = new HashMap<>();

          if (decompileResults.decompileCompleted())
          {
              DecompiledFunction decompiledFunction = decompileResults.getDecompiledFunction();
              String decompiled = decompiledFunction.getC();
              response_dict.put("status", "completed");
              response_dict.put("decompiled", decompiled);
          }
          else
          {
              response_dict.put("status", "error");
          }
              
          // println("haha----------------------");
          // println(response_dict.get("decompiled"));

          //write dict to file
          String output_path = args[1];
          try (java.io.FileWriter file = new java.io.FileWriter(output_path)) {
              file.write(response_dict.get("decompiled"));
          } catch (java.io.IOException e) {
              e.printStackTrace();
          }



		}
		finally {
			decompInterface.dispose();
      
		}
	}

  private DecompInterface setUpDecompiler(Program program) {

		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(currentProgram)) {
			println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options = DecompilerUtils.getDecompileOptions(state.getTool(), program);

		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}
}
