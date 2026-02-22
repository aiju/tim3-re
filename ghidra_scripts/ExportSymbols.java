// Export all non-default symbols from the current program as JSON.
//
// @category Export

import ghidra.app.script.GhidraScript;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import com.google.gson.*;
import java.io.*;

public class ExportSymbols extends GhidraScript {
    @Override
    public void run() throws Exception {
        File outputFile = askFile("Save symbols to", "Save");

        FunctionManager funcMgr = currentProgram.getFunctionManager();
        SymbolTable symTable = currentProgram.getSymbolTable();
        SymbolIterator it = symTable.getAllSymbols(true);

        Gson gson = new Gson();
        PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(outputFile)));
        int count = 0;

        while (it.hasNext()) {
            Symbol sym = it.next();

            if (sym.isExternal()) {
                continue;
            }

            String addr = sym.getAddress().toString();
            String name = sym.getName(true); // include namespace
            SymbolType symType = sym.getSymbolType();

            String kind;
            if (symType == SymbolType.FUNCTION) {
                kind = "FUNC";
            } else if (symType == SymbolType.LABEL) {
                kind = "LABEL";
            } else if (symType == SymbolType.NAMESPACE) {
                kind = "NAMESPACE";
            } else if (symType == SymbolType.CLASS) {
                kind = "CLASS";
            } else if (symType == SymbolType.PARAMETER) {
                kind = "PARAM";
            } else if (symType == SymbolType.LOCAL_VAR) {
                kind = "LOCAL";
            } else {
                kind = symType.toString();
            }

            JsonObject obj = new JsonObject();
            obj.addProperty("address", addr);
            obj.addProperty("type", kind);
            obj.addProperty("name", name);

            if (symType == SymbolType.FUNCTION) {
                Function func = funcMgr.getFunctionAt(sym.getAddress());
                if (func != null) {
                    obj.addProperty("callingConvention", func.getCallingConventionName());
                    obj.addProperty("signature", func.getSignature().getPrototypeString());
                }
            }

            out.println(gson.toJson(obj));
            count++;
        }

        out.close();
        println("Exported " + count + " symbols to " + outputFile.getAbsolutePath());
    }
}
