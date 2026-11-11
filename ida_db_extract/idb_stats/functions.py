import idautils
import ida_funcs
import ida_typeinf
import ida_nalt
import ida_name

def get_binary_functions_and_prototypes():
    results = []

    # 1. Iterate over the starting address (ea) of every function in the binary
    for ea in idautils.Functions():
        
        # Get the actual function name
        func_name = ida_name.get_name(ea)
        
        # 2. Create an empty tinfo_t object to hold our type data
        tinfo = ida_typeinf.tinfo_t()
        
        # 3. Retrieve the type info assigned to this specific address
        # get_tinfo returns True if the address has a recognized type signature
        if ida_nalt.get_tinfo(tinfo, ea):
            
            # 4. Verify that the type at this address is actually a function
            if tinfo.is_func():
                
                # 5. Extract detailed components of the function
                func_details = ida_typeinf.func_type_data_t()
                tinfo.get_func_details(func_details)
                
                # Get the return type as a string
                ret_type = str(func_details.rettype)
                
                # Loop through the arguments
                args = []
                for i in range(func_details.size()):
                    arg = func_details[i]
                    # Sometimes arguments don't have names, so we provide a fallback
                    arg_name = arg.name if arg.name else f"a{i+1}"
                    arg_type = str(arg.type)
                    args.append(f"{arg_type} {arg_name}")
                
                results.append({
                    "address": ea,
                    "name": func_name,
                    # str(tinfo) generates the complete C-style prototype!
                    "full_prototype": str(tinfo), 
                    "return_type": ret_type,
                    "arguments": args
                })

    return results

def get_all_function_names():
    """Iterates through all functions in the IDB and prints their names and addresses."""
    functions = []
    
    func_count = ida_funcs.get_func_qty()
    
    for i in range(func_count):
        pfn = ida_funcs.getn_func(i)
        if not pfn:
            continue
            
        func_ea = pfn.start_ea
        func_name = ida_name.get_name(func_ea)
        
        if not func_name:
            func_name = f"sub_{func_ea:X}"
        
        functions.append(f"0x{func_ea:X} : {func_name}")
    return functions