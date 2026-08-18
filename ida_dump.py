import idaapi
import idautils
import ida_hexrays
import ida_auto
import ida_pro
def dump_c_code():
    ida_auto.auto_wait()
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(current_dir, "vuln_c_code.txt")
    
    with open(output_path, "w", encoding="utf-8") as f:
        for ea in idautils.Functions():
            func_name = idaapi.get_func_name(ea)
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    f.write(f"// ========== Function: {func_name} ==========\n")
                    f.write(str(cfunc) + "\n\n")
            except Exception as e:
                    pass 

    ida_pro.qexit(0)

if __name__ == '__main__':
    dump_c_code()