import sys
import tkinter as tk
from tkinter import filedialog, messagebox

# Opcode Mappings (5-bit)
OPCODES = {
    "ADD": "00000", "SUB": "00001", "MUL": "00010", "DIV": "00011",
    "MOD": "00100", "CMP": "00101", "AND": "00110", "OR": "00111",
    "NOT": "01000", "MOV": "01001", "MOVU": "01001", "MOVH": "01001", 
    "LSL": "01010", "LSR": "01011", "ASR": "01100", "NOP": "01101", 
    "LD": "01110", "ST": "01111", "BEQ": "10000", "BGT": "10001", 
    "B": "10010", "CALL": "10011", "RET": "10100", "END": "11111", 
    "HLT": "11111"
}

# Register Mappings (4-bit)
REGISTERS = {
    "R0": "0000", "R1": "0001", "R2": "0010", "R3": "0011",
    "R4": "0100", "R5": "0101", "R6": "0110", "R7": "0111",
    "R8": "1000", "R9": "1001", "R10": "1010", "R11": "1011",
    "R12": "1100", "R13": "1101", "R14": "1110", "R15": "1111"
}

symbol_table = {}  # Stores label addresses
last_cmp = None

def first_pass(lines):
    """Record label addresses."""
    pc = 0
    for line in lines:
        stripped = line.strip().split("#")[0]  # Remove comments
        if not stripped:
            continue
        if ":" in stripped:
            label, rest = stripped.split(":", 1)
            symbol_table[label.strip()] = pc
            if rest.strip():  # If there's an instruction after the label
                pc += 1
        else:
            pc += 1

def format_binary(opcode, i, rd, rs1, rs2, imm):
    if imm is not None:
        imm_bin = format(int(imm) & 0x3FFFF, '018b')
        return f"{opcode}{i}{rd}{rs1}{imm_bin}"
    else:
        return f"{opcode}{i}{rd}{rs1}{rs2}{'0'*14}"

def assemble_instruction(line, pc):
    global last_cmp
    parts = line.replace(",", "").split()
    if not parts:
        return None
    if parts[0].endswith(":"):
        parts.pop(0)
        if not parts:
            return None  
    inst = parts[0]
    if inst not in OPCODES:
        raise ValueError(f"Unknown instruction: {inst}")
    opcode = OPCODES[inst]

    if inst in ["ADD", "SUB", "MUL", "DIV", "LSL", "LSR", "ASR", "AND", "OR", "MOD"]:
        if len(parts) == 4 and parts[3].lstrip('-').isdigit():
            rd, rs1 = REGISTERS.get(parts[1].upper()), REGISTERS.get(parts[2].upper())
            imm = int(parts[3]) & 0x3FFFF
            return format_binary(opcode, "1", rd, rs1, "0000", imm)
        elif len(parts) == 4:
            rd, rs1, rs2 = REGISTERS.get(parts[1].upper()), REGISTERS.get(parts[2].upper()), REGISTERS.get(parts[3].upper())
            return format_binary(opcode, "0", rd, rs1, rs2, None)

    elif inst == "CMP":
        if len(parts) == 3 and parts[2].lstrip('-').isdigit():
            rs1 = REGISTERS.get(parts[1].upper())
            imm = int(parts[2]) & 0x3FFFF
            last_cmp = (rs1, str(imm))  # Ensure last_cmp stores the immediate value
            return format_binary(opcode, "1", rs1, "0000", "0000", imm)
        elif len(parts) == 3:
            rs1, rs2 = REGISTERS.get(parts[1].upper()), REGISTERS.get(parts[2].upper())
            last_cmp = (rs1, rs2)
            return format_binary(opcode, "0", rs1, "0000", rs2, None)

    elif inst in ["NOT", "MOV"]:
        if len(parts) == 3 and parts[2].lstrip('-').isdigit():
            rd = REGISTERS.get(parts[1].upper())
            imm = int(parts[2]) & 0x3FFFF
            return format_binary(opcode, "1", rd, "0000", "0000", imm)
        elif len(parts) == 3:
            rd, rs1 = REGISTERS.get(parts[1].upper()), REGISTERS.get(parts[2].upper())
            return format_binary(opcode, "0", rd, rs1, "0000", None)

    elif inst in ["MOVU", "MOVH"]:
        if len(parts) == 3:
            rd = REGISTERS.get(parts[1].upper())
        
            imm_str = parts[2].strip()
            if imm_str.startswith('0x'):  # Handle hexadecimal values
                imm = int(imm_str, 16)  # Convert hex value to integer
            else:  # Handle decimal values
                imm = int(imm_str)  # Convert decimal value to integer
        
            # Handle MOVU (unsigned)
            if inst == "MOVU":
                imm &= 0xFFFF  # Ensure it's a 16-bit value
                return format_binary(opcode, "1", rd, "0000", "0000", imm)
        
            # Handle MOVH (left shift by 16)
            else:
                inst == "MOVH"
                imm = (imm << 16) & 0x3FFFF  # Left shift by 16 and mask
                return format_binary(opcode, "1", rd, "0000", "0000", imm)
        
    elif inst in ["LD", "ST"]:
        if len(parts) == 3 and parts[2].lstrip('-').isdigit():
            rd = REGISTERS.get(parts[1].upper())
            imm = int(parts[2]) & 0x3FFFF  # Correctly extract the immediate value
            return format_binary(opcode, "1", rd, "0000", "0000", imm)
        elif len(parts) == 3:
            rd, rs1 = REGISTERS.get(parts[1].upper()), REGISTERS.get(parts[2].upper())
            return format_binary(opcode, "0", rd, rs1, "0000", None)

    elif inst in ["BEQ", "BGT"]:
        if len(parts) != 2:  # BEQ should have exactly one argument (a label)
            raise ValueError(f"Invalid syntax for {inst}: {line}")

        if last_cmp is None:
            raise ValueError(f"{inst} must follow a CMP instruction.")

        rs1, rs2_or_imm = last_cmp  # Extract the stored CMP comparison

        if rs2_or_imm.isdigit():  # If CMP was with an immediate
            cmp_mode = "1"
            imm_bin = format(int(rs2_or_imm) & 0x3FFFF, '018b')  # Convert immediate
            condition_code = "000"  # Placeholder for BEQ/BGT condition
            return f"{opcode}{condition_code}00{rs1}{imm_bin}"

        else:  # If CMP was between two registers
            cmp_mode = "0"
            offset = (symbol_table.get(parts[1], 0) - pc)
            address = format(offset & 0x7FFFFFF, '027b')  # Convert label offset
            return f"{opcode}000{address}"

    elif inst in ["B", "CALL"]:
        if len(parts) == 2:
            offset = (symbol_table.get(parts[1], 0) - pc)
            address = format(offset & 0xFFFFFF, '024b')
            return f"{opcode}000{address}"

    elif inst in ["RET", "NOP", "HLT", "END"]:
        return f"{opcode}000000000000000000000000000"

    raise ValueError(f"Invalid instruction format: {line}")

def assemble_file(input_file, output_file):
    with open(input_file, "r") as infile:
        lines = infile.readlines()

    first_pass(lines)

    with open(output_file, "w") as outfile:
        for line in lines:
            try:
                binary_code = assemble_instruction(line, pc=0)
                if binary_code:
                    outfile.write(binary_code + "\n")
            except ValueError as e:
                print(f"Error: {e}\nLine: {line.strip()}")
                sys.exit(1)

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

def run_assembler(input_file, output_file):
    try:
        assemble_file(input_file, output_file)
        messagebox.showinfo("Success", f"Assembly completed! Output saved to {output_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def open_file():
    file_path = filedialog.askopenfilename(filetypes=[("Assembly Files", "*.asm"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "r") as file:
            input_text.delete(1.0, tk.END)
            input_text.insert(tk.END, file.read())

def save_output():
    file_path = filedialog.asksaveasfilename(filetypes=[("Binary Files", "*.bin"), ("All Files", "*.*")], defaultextension=".bin")
    if file_path:
        with open(file_path, "w") as file:
            file.write(output_text.get(1.0, tk.END))
        messagebox.showinfo("Saved", f"Output saved to {file_path}")

def assemble():
    # Get input text and save it to a temporary file
    temp_input = "temp_input.asm"
    temp_output = "temp_output.bin"
    
    with open(temp_input, "w") as file:
        file.write(input_text.get(1.0, tk.END))

    run_assembler(temp_input, temp_output)
    
    # Read output and display it in the right text box
    with open(temp_output, "r") as file:
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, file.read())

# GUI Setup
root = tk.Tk()
root.title("GUI Assembler")
root.configure(bg="#1E1E1E")  # Dark background

frame = tk.Frame(root, padx=10, pady=10, bg="#1E1E1E")
frame.pack(padx=10, pady=10)

# Input and Output Text Areas
input_text = scrolledtext.ScrolledText(frame, width=50, height=15, bg="#252526", fg="white", insertbackground="white")
input_text.grid(row=0, column=0, padx=5, pady=5)

output_text = scrolledtext.ScrolledText(frame, width=50, height=15, bg="#252526", fg="white", insertbackground="white")
output_text.grid(row=0, column=1, padx=5, pady=5)

# Buttons
btn_frame = tk.Frame(root, bg="#1E1E1E")
btn_frame.pack(pady=10)

btn_assemble = tk.Button(btn_frame, text="Assemble", command=assemble, bg="#4F46E5", fg="white", width=10)
btn_assemble.grid(row=0, column=0, padx=5)

btn_open = tk.Button(btn_frame, text="Open File", command=open_file, bg="#22C55E", fg="white", width=10)
btn_open.grid(row=0, column=1, padx=5)

btn_save = tk.Button(btn_frame, text="Save Output", command=save_output, bg="#DC2626", fg="white", width=10)
btn_save.grid(row=0, column=2, padx=5)

root.mainloop()



if __name__== "_main_":
    if len(sys.argv) != 3:
        print("Usage: python3 modifier.py input.asm output.bin")
        sys.exit(1)

    assemble_file(sys.argv[1], sys.argv[2])
    