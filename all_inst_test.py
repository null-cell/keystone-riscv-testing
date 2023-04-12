from capstone import Cs
from keystone import *
from qiling import Qiling
from qiling.const import QL_VERBOSE
import time
import sys
import os
from collections import defaultdict
import random
random.seed(10)

# import the RISCV instructions from cpp file with a single list into a python dict with the first comment value as key and the rest of the line as key value dict elements
class Instruction:
    # define the class
    def __init__(self, mnemonic="err", classname="err", parameters="err", extension="err", classes=["err"]):
        self.mnemonic = mnemonic
        self.classname = classname
        self.parameters = parameters
        self.extension = extension
        self.classes = []
        self.symb = self.classname.split("::")[1].lower().strip()+"_symb"

        for mclass in classes:
            mclass = mclass.strip()[4:]
            if mclass == "":
                continue
            elif mclass == "_40_":
                self.classes.append(["("])
            elif mclass == "_41_":
                self.classes.append([")"])
            elif mclass[:3] == "GPR":
                mclass = mclass[3:]
                if mclass[:1].isdigit():
                    raise Exception("GPR class cannot continue with a number")
                elif mclass[:1] == "C":
                    self.classes.append(["x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15"])
                elif mclass[0:1] == "No":
                    self.classes.append(["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31"])
                    mclass = mclass[2:].lower()
                    while len(mclass > 2) and re.fullmatch("x\d", mclass[:2]) != None:
                        self.classes[-1].remove(mclass[:2])
                        mclass = mclass[2:]
                else:
                    self.classes.append(["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29", "x30", "x31"])

                            
            elif mclass == "SP":
                self.classes.append(["sp"])
            elif mclass[:3] == "FPR":
                mclass = mclass[3:]
                #floating point register, add filters
                if mclass[0:3] == "128":
                    mclass = mclass[3:]
                elif mclass[0:2] in ["32", "64"]:
                    mclass = mclass[2:]
                if mclass[:1] == "C":
                    self.classes.append(["f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15"])
                else:
                    self.classes.append(["f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15", "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23", "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31"])
            
            # if the class is *Symbol, then omit the mnemonic in the eventual input string
            elif mclass in ["CallSymbol","BareSymbol"]:
                self.classes.append(set([self.symb]))

            elif mclass == "FenceArg":
                self.classes.append(["i", "o", "r", "w", "io", "ir", "iw", "or", "ow", "rw", "ior", "iow", "irw", "iorw"])
            
            elif mclass == "FRMArg":
                self.classes.append(["rne", "rtz", "rdn", "rup", "rmm"])

            elif mclass == "CSRSystemRegister":
                # self.classes.append(["fflags","frm","fcsr","cycle","cycleh","time","timeh","instret","instreth","hpmcounter3","hpmcounter31","hpmcounter31h","hpmcounter4","hpmcounter4h"]) #these are the unprivileged CSR's
                self.classes.append(["mstatus"]) #TODO: add all machine level CSR's
            
            # only add has TPRelAddSymbol, so we can construct the input string now
            elif mclass == "TPRelAddSymbol":
                self.classes.append(set(["%tprel_add("+self.symb+")"]))
                

            elif mclass[:4] == "SImm":
                mclass = mclass[4:]
                exp = ""
                if mclass[:1].isdigit():
                    while mclass[:1].isdigit():
                        exp += mclass[:1]
                        mclass = mclass[1:]
                elif mclass[:8] == "Log2XLen":
                    mclass = mclass[8:]
                    if XLEN == 32:
                        exp = "5"
                    elif XLEN == 64:
                        exp = "6"
                    elif XLEN == 128:
                        exp = "7"
                    else:
                        raise Exception("XLEN not supported")
                if mclass[:3] != "Lsb":
                    self.classes.append([str(i) for i in range(-2**(int(exp)-1), 2**(int(exp)-1) -1)])
                if mclass[:3] == "Lsb":
                    mclass = mclass[3:]
                    lsb = 0
                    while mclass[:1] == "0":
                        lsb += 1
                        mclass = mclass[1:]
                    self.classes.append([str(i) for i in range(-2**(int(exp)-1), 2**(int(exp)-1) -1 , 2**lsb)])
                if mclass[:7] == "NonZero":
                    mclass = mclass[7:]
                    self.classes[-1].remove("0")
            
            elif mclass[:4] == "UImm":
                mclass = mclass[4:]
                exp = ""
                if mclass[:1].isdigit():
                    while mclass[:1].isdigit():
                        exp += mclass[:1]
                        mclass = mclass[1:]
                elif mclass[:8] == "Log2XLen":
                    mclass = mclass[8:]
                    if XLEN == 32:
                        exp = "5"
                    elif XLEN == 64:
                        exp = "6"
                    elif XLEN == 128:
                        exp = "7"
                    else:
                        raise Exception("XLEN not supported")
                if mclass[:3] != "Lsb":
                    self.classes.append([str(i) for i in range(2**(int(exp)) -1)])
                if mclass[:3] == "Lsb":
                    mclass = mclass[3:]
                    lsb = 0
                    while mclass[:1] == "0":
                        lsb += 1
                        mclass = mclass[1:]
                    self.classes.append([str(i) for i in range(0, 2**(int(exp)) -1 , 2**lsb)])
                if mclass[:7] == "NonZero":
                    mclass = mclass[7:]
                    self.classes[-1].remove("0")
                if mclass[:3] == "LUI":
                    mclass = mclass[3:]
                    self.classes[-1] = set(self.classes[-1] + ["%hi("+self.symb+")", "%tprel_hi("+self.symb+")"])
                if mclass[:5] == "AUIPC":
                    mclass = mclass[5:]
                    self.classes[-1] = set(self.classes[-1] + ["%pcrel_hi("+self.symb+")", "%got_pcrel_hi("+self.symb+")", "%tls_ie_pcrel_hi("+self.symb+")", "%tls_gd_pcrel_hi("+self.symb+")"])
            
            elif mclass == "ImmXLenLI":
                if XLEN == 64:
                    self.classes.append(range(-2**(XLEN)+1, 2**(XLEN)-1))
                elif XLEN == 32:
                    self.classes.append(range(-2**(XLEN-1), 2**(XLEN)-1))

            elif mclass == "CLUIImm":
                self.classes.append([str(i) for i in range(1, 31)] + [str(i) for i in range(0xfffe0, 0xfffff)])

    # define to string of class
    def __str__(self):
        return "mnemonic: " + self.mnemonic + "\nclassname: " + self.classname + "\nparameters: " + self.parameters + "\nextension: " + self.extension + "\nclasses: " + str(self.classes) + "\n"

def createExtensionAssemblyFile(instrdict, extension):
    #create a file with the instructions
    #print("[+] Creating extension folder for: "+extension)
    ctr = 0
    try: 
        os.makedirs("assembly_tests/"+extension)
    except FileExistsError:
        pass  

    for instruction in instrdict[extension]:
        with open("assembly_tests/"+extension+"/"+instruction.classname.split("::")[1].lower()+str(ctr)+".s", 'w') as f:

            f.write(".text\n")
            inst = createInstruction(instruction)
            f.write(inst+"\n")
            ctr += 1
            #print("[+] Written instruction: "+inst, end="\r")
        #print("")
    print("[+] Created extension files for: "+extension)

def createInstruction(instruction):
    # for add with %tprel_add, we have to have the fourth operand as x4/tp
    if instruction.classname == "RISCV::PseudoAddTPRel":
        picked1, _ = pickClass(instruction.classes[0])
        picked2, _ = pickClass(instruction.classes[1])
        inst = instruction.symb+ ": add "+picked1+", "+picked2+", x4, %tprel_add("+instruction.symb+")"
        return inst

    # create a new instruction
    inst = "\t"+instruction.mnemonic + " "
    # for each class, pick a random value
    for mclass in instruction.classes:
        picked, symbolinst = pickClass(mclass)
        if symbolinst:
            inst = instruction.symb + ": " + inst + " "
            
        # if the picked operand is a bracket, check the previous picked operand
        # if the previous operand is a register, keep the comma and space before the bracket
        # otherwise if it is a number, remove the ", " from the previous operand
        if picked == "(":
            prevop = inst.split(" ")[-2]
            if prevop[:1] in ["x", "f"]:
                #previous was a register
                pass 
            else:
                #previous was a number
                inst = inst[:-2]
            
        inst += picked + ", "
    # remove the last ", " if there is more than just mnemonic
    if(len(instruction.classes) > 0):
        inst = inst[:-2]
    # remove the ", " inside the brackets
    inst = inst.replace(", )", ")")
    inst = inst.replace("(, ", "(")

    # return the instruction
    return inst

def pickClass(mclass):
    # pick a random value from the class
    if type(mclass) == list:
        return (mclass[random.randint(0, len(mclass)-1)], False)
        # return mclass[len(mclass)//2]
    # if the class is a range, pick a random value from the range
    elif type(mclass) == range:
        return (str(random.randint(mclass.start, mclass.stop)), False)
        # return str(mclass.stop//2)
    # raise error if it is anything else
    elif type(mclass) == set:
        return (random.choice(list(mclass)), True)
    else:
        raise Exception("Class is not a list or range")


if __name__ == "__main__":
    
    start_time = time.time()
    global XLEN
    XLEN = 64
    instrdict = defaultdict(list)
    extensions = set()
    num_instr = defaultdict(int)
    # read the instructions file into a list
    with open(sys.argv[1], 'r') as f:
        for line in f:
            splitline = line.split("{")[1].split(",")
            mnemonic = splitline[0].split("/*")[1].split("*/")[0].strip()        
            classname = splitline[1].strip()
            parameters = splitline[2].strip()
            extension = splitline[3].strip()[6:]
            extensions.add(extension)
            classes = line.split("{")[2].split("}")[0].strip().split(", ")
            instrdict[extension].append(Instruction(mnemonic, classname, parameters, extension, classes))
            num_instr[extension] += 1
            #print("[+] Parsed: "+mnemonic)
    
    # order extensions, so each execution will have the same order
    extensions = sorted(extensions)
    

    # create the assembly files for each extension(set)
    for extension in extensions:
        createExtensionAssemblyFile(instrdict, extension)
    print("||||||||||||||||||||||||||||||||||||||||||||||||||||")

    # assemble each file with gcc-as
    for extension in extensions:
        #print("[+] Creating folder: object_tests/"+extension+" [mkdir object_tests/"+extension+"]")
        try:
            os.makedirs("object_tests/"+extension)
        except FileExistsError:
            pass
        print("[+] Assembling files from extension: "+extension)

        for file in os.listdir("assembly_tests/"+extension):
            os.system("riscv64-unknown-linux-gnu-as -o object_tests/"+extension+"/"+file[:-2]+".o assembly_tests/"+extension+"/"+file+" -march=rv64gc -mno-relax -Z")
    print("||||||||||||||||||||||||||||||||||||||||||||||||||||")

    # objdump each file
    for extension in extensions:
        #print("[+] Creating folder: objdump_tests/"+extension+" [mkdir objdump_tests/"+extension+"]")
        try:
            os.makedirs("objdump_tests/"+extension)
        except FileExistsError:
            pass
        
        print("[+] Objdumping files from extension: "+extension)
        for file in os.listdir("object_tests/"+extension):
            os.system("riscv64-unknown-linux-gnu-objdump -d object_tests/"+extension+"/"+file+" --disassembler-options=no-aliases -b elf64-littleriscv -m riscv:rv64 > objdump_tests/"+extension+"/"+file[:-2]+".objdump")
    print("||||||||||||||||||||||||||||||||||||||||||||||||||||")

    # init keystone
    ks = Ks(KS_ARCH_RISCV, KS_MODE_RISCV64)
    XLEN = 64
    results = defaultdict(int)
    disas_results = defaultdict(int)
    success_disas_results = defaultdict(int)
    different_results = defaultdict(int)
    failed_gcc = defaultdict(int)
    # assemble each file with keystone
    for extension in extensions:
        print("[+] Keystone assembling extension: "+extension)
        results[extension] = 0
        disas_results[extension] = 0
        success_disas_results[extension] = 0
        different_results[extension] = 0
        failed_gcc[extension] = 0

        for file in os.listdir("assembly_tests/"+extension):
            # print("[+] Keystone assembling file: "+file)
            with open("assembly_tests/"+extension+"/"+file, 'r') as fasm:
                with open("objdump_tests/"+extension+"/"+file[:-2]+".objdump", "r") as fobjdump:
                    # read from both files
                    # from assembly tests, skip the first line
                    # from objdump tests, skip the first 7 lines
                    asm_lines = fasm.read().splitlines()[1:]
                    objdump_lines = fobjdump.read().splitlines()
                    
                    #if there are not enough objdump lines, skip the file since it was probably errored out in the assembly process
                    if len(objdump_lines) <= 7:
                        print("[-] Failed to disassemble: "+file+" (too few lines in objdump: "+str(len(objdump_lines))+")")
                        failed_gcc[extension] += 1

                    # if there is more than one objdump line, report a difference in disassembled instructions and the assembly file, but still try to assemble the new disassembled instructions
                    elif len(objdump_lines) > 8:
                        # print("[!] More than one objdump line for file: "+file)
                        # print("[!] Disassembled instructions: "+"; ".join(objdump_lines))
                        # print("[!] Assembly instructions: "+"; ".join(asm_lines))
                        # print("[!] Trying to assemble the new disassembled instructions")
                        disas_results[extension] += 1
                        #TODO: try to assemble the new disassembled instructions
                        objdump_lines = objdump_lines[7:]
                        objdump_lines = [line for line in objdump_lines if line.strip() != ""]
                        objdump_lines = [line for line in objdump_lines if line.strip() != "..."]
                        correct = True
                        for objdump_line in objdump_lines:
                            objdump_line_hex = objdump_line.split(":")[1].split()[0].strip()
                            objdump_line_inst = " ".join(objdump_line.split(":")[1].strip().split()[1:]).strip()
                            if "#" in objdump_line_inst:
                                objdump_line_inst = objdump_line_inst.split("#")[0].strip()
                            if "<" in objdump_line_inst:
                                objdump_line_inst = objdump_line_inst.split("<")[0].strip()
                            objdump_line_mnemonic = objdump_line_inst.split()[0].strip()

                            # assemble the instruction with keystone
                            ks_hex, _ = ks.asm(objdump_line_inst)
                            ks_hex = "".join(reversed(['{:0>2x}'.format(i) for i in ks_hex]))
                            if objdump_line_hex != ks_hex:
                                correct = False
                                print("----------------------------------------------")
                                print("[-] Failed while assembling disected pseudo instructions: "+objdump_line_mnemonic+ " (objdump line: "+objdump_line_inst+")")
                                print("[-] Expected (Keystone): "+ks_hex)
                                print("[-] Got (GCC+Objdump): "+objdump_line_hex)
                                print("----------------------------------------------")
                                break
                        if correct:
                            success_disas_results[extension] += 1

                    else:
                        # assemble assembly_line with Keystone and then compare with hex code from objdump
                        
                        objdump_line = objdump_lines[7].strip()
                        assembly_line = asm_lines[0].strip()
                        if objdump_line.strip() == "...":
                            print("----------------------------------------------")
                            print("[-] Objdump failed: "+assembly_line.strip().split()[0]+ " (objdump line: "+objdump_line.strip()+")")
                            print("[-] Expected (Keystone): "+assembly_line)
                            print("[-] Got (GCC+Objdump): "+objdump_line)
                            print("----------------------------------------------")
                            failed_gcc[extension] += 1

                        else:
                            # get the hex code from objdump
                            objdump_line_hex = objdump_line.split(":")[1].split()[0].strip()
                            objdump_line_inst = " ".join(objdump_line.split(":")[1].strip().split()[1:]).strip()
                            objdump_line_mnemonic = objdump_line_inst.split()[0].strip()

                            # assemble the assembly line with Keystone
                            asm_hex, _ = ks.asm(assembly_line)
                            asm_hex = "".join(reversed(['{:0>2x}'.format(i) for i in asm_hex]))
                            if objdump_line_hex == asm_hex:
                                results[extension] += 1
                            else:
                                if objdump_line_mnemonic == assembly_line.strip().split()[0]:
                                    print("----------------------------------------------")
                                    print("[!] Different hex code for same mnemonic: "+objdump_line_mnemonic)
                                    print("[!] Expected (Keystone): "+assembly_line+" -> "+asm_hex)
                                    print("[!] Got (GCC+Objdump): "+objdump_line_inst+" -> "+objdump_line_hex)
                                    print("----------------------------------------------")
                                    different_results[extension] += 1
                                else:    
                                    print("----------------------------------------------")
                                    print("[-] Failed to assemble - different mnemonics: "+assembly_line.strip().split()[0])
                                    print("[-] Expected (Keystone): "+assembly_line+" -> "+asm_hex)
                                    print("[-] Got (GCC+Objdump): "+objdump_line_inst+" -> "+objdump_line_hex)
                                    print("----------------------------------------------")
                                    different_results[extension] += 1
                                # check if the objdump disassembled instruction is the same as the assembly instruction

        print("[+] Success for "+extension+": "+str(results[extension])+"/"+str(num_instr[extension])+" ("+str(round(results[extension]/num_instr[extension]*100, 2))+"%)")
        if results[extension] < num_instr[extension]:
            if disas_results[extension] > 0:
                print("[+] Disassembled results for "+extension+": "+str(disas_results[extension])+"/"+str(num_instr[extension])+" ("+str(round(disas_results[extension]/num_instr[extension]*100,2))+"%)")
            if disas_results[extension] > 0:
                print("[+] Successful disassembled results for "+extension+": "+str(success_disas_results[extension])+"/"+str(disas_results[extension])+" ("+str(round(success_disas_results[extension]/disas_results[extension]*100,2))+"%)")
            if different_results[extension] > 0:
                print("[+] Different results for "+extension+": "+str(different_results[extension])+"/"+str(num_instr[extension])+" ("+str(round(different_results[extension]/num_instr[extension]*100,2))+"%)")
            if failed_gcc[extension] > 0:
                print("[+] Failed GCC for "+extension+": "+str(failed_gcc[extension])+"/"+str(num_instr[extension])+" ("+str(round(failed_gcc[extension]/num_instr[extension]*100,2))+"%)")

        print("******************************************")
                 
    print("[+] Total results: "+str(sum(results.values()))+"/"+str(sum(num_instr.values()))+" ("+str(sum(results.values())/sum(num_instr.values())*100)+"%)")
    print("[+] Total disassembled results: "+str(sum(disas_results.values()))+"/"+str(sum(num_instr.values()))+" ("+str(sum(disas_results.values())/sum(num_instr.values())*100)+"%)")
    print("[+] Total success disassembled results: "+str(sum(success_disas_results.values()))+"/"+str(sum(disas_results.values()))+" ("+str(sum(success_disas_results.values())/sum(disas_results.values())*100)+"%)")
    print("[+] Total different results: "+str(sum(different_results.values()))+"/"+str(sum(num_instr.values()))+" ("+str(sum(different_results.values())/sum(num_instr.values())*100)+"%)")
    print("[+] Total failed gcc results: "+str(sum(failed_gcc.values()))+"/"+str(sum(num_instr.values()))+" ("+str(sum(failed_gcc.values())/sum(num_instr.values())*100)+"%)")

    print("--- %s seconds ---" % (time.time() - start_time))
        

