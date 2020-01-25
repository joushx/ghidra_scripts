# Applies IDR map files
#@author Johannes Mittendorfer
#@category Delphi
#@keybinding 
#@menupath Tools.Delphi.Map
#@toolbar 


from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.address import Address
from ghidra.program.model.symbol import SourceType

def read_file(filename):
	return open(filename).read()

def parse_file(contents):
	lines = contents.split("\r\n")
	return map(parse_line, lines[9:])

def parse_line(line):
	parts = line.split(" ")

	if(len(parts) < 2):
		print("Wrong size: " + line)
		return None

	return (parts[1], parts[2])

def generate_names(lines):
	return map(generate_name, lines)

def generate_name(line):
	if(line is None):
		return

	addr = extract_address(line[1])
	name = extract_name(line[1])

	if(addr is None or name is None):
		return

	return (addr, name)

def remove_addr_suffix(name):
	parts = name.split("_")
	parts = filter(lambda p: len(p) > 0, parts)
	return "_".join(parts[:-1])

def extract_name(name_part):
	clean_name = remove_addr_suffix(name_part)
	return clean_name.replace(".", "_").replace("@", "")

def extract_address(name_part):
	addr = "0x" + name_part.split("_")[-1]
	return currentProgram.getAddressFactory().getAddress(addr)

def rename_functions(names):
	listing = currentProgram.getListing();

	for name in names:
		rename_function(name, listing)

def rename_function(name, listing):
	if(name is None):
		return

	func = listing.getFunctionContaining(name[0])
	if(func == None):
		return

	func.setName(name[1], SourceType.IMPORTED)

contents = read_file("<Path to MAP file>")
lines = parse_file(contents)
names = generate_names(lines)
rename_functions(names)

