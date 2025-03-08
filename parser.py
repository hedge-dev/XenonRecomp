##
## Searches for functions in .text that are referenced by functions in .pdata
##
## Input: 
## Decompiled code - Created in IDA Pro 9.0SP1 with File -> Produce File -> Create HTML File...
## CLI output from a XenonRecomp run - When trying to compile with XenonRecomp, use > to save the output from the terminal
##
## Output: 
## XenonRecomp config - Function block for TOML to be inputted into XenonRecomp 
##

import sys
import re

# Check if correct number of input arguments were given
if len(sys.argv) != 4:
    sys.exit("parser.py [IDA HTML] [XenonRecomp log] [Output TOML]")

# Filepath input arguments
ida_html = sys.argv[1]
xenonrecomp_log = sys.argv[2]
output_file = sys.argv[3]

##
## Parse XenonRecomp log
##

# The starting index of the erroneous switch statement address in the XenonRecomp log
switch_idx = 22

# Initialize list to store erroneous switch statement addresses
switch_addrs = []
    
print("Parsing XenonRecomp log...")
# Import each line of XenonRecomp log
with open(xenonrecomp_log, 'r') as file:
    # Read each line in the file
    for line in file: 
        # If this line describes an error, it has the address of a problematic switch statement
        if re.search('ERROR', line) != None:
            # Save the address as integer
            switch_addrs.append(line[switch_idx:switch_idx+8])

# Save only unique addresses and sort
switch_addrs = set(switch_addrs)

##
## Parse IDA HTML
##

# See if current function is referenced by the inputted comparison address 
def compare_xref_addr(line, compare_addr):
    # Get the address of the referencing function
    xref_idx = line.find('CODE XREF: sub_')
    # If there is not a referencing function or it is in a different file, this doesn't need to be verified
    if xref_idx == -1:
        return True
    else:
        xref = line[xref_idx+15:xref_idx+23]

    # Check equality between XREF address and comparison address
    return xref == compare_addr

# Initialize list to store start and end of functions 
functs = []

# Count how many functions have been added
num_functs = 0

# Mark if we are in .text section
in_text = False

# Mark if we should end parsing
end_parse = False

# Initialize address of last padding to 0
pad_addr = '00000000'

# Import each line of decompiled code
print("Parsing IDA HTML...")
with open(ida_html, 'r') as file:
    # Read each line in the file
    for line in file:
        if not end_parse:
            # If in .text
            if in_text:
                # Get the current address
                colon_idx = line.find(':')
                curr_addr = line[colon_idx+1:colon_idx+9]

                # Check if this is the start of a function
                if re.search('^\.text:'+curr_addr+' </span><span class="c[0-9]*">sub_'+curr_addr, line):
                    # Check if this is a new function and not part of a switch
                    if num_functs > 0:
                        # If the referencing function is not the last added function, then it is not part of a switch
                        if not compare_xref_addr(line, functs[num_functs-1][0]):
                            # Add this address as a new function
                            functs.append([curr_addr, 0])
                            num_functs = num_functs+1
                            # Convert addresses to integer for comparison
                            curr_addr_int = int(curr_addr, 16)
                            pad_addr_int = int(pad_addr, 16)
                            # If previous address was padding, end last function at the padding
                            if curr_addr_int-4 == pad_addr_int:
                                functs[num_functs-2][1] = pad_addr_int
                            # Else, end last function as this address
                            else:
                                functs[num_functs-2][1] = curr_addr_int

                    # If this is the first function to be added, don't need to check if it is part of a switch
                    else:
                        # Add this address as a new function
                        functs.append([curr_addr, 0])
                        num_functs = num_functs+1

                # If this is not the start of a function
                else:
                    # Check if it is a nested loc_ or def_
                    if re.search('^\.text:'+curr_addr+' </span><span class="c[0-9]*">[ld][oe][cf]_'+curr_addr, line):
                        # If the referencing function is not the last added function, then it is not part of a switch
                        if not compare_xref_addr(line, functs[num_functs-1][0]):
                            # Add this address as a new function
                            functs.append([curr_addr, 0])
                            num_functs = num_functs+1
                            # Convert addresses to integer for comparison
                            curr_addr_int = int(curr_addr, 16)
                            pad_addr_int = int(pad_addr, 16)
                            # If previous address was padding, end last function at the padding
                            if curr_addr_int-4 == pad_addr_int:
                                functs[num_functs-2][1] = pad_addr_int
                            # End the last function at the previous address
                            else:
                                functs[num_functs-2][1] = curr_addr_int
                    
                    # Check if this line is padding
                    elif re.search('<span class="c[0-9]*">\.long </span><span class="c[0-9]*">0$', line):
                        # Save address of most recently found padding
                        pad_addr = curr_addr

                    # Check if we are still in .text
                    elif re.search('\.text:', line) == None:
                        # If not, end parsing
                            end_parse = True

            # If not in .text
            else:
                # If .text section header found
                if re.search('<span class="c[0-9]*">\.section &quot;\.text&quot;', line) != None:
                    in_text = True

##
## Find .text functions that are referenced by .pdata functions
##

# Initialize list for functions that need to be added to toml
output_functs = []

# Look for related functions for every unique errored switch statement
print("Searching for needed functions...")
for switch_addr in switch_addrs:
    # Start looking at first subroutine
    curr_funct_idx = 0

    # Save current switch statement address as integer
    switch_addr_int = int(switch_addr, 16)

    # The related function for this switch statement has not been found yet
    search_for_funct = True

    # Start search for function relating to switch statement
    while(search_for_funct):
        curr_funct = functs[curr_funct_idx]
        # If switch address is after this function's start
        curr_funct_start = int(curr_funct[0], 16)
        if(switch_addr_int > curr_funct_start):
            # If switch address is before this function's end
            curr_funct_end = curr_funct[1]
            if(switch_addr_int <= curr_funct_end):
                # Save current function's start address and the function's length
                output_functs.append([hex(curr_funct_start), hex(curr_funct_end-curr_funct_start)])
                # Don't need to continue search for this switch statement
                search_for_funct = False

            # Look in next function
            curr_funct_idx = curr_funct_idx + 1

        # Related function was not found
        else:
            print(f"WARNING: Function relating to {switch_addr} not found")
            # Don't need to continue search for this switch statement
            search_for_funct = False

print(f"{len(output_functs)} functions found!")                

# Create formatted string to export to TOML
output_str = "functions = ["

# Append all function addresses and lengths to formatted string
for funct in output_functs:
    # Format hex to uppercase 
    curr_funct_start = '0x'+funct[0][2:].upper()
    curr_funct_end = '0x'+funct[1][2:].upper()

    # Format function 
    curr_funct = "\n    { address = "+curr_funct_start+", size = "+curr_funct_end+" },"

    # Add to complete output string
    output_str = output_str+curr_funct

# Delete last comma
output_str = output_str[:len(output_str)-1]

# Add last bracket
output_str = output_str+"\n]"

# Output to file
with open(output_file, "w") as file:
    file.write(output_str)


