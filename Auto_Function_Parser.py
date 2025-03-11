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
    sys.exit("Auto_Function_Parser.py [IDA HTML] [XenonRecomp log] [Output TOML]")

# Filepath input arguments
ida_html = sys.argv[1]
xenonrecomp_log = sys.argv[2]
output_file = sys.argv[3]

# Disable extra debug output 
debug = False

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
        if re.search('ERROR: Switch case at ', line):
            # Save the address as integer
            switch_addrs.append(line[switch_idx:switch_idx+8])

# Save only unique addresses and sort
switch_addrs = set(switch_addrs)

##
## Parse IDA HTML
##

# Initialize list to store start and end of functions 
functs = []

# Count how many functions have been added
num_functs = 0

# Function for adding to function list and incrementing count
def add_function(new_start_addr, prev_end_addr, start_type):
    global num_functs
    # If an end address for the last added function was specified
    if prev_end_addr != None:
        # Set end address for last added function
        functs[num_functs-1][1] = prev_end_addr
    # Add a new function to the list with the specified starting address
    functs.append([new_start_addr, 0, [], start_type])
    # Increment the number of functions
    num_functs = num_functs+1

# Mark if we are in .text section
in_text = False

# Mark if we should end parsing
end_parse = False

# Initialize address of last bctr instruction to 0
bctr_addr = '00000000'

# Initialize address of last blr instruction to 0
blr_addr = '00000000'

# Initialize address of last 'End of function' comment to 0
eof_addr = '00000000'

# Initialize address of last restgprlr instruction to 0
restgprlr_addr = '00000000'

# Initialize address of last padding to 0
pad_addr = 0

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
                if re.search(r'\.text:'+curr_addr+' </span><span class="c[0-9]*">sub_'+curr_addr+'</span><span class="c[0-9]*">: *</span><span class="c[0-9]*"># [A-Z][A-Z][A-Z][A-Z] XREF:', line):
                    # Save current address as integer
                    curr_addr_int = int(curr_addr, 16)

                    # If this is not the first function being added
                    if num_functs > 0:
                        # If last address had padding or restgprlr instruction, then this function was already added
                        if curr_addr_int-4 == pad_addr or curr_addr_int-4 == restgprlr_addr:
                            # Set function type for start address
                            functs[num_functs-1][3] = 'sub'
                        else:
                            # Check if this function is part of latest added function
                            is_nested_funct = False
                            nested_functs = functs[num_functs-1][2]
                            for nested_funct in nested_functs:
                                if nested_funct == curr_addr:
                                    is_nested_funct = True
                                    break
                            
                            # If last address was not padding and not nested in latest function
                            if not is_nested_funct:
                                # Add new function and last function's end address
                                add_function(curr_addr_int, curr_addr_int, 'sub')
                    else:
                        # Add new function
                        add_function(curr_addr_int, None, 'sub')

                # If this is a location
                elif re.search(r'^\.text:'+curr_addr+' </span><span class="c[0-9]*">loc_'+curr_addr, line):
                    curr_addr_int = int(curr_addr, 16)
                    curr_funct = functs[num_functs-1]
                    # If previous address was a blr instruction
                    if curr_addr_int-4 == int(blr_addr, 16):
                        # If previous address had an 'End of function' comment or if there was a bctr with the comment
                        if blr_addr == eof_addr or bctr_addr == eof_addr:
                            # Find a XREF pointing to a .text address
                            xref_idx = line.find('XREF: .text:')
                            if xref_idx > -1:
                                underscore_idx = line.find('_', xref_idx)
                                if underscore_idx > -1:
                                    xref = line[underscore_idx+1:underscore_idx+9]
                                else:
                                    xref = line[xref_idx+12:xref_idx+20]
                            else:
                                xref = None

                            # Couldn't find XREF pointing to .text address or the XREF is after this address
                            if xref == None or int(xref, 16) > curr_addr_int:
                                # Add as new function
                                add_function(curr_addr_int, curr_addr_int, 'loc')

                    else:
                        # Find address of function that references this
                        xref_idx = line.find('CODE XREF: sub_')
                        # If it was found
                        if xref_idx > -1:
                            # Store as nested function in latest function
                            functs[num_functs-1][2].append(line[xref_idx+15:xref_idx+23])

                # Check if this line is padding
                elif num_functs > 0 and re.search(r'<span class="c[0-9]*">\.long </span><span class="c[0-9]*">0$', line):
                    # Convert current address to integer 
                    curr_addr_int = int(curr_addr, 16)

                    # Add a new function at the line after padding, and end the current function at this padding address
                    add_function(curr_addr_int+4, curr_addr_int, None)
                    
                    # Save padding address
                    pad_addr = curr_addr_int

                # Check for blr instruction
                elif re.search('<span class="c[0-9]*">blr$', line):
                    blr_addr = curr_addr

                # Check for 'End of function' comment
                elif re.search('End of function ', line):
                    eof_addr = curr_addr
    
                # Check for bctr instruction
                elif re.search('<span class="c[0-9]*">bctr$', line):
                    bctr_addr = curr_addr

                # Check for restgprlr instruction
                elif re.search('<span class="c[0-9]*">b         </span><span class="c[0-9]*">__restgprlr_[0-9][0-9]$', line):
                    # Convert current address to integer 
                    curr_addr_int = int(curr_addr, 16)

                    # Add a new function at the line after restgprlr instruction, and end the current function at this address
                    add_function(curr_addr_int+4, curr_addr_int, None)
                    
                    restgprlr_addr = curr_addr_int

            # If not in .text
            else:
                # If .text section header found
                if re.search(r'<span class="c[0-9]*">\.section &quot;\.text&quot;', line):
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
        curr_funct_start = curr_funct[0]
        if(switch_addr_int > curr_funct_start):
            # If switch address is before this function's end
            curr_funct_end = curr_funct[1]
            if(switch_addr_int <= curr_funct_end):
                # Save current function's start address and the function's length
                if debug:
                    output_functs.append([hex(curr_funct_start), hex(curr_funct_end-curr_funct_start), switch_addr])
                else:
                    output_functs.append([hex(curr_funct_start), hex(curr_funct_end-curr_funct_start)])
            
                # Don't need to continue search for this switch statement
                search_for_funct = False

            # Look in next function
            curr_funct_idx = curr_funct_idx + 1

        # Related function was not found
        else:
            print(f"WARNING: Function relating to {switch_addr} not found! Skipping.")
            # Don't need to continue search for this switch statement
            search_for_funct = False

# Remove duplicates
if not debug: 
    output_functs = list(set(tuple(funct) for funct in output_functs))

# Make sure there are no functions with the same starting address but different lengths
if not debug:
    for i in range(len(output_functs)):
        for j in range(i+1, len(output_functs)):
            curr_funct_start = output_functs[i][0]
            if curr_funct_start == output_functs[j][0]:
                print(f"WARNING: {curr_funct_start} has multiple entries of different lengths, manually find correct one.")

print(f"{len(output_functs)} functions found!")

##
## Output all found functions to TOML in correct format
##

# Create formatted string to export to TOML
output_str = "functions = ["

# Append all function addresses and lengths to formatted string
print("Outputting to formatted file...")
for funct in output_functs:
    # Format hex to uppercase 
    curr_funct_start = '0x'+funct[0][2:].upper()
    curr_funct_end = '0x'+funct[1][2:].upper()

    # Format function 
    curr_funct = "\n    { address = "+curr_funct_start+", size = "+curr_funct_end
    if debug:
        curr_funct = curr_funct+", src = "+funct[2]
    curr_funct = curr_funct+" },"

    # Add to complete output string
    output_str = output_str+curr_funct

# Delete last comma
output_str = output_str[:len(output_str)-1]

# Add last bracket
output_str = output_str+"\n]"

# Output to file
with open(output_file, "w") as file:
    file.write(output_str)


