# XenonRecomp

XenonRecomp is a tool that converts Xbox 360 executables into C++ code, which can then be recompiled for any platform.

This project was heavily inspired by [N64: Recompiled](https://github.com/N64Recomp/N64Recomp), a similar tool for N64 executables.

**DISCLAIMER:** This project does not provide a runtime implementation. It only converts the game code to C++, which is not going to function correctly without a runtime backing it. **Making the game work is your responsibility.**

## Implementation Details

### Instructions

The instructions are directly converted without any effort to make them resemble decompiled code, meaning the output is not very human-readable. The CPU state is passed as an argument to every PPC function, which includes definitions for every PPC register and their current values at the time of execution. The second argument is the base address pointer, as the Xbox 360 CPU uses 32-bit pointers.

A good amount of PPC instructions are implemented, with missing ones primarily being variants of already implemented instructions. Some instructions, like the D3D unpack/pack instructions, do not support all operand types. When a missing case is encountered, a warning is generated, or a debug break is inserted into the converted C++ code.

The instruction implementations operate on little-endian values. However, since the Xbox 360 is a big-endian machine, the memory load instructions swap endianness when reading values, and memory store instructions reverse it to big-endian before writing. All the memory loads and stores are marked volatile to prevent Clang from doing unsafe code reordering.

Vector registers' endianness handling is more complicated. Instead of swapping individual 32-bit elements, the recompiler chooses to reverse the entire 16-byte vector. Instructions must account for this reversed order, such as using the WZY components instead of XYZ in dot products or requiring reversed arguments for vector pack instructions.

The FPU expects denormalized numbers to remain unmodified, while VMX instructions always flush them. This is managed by storing the current floating-point state in the CPU state struct and enabling or disabling denormal flushing as necessary before executing each instruction.

Most VMX instructions are implemented using x86 intrinsics. Support for ARM64 is implemented using [SIMD Everywhere](https://github.com/simd-everywhere/simde).

### MMIO

MMIO, which is typically used for hardware operations such as XMA decoding, is currently unimplemented. There is an unfinished attempt to implement MMIO, but supporting it may be non-trivial and could require advanced analysis of instructions.

### Indirect Functions

Virtual function calls are resolved by creating a "perfect hash table" at runtime, where dereferencing a 64-bit pointer (using the original instruction address multiplied by 2) gives the address of the recompiled function. This was previously implemented by creating an 8 GB virtual allocation, but it had too much memory pressure. Now it relies on function addresses being placed after the valid XEX memory region in the base memory pointer. These regions are exported as macros in the output `ppc_config.h` file.

### Jump Tables

Jump tables, at least in older Xbox 360 binaries, often have predictable assembly patterns, making them easy to detect statically without needing a virtual machine. XenonAnalyse has logic for detecting jump tables in Sonic Unleashed, though variations in other games (likely due to updates in the Xbox 360 compiler) may require modifications to the detection logic. Currently, there is no fully generic solution for handling jump tables, so updates to the detection logic may be needed for other games.

The typical way to find jump tables is by searching for the `mtctr r0` instruction. It will almost always be followed with a `bctr`, with the previous instructions computing the jump address.

XenonAnalyse generates a TOML file containing detected jump tables, which can be referenced in the main TOML config file. This allows the recompiler to generate real switch cases for these jump tables.

### Function Boundary Analysis

XenonAnalyse includes a function boundary analyzer that works well in most cases. Functions with stack space have their boundaries defined in the `.pdata` segment of the XEX. For functions not found in this segment, the analyzer detects the start of functions by searching for branch link instructions, and determines their length via static analysis.

However, the analyzer struggles with functions containing jump tables, since they look like tail calls without enough information. While there is currently no solution for this, it might be relatively simple to extend the function analyzer to account for jump tables defined in the TOML file. As a workaround, the recompiler TOML file allows users to manually define function boundaries.

### Exceptions

The recompiler currently does not support exceptions. This is challenging due to the use of the link register and the fact that exception handlers can jump to arbitrary code locations.

### setjmp

`setjmp` and `longjmp` are implemented by redirecting them to native implementations. Thanks to the Xbox 360's large number of vector registers, the guest CPU state struct is large enough to hold the x86 CPU state and potentially states from other architectures.

### Optimizations

Since Xbox 360 binaries typically follow a stable ABI, we can make certain assumptions about code structure, allowing the Clang compiler to generate better code. Several optimization options are available in the recompiler, but it's recommended to test them only after having a successfully functioning recompilation.

The link register can be skipped assuming the game does not utilize exceptions, as the whole process of recompilation already takes care of function return behavior.

The following registers, assuming the game doesn't violate the ABI, can be safely converted into local variables, as they never leave the function scope:
* Count register
* XER
* Reserved register
* Condition registers
* Non argument registers
* Non volatile registers

The local variable optimization particularly introduces the most improvements, as the calls to the register restore/save functions can be completely removed, and the redundant stores to the PPC context struct can be eliminated. In [Unleashed Recompiled](https://github.com/hedge-dev/UnleashedRecomp), the executable size decreases by around 20 MB with these optimizations, and frame times are reduced by several milliseconds.

### Patch Mechanisms

XenonRecomp defines PPC functions in a way that makes them easy to hook, using techniques in the Clang compiler. By aliasing a PPC function to an "implementation function" and marking the original function as weakly linked, users can override it with a custom implementation while retaining access to the original function:

```cpp
PPC_FUNC_IMPL(__imp__sub_XXXXXXXX);
PPC_FUNC(sub_XXXXXXXX)
{
    __imp__sub_XXXXXXXX(ctx, base);
}
```

Additionally, mid-asm hooks can be inserted directly into the translated C++ code at specific instruction addresses. The recompiler inserts these function calls, and users are responsible for implementing them in their recompilation project. The linker resolves them during compilation.

## Usage

### XenonAnalyse

XenonAnalyse, when used as a command-line application, allows an XEX file to be passed as an input argument to output a TOML file containing all the detected jump tables in the executable:

```
XenonAnalyse [input XEX file path] [output jump table TOML file path]
```

However, as explained in the earlier sections, due to variations between games, additional support may be needed to handle different patterns.

[An example jump table TOML file can be viewed in the Unleashed Recompiled repository.](https://github.com/hedge-dev/UnleashedRecomp/blob/main/UnleashedRecompLib/config/SWA_switch_tables.toml)

### XenonRecomp

XenonRecomp accepts a TOML file with recompiler configurations and the path to the `ppc_context.h` file located in the XenonUtils directory:

```
XenonRecomp [input TOML file path] [input PPC context header file path]
```

[An example recompiler TOML file can be viewed in the Unleashed Recompiled repository.](https://github.com/hedge-dev/UnleashedRecomp/blob/main/UnleashedRecompLib/config/SWA.toml)

#### Main

```toml
[main]
file_path = "../private/default.xex"
patch_file_path = "../private/default.xexp"
patched_file_path = "../private/default_patched.xex"
out_directory_path = "../ppc"
switch_table_file_path = "SWA_switch_tables.toml"
```

All the paths are relative to the directory where the TOML file is stored.

Property|Description
-|-
file_path|Path to the XEX file.
patch_file_path|Path to the XEXP file. This is not required if the game has no title updates.
patched_file_path|Path to the patched XEX file. XenonRecomp will create this file automatically if it is missing and reuse it in subsequent recompilations. It does nothing if no XEXP file is specified. You can pass this output file to XenonAnalyse.
out_directory_path|Path to the directory that will contain the output C++ code. This directory must exist before running the recompiler.
switch_table_file_path|Path to the TOML file containing the jump table definitions. The recompiler uses this file to convert jump tables to real switch cases.

#### Optimizations

```toml
skip_lr = false
skip_msr = false
ctr_as_local = false
xer_as_local = false
reserved_as_local = false
cr_as_local = false
non_argument_as_local = false
non_volatile_as_local = false
```

Enables or disables various optimizations explained earlier in the documentation. It is recommended not to enable these optimizations until you have a successfully running recompilation. 

#### Register Restore & Save Functions

```toml
restgprlr_14_address = 0x831B0B40
savegprlr_14_address = 0x831B0AF0
restfpr_14_address = 0x831B144C
savefpr_14_address = 0x831B1400
restvmx_14_address = 0x831B36E8
savevmx_14_address = 0x831B3450
restvmx_64_address = 0x831B377C
savevmx_64_address = 0x831B34E4
```

Xbox 360 binaries feature specialized register restore & save functions that act similarly to switch case fallthroughs. Every function that utilizes non-volatile registers either has an inlined version of these functions or explicitly calls them. The recompiler requires the starting address of each restore/save function in the TOML file to recompile them correctly. These functions could likely be auto-detected, but there is currently no mechanism for it.

Property|Description|Byte Pattern
-|-|-
restgprlr_14_address|Start address of the `__restgprlr_14` function. It starts with `ld r14, -0x98(r1)`, repeating the same operation for the rest of the non-volatile registers and restoring the link register at the end.|`e9 c1 ff 68`
savegprlr_14_address|Start address of the `__savegprlr_14` function. It starts with `std r14, -0x98(r1)`, repeating the same operation for the rest of the non-volatile registers and saving the link register at the end.|`f9 c1 ff 68`
restfpr_14_address|Start address of the `__restfpr_14` function. It starts with `lfd f14, -0x90(r12)`, repeating the same operation for the rest of the non-volatile FPU registers.|`c9 cc ff 70`
savefpr_14_address|Start address of the `__savefpr_14` function. It starts with `stfd r14, -0x90(r12)`, repeating the same operation for the rest of the non-volatile FPU registers.|`d9 cc ff 70`
restvmx_14_address|Start address of the `__restvmx_14` function. It starts with `li r11, -0x120` and `lvx v14, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers until `v31`.|`39 60 fe e0 7d cb 60 ce`
savevmx_14_address|Start address of the `__savevmx_14` function. It starts with `li r11, -0x120` and `stvx v14, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers until `v31`.|`39 60 fe e0 7d cb 61 ce`
restvmx_64_address|Start address of the `__restvmx_64` function. It starts with `li r11, -0x400` and `lvx128 v64, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers.|`39 60 fc 00 10 0b 60 cb`
savevmx_64_address|Start address of the `__savevmx_64` function. It starts with `li r11, -0x400` and `stvx128 v64, r11, r12`, repeating the same operation for the rest of the non-volatile VMX registers.|`39 60 fc 00 10 0b 61 cb`

#### longjmp & setjmp

```toml
longjmp_address = 0x831B6790
setjmp_address = 0x831B6AB0
```

These are addresses for the `longjmp` and `setjmp` functions in the executable. The recompiler directly redirects these functions to native versions. The implementation of these functions might vary between games. In some cases, you might find `longjmp` by looking for calls to `RtlUnwind`, and `setjmp` typically appears just after it.

If the game does not use these functions, you can remove the properties from the TOML file.

#### Explicit Function Boundaries

```toml
functions = [
    { address = 0x824E7EF0, size = 0x98 },
    { address = 0x824E7F28, size = 0x60 },
]
```

You can define function boundaries explicitly using the `functions` property if XenonAnalyse fails to analyze them correctly, for example, with functions containing jump tables.

#### Invalid Instruction Skips

```toml
invalid_instructions = [
    { data = 0x00000000, size = 4 }, # Padding
    { data = 0x831B1C90, size = 8 }, # C++ Frame Handler
    { data = 0x8324B3BC, size = 8 }, # C Specific Frame Handler
    { data = 0x831C8B50, size = 8 },
    { data = 0x00485645, size = 44 } # End of .text
]
```

In the `invalid_instructions` property, you can define 32-bit integer values that instruct the recompiler to skip over certain bytes when it encounters them. For example, in Unleashed Recompiled, these are used to skip over exception handling data, which is placed between functions but is not valid code.

#### Mid-asm Hooks

```toml
[[midasm_hook]]
name = "IndexBufferLengthMidAsmHook"
address = 0x82E26244
registers = ["r3"]
```

```cpp
void IndexBufferLengthMidAsmHook(PPCRegister& r3)
{
    // ...
}
```

You can define multiple mid-asm hooks in the TOML file, allowing the recompiler to insert function calls at specified addresses. When implementing them in your recompilation project, the linker will resolve the calls automatically.

Property|Description
-|-
name|Function name of the mid-asm hook. You can reuse function names to place the same implementation at multiple addresses. Otherwise, unique implementations must have unique names.
address|Address of the instruction where the function call will be placed. This does not overwrite the instruction at the specified address.
registers|Registers to pass as arguments to the mid-asm hook. This is a list of registers because the local variable optimization does not keep optimized registers within the PPC context struct.
return|Set to `true` to indicate that the function where the hook was inserted should immediately return after calling the mid-asm hook.
return_on_true|Set to `true` to indicate that the function should return if the mid-asm hook call returns `true`.
return_on_false|Set to `true` to indicate that the function should return if the mid-asm hook call returns `false`.
jump_address|The address to jump to immediately after calling the mid-asm hook. The address must be within the same function where the hook was placed.
jump_address_on_true|The address to jump to if the mid-asm hook returns `true`. The address must be within the same function where the hook was placed.
jump_address_on_false|The address to jump to if the mid-asm hook returns `false`. The address must be within the same function where the hook was placed.
after_instruction|Set to `true` to place the mid-asm hook immediately after the instruction, instead of before.

Certain properties are mutually exclusive. For example, you cannot use both `return` and `jump_address`, and direct or conditional returns/jumps cannot be mixed. The recompiler is going to show warnings if this is not followed.

### Tests

XenonRecomp can recompile Xenia's PPC tests and execute them through the XenonTests project in the repository. After building the tests using Xenia's build system, XenonRecomp can process the `src/xenia/cpu/ppc/testing/bin` directory as input, generating C++ files in the specified output directory:

```
XenonRecomp [input testing directory path] [input PPC context header file path] [output directory path]
```

Once the files are generated, refresh XenonTests' CMake cache to make them appear in the project. The tests can then be executed to compare the results of instructions against the expected values.

## Building

The project requires CMake 3.20 or later and Clang 18 or later to build. Since the repository includes submodules, ensure you clone it recursively.

Compilers other than Clang have not been tested and are not recommended, including for recompilation output. The project relies on compiler-specific intrinsics and techniques that may not function correctly on other compilers, and many optimization methods depend on Clang's code generation.

On Windows, you can use the clang-cl toolset and open the project in Visual Studio's CMake integration.

## Special Thanks

This project could not have been possible without the [Xenia](https://github.com/xenia-project/xenia) emulator, as many parts of the CPU code conversion process has been implemented by heavily referencing its PPC code translator. The project also uses code from [Xenia Canary](https://github.com/xenia-canary/xenia-canary) to patch XEX binaries.
