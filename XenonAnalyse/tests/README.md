# XenonAnalyse tests

Synthetic hand-crafted PPC bytecode fixtures for `Function::Analyze`'s
switch-aware block walker.

## Fixtures

`switch_aware_walker_test.cpp` exercises three scenarios against a
synthetic 4-case absolute-form switch function built in-source from
hand-emitted big-endian instruction words:

1. **Happy path** — `switchMap` populated. Walker pushes all 4 labels
   + default as successor blocks, `fn.size` extends to cover through
   the default block.
2. **Null-map safety** — `switchMap = nullptr`. Walker uses legacy
   pre-patch behavior; discontinuity pass erases the label blocks;
   `fn.size` covers only the pre-bctr head.
3. **Wrong-map miss** — `switchMap` populated, but with an entry for
   an unrelated bctr VA. `switchMap->find(our_bctr)` returns `end()`;
   walker falls through to legacy behavior.

All three assert on `fn.size` landing in the expected range. The
tests use `assert`-style `fprintf(stderr, "[FAIL ...]" ...) + return 1`
rather than a framework, to keep the test self-contained (no new
dependencies).

## Running

Compile against a built `LibXenonAnalyse` + `XenonUtils` + `disasm` +
`fmt`. Example (from a VS 2022 Developer Command Prompt with LLVM in
PATH, after building the rest of the tree):

```
cd XenonAnalyse/tests
clang-cl /std:c++20 /EHsc /nologo ^
  /I"..\" /I"..\..\XenonUtils" ^
  switch_aware_walker_test.cpp ^
  "..\..\build\XenonAnalyse\LibXenonAnalyse.lib" ^
  "..\..\build\XenonUtils\XenonUtils.lib" ^
  "..\..\build\thirdparty\disasm\disasm.lib" ^
  "..\..\build\thirdparty\fmt\fmt.lib" ^
  /link /OUT:walker_test.exe
walker_test.exe
```

Expected:

```
[ok   happy-path] fn.base=0x10000, fn.size=0x38, blocks=7
[ok   null-map ] fn.base=0x10000, fn.size=0x1C (pre-patch truncation preserved)
[ok   wrong-map] fn.base=0x10000, fn.size=0x1C (unrelated map entry correctly ignored)

All 3 tests PASSED
```

## CMake integration

Not included in this commit. If the repository adopts a test-runner
pattern, a minimal CMake shape would be:

```cmake
add_executable(xenonanalyse_switch_walker_test switch_aware_walker_test.cpp)
target_link_libraries(xenonanalyse_switch_walker_test PRIVATE LibXenonAnalyse)
add_test(NAME switch_walker COMMAND xenonanalyse_switch_walker_test)
```

Or as an opt-in build behind `-DXENONANALYSE_TESTS=ON`. Whatever
convention the repository prefers.
