cmake_minimum_required(VERSION 3.15)
project(sleigh_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ---- Find Python + pybind11 ----
# Auto-detect from PATH / environment.  Override with:
#   -DPython_EXECUTABLE=<path>
#   -Dpybind11_DIR=<path>
find_package(Python REQUIRED COMPONENTS Interpreter Development)
find_package(pybind11 CONFIG REQUIRED)

# ---- zlib ----
# Try vcpkg / system first; fall back to manual ZLIB_ROOT hint.
#   -DZLIB_ROOT=<path>          (prefix containing include/ and lib/)
#   -DCMAKE_TOOLCHAIN_FILE=...  (vcpkg toolchain)
find_package(ZLIB REQUIRED)

# ---- SLEIGH core sources (from Makefile LIBSLA_NAMES) ----
# CORE
set(CORE_SRC
    xml.cc marshal.cc space.cc float.cc address.cc pcoderaw.cc
    translate.cc opcodes.cc globalcontext.cc
)
# SLEIGH decoder
set(SLEIGH_SRC
    sleigh.cc pcodeparse.cc pcodecompile.cc sleighbase.cc slghsymbol.cc
    slghpatexpress.cc slghpattern.cc semantics.cc context.cc
    slaformat.cc compression.cc filemanage.cc
)
# Extra needed by SLEIGH runtime
set(EXTRA_SRC
    loadimage.cc memstate.cc emulate.cc opbehavior.cc
)

# ---- pybind11 module ----
pybind11_add_module(sleigh_native
    sleigh_bind.cpp
    ${CORE_SRC}
    ${SLEIGH_SRC}
    ${EXTRA_SRC}
)

target_include_directories(sleigh_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sleigh_native PRIVATE ZLIB::ZLIB)

# Windows-specific: suppress some warnings
if(MSVC)
    target_compile_definitions(sleigh_native PRIVATE _WINDOWS _CRT_SECURE_NO_WARNINGS)
    target_compile_options(sleigh_native PRIVATE /W3 /wd4267 /wd4244 /wd4018 /wd4804 /wd4805 /EHsc)
endif()

# GCC / Clang warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(sleigh_native PRIVATE -Wall -Wno-sign-compare -Wno-unused-parameter)
endif()

# Install the .pyd / .so into the python package
install(TARGETS sleigh_native
    LIBRARY DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/../python/ghidra/sleigh"
    RUNTIME DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/../python/ghidra/sleigh"
)

# ============================================================
# decompiler_native — full Ghidra decompiler as a Python module
# ============================================================

# All decompiler sources (excluding ghidra server, BFD, console, test files)
set(DECOMP_SRC
    # Core infrastructure
    xml.cc marshal.cc space.cc float.cc address.cc pcoderaw.cc
    translate.cc opcodes.cc globalcontext.cc capability.cc error.hh types.h
    # SLEIGH engine
    sleigh.cc pcodeparse.cc pcodecompile.cc sleighbase.cc slghsymbol.cc
    slghpatexpress.cc slghpattern.cc semantics.cc context.cc
    slaformat.cc compression.cc filemanage.cc
    # Emulation/LoadImage
    loadimage.cc memstate.cc emulate.cc emulateutil.cc opbehavior.cc
    # Architecture
    architecture.cc sleigh_arch.cc raw_arch.cc
    # P-code inject
    inject_sleigh.cc pcodeinject.cc
    # Type system
    type.cc cast.cc
    # Database / Symbols
    database.cc comment.cc cpool.cc crc32.cc stringmanage.cc
    # Function data
    funcdata.cc funcdata_block.cc funcdata_op.cc funcdata_varnode.cc
    # Analysis
    flow.cc heritage.cc merge.cc cover.cc block.cc blockaction.cc
    op.cc varnode.cc variable.cc
    dynamic.cc graph.cc
    # Actions / Rules
    action.cc coreaction.cc ruleaction.cc rulecompile.cc
    condexe.cc double.cc subflow.cc constseq.cc
    # Function spec
    fspec.cc paramid.cc modelrules.cc
    # Output
    prettyprint.cc printlanguage.cc printc.cc printjava.cc
    # Override / Options
    override.cc options.cc
    # Varmap / Range
    varmap.cc rangeutil.cc prefersplit.cc
    # Jump tables
    jumptable.cc
    # Expression / String
    expression.cc
    # Union resolve
    unionresolve.cc
    # Transforms
    transform.cc
    # Userop
    userop.cc
    # Signatures (if present and not server-dependent)
    # signature.cc
    # Grammar
    grammar.cc
    # Interface (decompiler library, not console)
    ifacedecomp.cc
    libdecomp.cc
    # Multiprecision
    multiprecision.cc
    # Loadimage XML
    loadimage_xml.cc
)

pybind11_add_module(decompiler_native
    decompiler_bind.cpp
    ${DECOMP_SRC}
)

target_include_directories(decompiler_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(decompiler_native PRIVATE ZLIB::ZLIB)

if(MSVC)
    target_compile_definitions(decompiler_native PRIVATE _WINDOWS _CRT_SECURE_NO_WARNINGS)
    target_compile_options(decompiler_native PRIVATE /W3 /wd4267 /wd4244 /wd4018 /wd4804 /wd4805 /wd4146 /wd4805 /EHsc /bigobj)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(decompiler_native PRIVATE -Wall -Wno-sign-compare -Wno-unused-parameter)
endif()

install(TARGETS decompiler_native
    LIBRARY DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/../python/ghidra/sleigh"
    RUNTIME DESTINATION "${CMAKE_CURRENT_SOURCE_DIR}/../python/ghidra/sleigh"
)
