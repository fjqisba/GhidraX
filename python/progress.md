# PyGhidra Progress

## Completed Modules (39 Python + sleigh_native.pyd)

### core/ (14 files)
- address.py, error.py, expression.py, float_format.py, globalcontext.py
- int128.py, marshal.py, opbehavior.py, opcodes.py, pcoderaw.py
- space.py, translate.py, types.py

### ir/ (5 files)
- cover.py, op.py, typeop.py (with push() dispatch), variable.py, varnode.py

### transform/ (21 files)
- action.py, condexe.py, coreaction.py, coreaction2.py, deadcode.py
- nzmask.py, ruleaction.py + batch1a-1i + batch2a-2c, universal.py
- **136/136 rules (130 real), 62/62 Actions**

### output/ (3 files) — **JUST REWRITTEN**
- prettyprint.py: Emit, EmitMarkup, SyntaxHighlight, tagCaseLabel, brace helpers
- printlanguage.py: **RPN stack** (ReversePolish, Atom, NodePending, pushOp/pushAtom/pushVn, parentheses, emitOp/emitAtom, recurse, opBinary/opUnary)
- printc.py: **50+ OpTokens**, 70+ opXxx handlers, pushConstant/Symbol/Type, 11 block emitters, docFunction

### analysis/ (5 files)
- dynamic.py, flow.py, funcdata.py, heritage.py, merge.py

### block/ (2 files)
- block.py (10 block types), collapse.py

### database/ (4 files)
- database.py, comment.py, cpool.py, stringmanage.py

### types/ (2 files)
- datatype.py (TypeFactory, 18 metatypes), cast.py (CastStrategyC/Java)

### fspec/ (2 files)
- fspec.py (FuncProto, ProtoModel, FuncCallSpecs), paramactive.py

### arch/ (2 files)
- architecture.py, loadimage.py

### sleigh/ (4 files + .pyd)
- lifter.py, slaformat.py, sleigh.py, sleighbase.py
- sleigh_native.cp314-win_amd64.pyd (pybind11, zlib static)

### emulate/ (2 files)
- emulate.py, memstate.py

## End-to-End Pipeline
```
x86 binary → sleigh_native.pyd → P-code → Funcdata → 136 rules + 62 Actions → Heritage SSA → PrintC (RPN stack) → C output
```

## Current Session: RPN Stack Architecture (Phases 1-5 DONE)

1. **PrintLanguage RPN Core** — pushOp/pushAtom/pushVn/recurse/emitOp/emitAtom/parentheses
2. **PrintC 50+ OpTokens** — correct precedence/associativity/spacing
3. **PrintC 70+ opXxx handlers** — all INT/BOOL/FLOAT/control-flow/memory ops
4. **PrintC block emission** — 11 emitBlock* methods + docFunction
5. **TypeOp.push()** — 70+ opcode→handler dispatch bridge
6. **Emit infrastructure** — tagCaseLabel, brace helpers, indent/comment

## Remaining Gaps vs C++ Ghidra

### High Priority
- [x] EmitPrettyPrint (simplified Oppen, line-width tracking + break insertion)
- [x] FlowBlock.emit() on all 10 block types (BlockBasic/Copy/Goto/Condition/If/WhileDo/DoWhile/InfLoop/Switch/List)
- [x] Block helpers: getBlock/getSize/nextInFlow/isJumpTarget/getFrontLeaf/gotoPrints/getSwitchBlock/getCaseBlock etc.
- [x] PrintC: emitInplaceOp (+=, -=, *=, /=, %=, <<=, >>=, &=, |=, ^=)
- [x] PrintC: emitLocalVarDecls (iterate HighVariables from VarnodeBank)
- [x] PrintC: emitVarDecl/emitVarDeclStatement
- [x] PrintC: opPtrsub with struct/union field access (-> / . syntax)
- [x] PrintC: pushPartialSymbol with field traversal (a.b.c syntax)
- [x] PrintC: checkArrayDeref + opLoad/opStore array syntax
- [x] PrintC: opPtradd with array subscript [] syntax
- [x] PrintC: pushPtrCharConstant, pushPtrCodeConstant, pushEquate
- [x] PrintC: checkAddressOfCast (& operator on array casts)
- [x] CommentSorter (setupFunctionList/BlockList/OpList/Header, hasNext/getNext)
- [x] options.py — OptionDatabase + 39 ArchOption classes (extrapop, nullprinting, inplaceops, nocast, etc.)
- [x] userop.py — UserPcodeOp + UserOpManage registry (UnspecializedPcodeOp, InjectedUserOp, VolatileRead/Write)

### Medium Priority
- [x] override.py — Override system (forcegoto, deadcode delay, indirect/proto override, flow override, multistage)
- [x] inject.py — PcodeInjectLibrary (InjectPayload, InjectContext, call/callother fixups)
- [x] jumptable.py — JumpTable, JumpModel, JumpModelTrivial, LoadTable, PathMeld, GuardRecord
- [x] rangeutil.py — CircleRange (intersect/union/contains/pullBack/pushForward/setNZMask)
- [x] subflow.py — SubvariableFlow (trace/replace sub-register logical values)
- [x] varmap.py — ScopeLocal, MapState, RangeHint, NameRecommend, DynamicRecommend, TypeRecommend
- [x] double.py — SplitVarnode + AddForm/SubForm/LogicalForm/ShiftForm/MultForm
- [x] constseq.py — ConstSequence for constant store detection (string/array init)
- [x] prefersplit.py — PreferSplitRecord + LanedRegister + PreferSplitManager
- [x] resolve.py — ResolvedUnion + UnionResolveMap for union field resolution
- [x] Architecture wired: UserOpManage, OptionDatabase, PcodeInjectLibrary, Override
- [x] test_printc_rpn.py — 12 RPN stack tests (binary/parens/unary/deref/subscript/arrow/dot/cast/assign/int/bool)
- [x] blockaction.py — FloatingEdge, LoopBody, CollapseStructure (sequence collapsing)
- [x] Funcdata wired: getVarnodeBank, getOverride, JumpTable, UnionResolveMap, getFirstReturnOp
- [x] VarnodeBank.allVarnodes() iterator
- [x] PrintC: emitLabel/emitLabelStatement/emitAnyLabelStatement/emitGotoStatement (break/continue/goto)
- [x] PrintC: emitForLoop with for(init;cond;iter) + auto-detect in emitBlockWhileDo
- [x] PrintC: CommentSorter wired into docFunction (emitCommentFuncHeader/emitCommentGroup/emitLineComment)
- [x] PrintC: emitSwitchCase with tagCaseLabel + data-type constants + break for exit cases
- [x] emitBlockBasic: comment wiring, label emission, only_branch mode, flat nofallthru goto
- [x] emitBlockWhileDo: overflow syntax (while(true) { body; if(cond) break; })
- [x] emitBlockLs: proper no_branch/nofallthru/nextInFlow flow control (matches C++ exactly)
- [x] emitBlockIf: else-if chain merging via pending_brace (else if syntax)
- [x] emitBlockCondition: RPN-based && || operator emission
- [x] emitBlockDoWhile + emitBlockInfLoop: emitAnyLabelStatement added
- [x] opReturn: halt/baddata/unimplemented/missing variants
- [x] opCall: improved name lookup from Funcdata callspecs
- [x] opCallind: hidden this parameter handling via callspecs
- [x] opSubpiece: field extraction via doesSpecialPrinting + isPieceStructured
- [x] pushCharConstant: emit 'A', '\\n' etc for character-typed constants
- [x] pushEnumConstant: emit ENUM_NAME for enum-typed constants
- [x] pushConstant: wired isCharPrint/isEnumType detection for TYPE_UINT/TYPE_INT
- [x] opIntZext/opIntSext: castStrategy-based hide-extension logic (opHiddenFunc for implied)
- [x] opFloatInt2Float: ZEXT absorption pattern from C++
- [x] printUnicode + printCharHexEscape methods for string/char emission
- [x] opFloatInt2Float: ZEXT absorption pattern from C++
- [x] opCbranch: isFallthruTrue + falsebranch + negatetoken chain for flat mode
- [x] emitBlockCopy: emitAnyLabelStatement + sub.emit() virtual dispatch
- [x] graph.py — DominatorTree + LoopDetector + IntervalGraph + SCCDetector (4 algorithms)
- [x] opCallother: annotation_assignment/no_operator/display_string display modes
- [x] opNewOp: new Type[size] array allocation syntax
- [x] docAllGlobals: emit global variable declarations recursively
- [x] docTypeDefinitions + emitStructDefinition + emitEnumDefinition
- [x] pushTypeStart/End: full type stack with ptr/array/code adornments + pushPrototypeInputs_rpn
- [x] docSingleGlobal: emit single global symbol declaration
- [x] emitCommentBlockTree: recursive comment emission within control-flow subtree
- [x] setCommentStyle/setCStyleComments/setCPlusPlusStyleComments
- [x] initializeFromArchitecture: sizeSuffix from long/int sizes + castStrategy wiring
- [x] adjustTypeOperators: scope/shift operator configuration
- [x] emitPrototypeOutput: output type with return varnode link
- [x] emitFunctionDeclaration: beginFuncProto + convention printing + scope push + openGroup
- [x] emitExpression: constructor/new syntax for doesSpecialPrinting ops
- [x] resetDefaultsPrintC + resetDefaults override + setCStyleComments
- [x] docFunction: popScope after emitBlockGraph + flat mode support
- [x] emitBlockIf: emitCommentBlockTree after condition block + condBlock.emit()
- [x] emitBlockWhileDo: emitCommentBlockTree + condBlock.emit() in normal path
- [x] emitBlockGoto: sub.emit() for proper virtual dispatch
- [x] Funcdata getScopeLocal alias added
- [x] pushSymbolScope/emitSymbolScope: namespace resolution with depth calculation
- [x] pushSymbol: syntax highlighting by category (volatile/global/param/var) + scope resolution
- [x] Funcdata getCallSpecs(op): fast PcodeOp→FuncCallSpecs lookup with _qlst_map cache
- [x] Funcdata addCallSpecs(fc): register with _qlst_map

**PrintC printc.cc 100% ported — ALL methods from C++ now in Python (~2500 lines)**

### Latest Session Additions
- [x] pushImpliedField: full field.subfield access with type traversal for hasImpliedField varnodes
- [x] opConstructor: full withNew=True for new Type(args) syntax with ptr deref
- [x] opCall: emitSymbolScope wired for function namespace resolution in calls
- [x] All block emitters converted to .emit() for proper virtual dispatch (no more _emitBlockDispatch for blocks)
- [x] emitBlockDoWhile: bl.getBlock(0).emit() for both body and condition
- [x] emitBlockWhileDo: bl.getBlock(1).emit() for body
- [x] emitBlockForLoop: bl.getBlock(1).emit() for body
- [x] PrintLanguage: escapeCharacterData + setPackedOutput
- [x] Funcdata: getCallSpecs with _qlst_map cache + addCallSpecs + getScopeLocal alias
- [x] emitStatement: CommentSorter wired via emitCommentGroup before each statement
- [x] opCpoolRefOp: full 7-tag dispatch (string/class/method/field/array_length/instanceof/check_cast)
- [x] opInsertOp/opExtractOp: bitfield emission with doesSpecialPrinting + isPieceStructured
- [x] type_instanceOf OpToken added for Java instanceof
- [x] emitBlockSwitch: emitAnyLabelStatement at top
- [x] emitBlockBasic: cleaned duplicate emitCommentGroup (now in emitStatement)
- [x] emitBlockGraph: sub.emit() replaces _emitBlockDispatch fallback
- [x] printCharacterConstant + doEmitWideCharPrefix (u/U/L prefixes)
- [x] getHiddenThisSlot: detect hidden this parameter in calls
- [x] emitPrototypeInputs: fixed first param + RPN pushTypeStart/End + dotdotdot
- [x] opCallother display_string: StringManager lookup for InternalStringOp
- [x] emitBlockSwitch: emitCommentBlockTree for switch header condition
- [x] opPtrsub: checkAddressOfCast wired for array addressof elimination
- [x] opCallother outvn bug fix
- [x] opCall: getHiddenThisSlot wired for hidden this skipping in direct calls
- [x] StringManager getString(addr): quoted string lookup for opCallother display_string
- [x] Funcdata.clear(): clears _qlst_map/_override/_unionMap on restart
- [x] opPtrsub ARRAY: subscript [] syntax when print_load/store_value set

### Low Priority (Ghidra-specific interfaces)
- [ ] ghidra_arch/context/translate/process
- [ ] database_ghidra, comment_ghidra, cpool_ghidra
- [ ] consolemain (CLI frontend)
