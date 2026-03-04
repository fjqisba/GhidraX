"""
Corresponds to: architecture.hh / architecture.cc

Manager for all the major decompiler subsystems.
An Architecture is tailored to a specific LoadImage, processor, and compiler spec.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional, List, Dict

from ghidra.core.address import Address, RangeList
from ghidra.core.space import (
    AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace, OtherSpace, JoinSpace,
    IPTR_PROCESSOR, IPTR_CONSTANT, IPTR_INTERNAL,
)
from ghidra.core.translate import Translate
from ghidra.core.pcoderaw import VarnodeData
from ghidra.core.opbehavior import OpBehavior
from ghidra.core.globalcontext import ContextDatabase, ContextInternal
from ghidra.types.datatype import TypeFactory
from ghidra.types.cast import CastStrategy, CastStrategyC
from ghidra.database.database import Database, ScopeInternal
from ghidra.database.comment import CommentDatabase, CommentDatabaseInternal
from ghidra.database.stringmanage import StringManager, StringManagerUnicode
from ghidra.database.cpool import ConstantPool, ConstantPoolInternal
from ghidra.fspec.fspec import ProtoModel, FuncProto
from ghidra.ir.typeop import TypeOp, registerTypeOps
from ghidra.output.printlanguage import PrintLanguage
from ghidra.output.printc import PrintC
from ghidra.output.prettyprint import EmitMarkup
from ghidra.transform.action import ActionDatabase
from ghidra.arch.loadimage import LoadImage
from ghidra.arch.userop import UserOpManage
from ghidra.arch.override import Override
from ghidra.arch.inject import PcodeInjectLibrary


class Architecture(AddrSpaceManager):
    """Manager for all the major decompiler subsystems.

    An instantiation is tailored to a specific LoadImage, processor,
    and compiler spec. This class is the owner of the LoadImage, Translate,
    symbols (Database), PrintLanguage, etc.
    """

    def __init__(self) -> None:
        super().__init__()
        self.archid: str = ""

        # Configuration data
        self.trim_recurse_max: int = 5
        self.max_implied_ref: int = 2
        self.max_term_duplication: int = 2
        self.max_basetype_size: int = 10
        self.min_funcsymbol_size: int = 1
        self.max_jumptable_size: int = 1024
        self.aggressive_ext_trim: bool = False
        self.readonlypropagate: bool = True
        self.infer_pointers: bool = True
        self.analyze_for_loops: bool = True
        self.nan_ignore_all: bool = False
        self.nan_ignore_compare: bool = False
        self.inferPtrSpaces: List[AddrSpace] = []
        self.funcptr_align: int = 0
        self.flowoptions: int = 0
        self.max_instructions: int = 100000
        self.alias_block_level: int = 2
        self.split_datatype_config: int = 0

        # Major subsystems
        self.symboltab: Optional[Database] = None
        self.context: Optional[ContextDatabase] = None
        self.protoModels: Dict[str, ProtoModel] = {}
        self.defaultfp: Optional[ProtoModel] = None
        self.defaultReturnAddr: VarnodeData = VarnodeData()
        self.evalfp_current: Optional[ProtoModel] = None
        self.evalfp_called: Optional[ProtoModel] = None
        self.types: Optional[TypeFactory] = None
        self.translate: Optional[Translate] = None
        self.loader: Optional[LoadImage] = None
        self.nohighptr: RangeList = RangeList()
        self.commentdb: Optional[CommentDatabase] = None
        self.stringManager: Optional[StringManager] = None
        self.cpool: Optional[ConstantPool] = None
        self.print_: Optional[PrintLanguage] = None
        self.printlist: List[PrintLanguage] = []
        self.options = None  # OptionDatabase
        self.inst: List[Optional[TypeOp]] = []
        self.allacts: ActionDatabase = ActionDatabase()
        self.userops: UserOpManage = UserOpManage()
        self.override: Optional[Override] = None
        self.pcodeinjectlib: Optional[PcodeInjectLibrary] = None
        self.loadersymbols_parsed: bool = False
        self.extra_pool_rules: list = []
        self.extra_pop: int = 0

    # --- Initialization ---

    def init(self) -> None:
        """Load the image and configure architecture.

        This is the main initialization entry point. Subclasses override
        the build* methods to customize each subsystem.
        """
        self.buildTypegrp()
        self.buildContext()
        self.buildDatabase()
        self.buildCommentDB()
        self.buildStringManager()
        self.buildConstantPool()
        self.buildInstructions()
        self.buildUserOps()
        self.buildInject()
        self.buildOptions()
        self.buildAction()
        self.setPrintLanguage("c-language")

    def buildTypegrp(self) -> None:
        """Build the data-type factory and prepopulate with core types."""
        self.types = TypeFactory()
        self.types.setupCoreTypes()

    def buildContext(self) -> None:
        """Build the Context database."""
        self.context = ContextInternal()

    def buildDatabase(self) -> None:
        """Build the database and global scope."""
        self.symboltab = Database(self)
        scope = self.symboltab.createGlobalScope("global")

    def buildCommentDB(self) -> None:
        """Build the comment database."""
        self.commentdb = CommentDatabaseInternal()

    def buildStringManager(self) -> None:
        """Build container for decoded strings."""
        self.stringManager = StringManagerUnicode(self, 256)

    def buildConstantPool(self) -> None:
        """Build the constant pool."""
        self.cpool = ConstantPoolInternal()

    def buildInstructions(self) -> None:
        """Register the p-code operations."""
        self.inst = registerTypeOps(self.types, self.translate)

    def buildUserOps(self) -> None:
        """Initialize user-defined p-code operations."""
        self.userops.initialize(self)

    def buildInject(self) -> None:
        """Build the p-code injection library."""
        self.pcodeinjectlib = PcodeInjectLibrary()

    def buildOptions(self) -> None:
        """Build the option database."""
        from ghidra.arch.options import OptionDatabase
        self.options = OptionDatabase(self)

    def buildAction(self) -> None:
        """Build the Action framework with the universal decompilation pipeline."""
        from ghidra.transform.universal import universalAction, buildDefaultGroups
        universalAction(self.allacts, self)
        buildDefaultGroups(self.allacts)
        self.allacts.setCurrent("decompile")

    def decompileFunction(self, fd) -> str:
        """Run the full decompilation pipeline on a Funcdata and return C output."""
        import io
        fd.setArch(self)
        # Ensure Architecture has a constant space
        if self._constantSpace is None:
            cs = ConstantSpace(self)
            self._insertSpace(cs)
            self._constantSpace = cs
        act = self.allacts.getCurrent()
        if act is not None:
            act.reset(fd)
            act.apply(fd)
        # Generate C output
        if self.print_ is not None:
            buf = io.StringIO()
            emit = EmitMarkup(buf)
            self.print_.setEmitter(emit)
            self.print_.docFunction(fd)
            return buf.getvalue()
        return ""

    # --- Prototype management ---

    def getModel(self, nm: str) -> Optional[ProtoModel]:
        return self.protoModels.get(nm)

    def hasModel(self, nm: str) -> bool:
        return nm in self.protoModels

    def setDefaultModel(self, model: ProtoModel) -> None:
        self.defaultfp = model

    def addModel(self, model: ProtoModel) -> None:
        self.protoModels[model.getName()] = model

    # --- Language selection ---

    def setPrintLanguage(self, nm: str) -> None:
        for pl in self.printlist:
            if pl.getName() == nm:
                self.print_ = pl
                return
        # Create default PrintC
        pc = PrintC(self, nm)
        emit = EmitMarkup()
        pc.setEmitter(emit)
        if self.types is not None:
            cs = CastStrategyC()
            cs.setTypeFactory(self.types)
            pc.setCastStrategy(cs)
        self.printlist.append(pc)
        self.print_ = pc

    def getPrintLanguage(self) -> Optional[PrintLanguage]:
        return self.print_

    # --- Accessors ---

    def getDescription(self) -> str:
        return self.archid

    def highPtrPossible(self, loc: Address, size: int) -> bool:
        if loc.getSpace() is not None and loc.getSpace().getType() == IPTR_INTERNAL:
            return False
        return not self.nohighptr.inRange(loc, size)

    def collectBehaviors(self) -> List[OpBehavior]:
        result = []
        for top in self.inst:
            if top is not None and top.getBehavior() is not None:
                result.append(top.getBehavior())
        return result

    def resetDefaults(self) -> None:
        self.trim_recurse_max = 5
        self.max_implied_ref = 2
        self.max_term_duplication = 2
        self.max_basetype_size = 10

    def clearAnalysis(self, fd) -> None:
        """Clear analysis specific to a function."""
        pass

    def createUnknownModel(self, modelName: str) -> Optional[ProtoModel]:
        """Create a model for an unrecognized name."""
        if self.defaultfp is not None:
            model = ProtoModel(modelName, self.defaultfp)
            self.protoModels[modelName] = model
            return model
        return None

    def getSpaceBySpacebase(self, loc: Address, size: int) -> Optional[AddrSpace]:
        """Get space associated with a spacebase register."""
        for spc in self._spaces:
            if spc is not None and hasattr(spc, 'numSpacebase') and spc.numSpacebase() > 0:
                for i in range(spc.numSpacebase()):
                    base = spc.getSpacebase(i)
                    if base.getAddr() == loc and base.size == size:
                        return spc
        return None

    def getLanedRegister(self, loc: Address, size: int):
        """Get LanedRegister associated with storage."""
        return None  # Requires lanerecords

    def getMinimumLanedRegisterSize(self) -> int:
        """Get the minimum size of a laned register in bytes."""
        return 0

    def getStackSpace(self) -> Optional[AddrSpace]:
        """Get the stack address space, if it exists."""
        for spc in self._spaces:
            if spc is not None and hasattr(spc, 'getType'):
                from ghidra.core.space import IPTR_SPACEBASE
                if spc.getType() == IPTR_SPACEBASE:
                    return spc
        return None

    def readLoaderSymbols(self, delim: str = "") -> None:
        """Read any symbols from loader into database."""
        self.loadersymbols_parsed = True

    def getSegmentOp(self, spc: AddrSpace):
        """Retrieve the segment op for the given space if any."""
        return None

    def setPrototype(self, pieces) -> None:
        """Set the prototype for a particular function."""
        pass

    def globalify(self) -> None:
        """Mark all spaces as global."""
        if self.symboltab is not None:
            scope = self.symboltab.getGlobalScope()
            if scope is not None:
                for spc in self._spaces:
                    if spc is not None and hasattr(spc, 'isHeritaged') and spc.isHeritaged():
                        pass  # Would add range to scope

    def decodeFlowOverride(self, decoder) -> None:
        """Decode flow overrides from a stream."""
        pass

    def encode(self, encoder) -> None:
        """Encode this architecture to a stream."""
        pass

    def restoreXml(self, store) -> None:
        """Restore the Architecture state from XML documents."""
        pass

    def nameFunction(self, addr: Address) -> str:
        """Pick a default name for a function."""
        return f"func_{addr.getOffset():08x}"

    def addSpacebase(self, basespace, nm: str, ptrdata, truncSize: int = 0,
                     isreversejustified: bool = False, stackGrowth: bool = True,
                     isFormal: bool = False) -> None:
        """Add a spacebase register mapping."""
        pass

    def addNoHighPtr(self, rng) -> None:
        """Add a new region where pointers do not exist."""
        if rng is not None:
            self.nohighptr.insertRange(rng)

    # --- Protected factory routines ---

    def buildTranslator(self, store=None):
        """Build the Translator object."""
        return self.translate

    def buildLoader(self, store=None) -> None:
        """Build the LoadImage object and load the executable image."""
        pass

    def buildPcodeInjectLibrary(self):
        """Build the injection library."""
        return PcodeInjectLibrary()

    def buildCoreTypes(self, store=None) -> None:
        """Add core primitive data-types."""
        if self.types is not None:
            self.types.setupCoreTypes()

    def buildSymbols(self, store=None) -> None:
        """Build any symbols from spec files."""
        pass

    def buildSpecFile(self, store=None) -> None:
        """Load any relevant specification files."""
        pass

    def modifySpaces(self, trans=None) -> None:
        """Modify address spaces as required by this Architecture."""
        pass

    def postSpecFile(self) -> None:
        """Let components initialize after Translate is built."""
        pass

    def resolveArchitecture(self) -> None:
        """Figure out the processor and compiler of the target executable."""
        pass

    def restoreFromSpec(self, store=None) -> None:
        """Fully initialize the Translate object."""
        pass

    def fillinReadOnlyFromLoader(self) -> None:
        """Load info about read-only sections."""
        pass

    def initializeSegments(self) -> None:
        """Set up segment resolvers."""
        pass

    def cacheAddrSpaceProperties(self) -> None:
        """Calculate some frequently used space properties and cache them."""
        pass

    def createModelAlias(self, aliasName: str, parentName: str) -> None:
        """Create name alias for a ProtoModel."""
        parent = self.protoModels.get(parentName)
        if parent is not None:
            self.protoModels[aliasName] = parent

    def resetDefaultsInternal(self) -> None:
        """Reset default values for options specific to Architecture."""
        self.trim_recurse_max = 5
        self.max_implied_ref = 2
        self.max_term_duplication = 2
        self.max_basetype_size = 10
        self.min_funcsymbol_size = 1
        self.max_jumptable_size = 1024
        self.aggressive_ext_trim = False
        self.readonlypropagate = True
        self.infer_pointers = True
        self.analyze_for_loops = True
        self.nan_ignore_all = False
        self.nan_ignore_compare = False

    # --- Decode/parse configuration methods ---

    def parseProcessorConfig(self, store=None) -> None:
        """Apply processor specific configuration."""
        pass

    def parseCompilerConfig(self, store=None) -> None:
        """Apply compiler specific configuration."""
        pass

    def parseExtraRules(self, store=None) -> None:
        """Apply any Rule tags."""
        pass

    def decodeDynamicRule(self, decoder) -> None:
        """Apply details of a dynamic Rule object."""
        pass

    def decodeProto(self, decoder) -> Optional[ProtoModel]:
        """Parse a proto-type model from a stream."""
        return None

    def decodeProtoEval(self, decoder) -> None:
        """Apply prototype evaluation configuration."""
        pass

    def decodeDefaultProto(self, decoder) -> None:
        """Apply default prototype model configuration."""
        pass

    def decodeGlobal(self, decoder, rangeProps: list = None) -> None:
        """Parse information about global ranges."""
        pass

    def decodeReadOnly(self, decoder) -> None:
        """Apply read-only region configuration."""
        pass

    def decodeVolatile(self, decoder) -> None:
        """Apply volatile region configuration."""
        pass

    def decodeReturnAddress(self, decoder) -> None:
        """Apply return address configuration."""
        pass

    def decodeStackPointer(self, decoder) -> None:
        """Apply stack pointer configuration."""
        pass

    def decodeDeadcodeDelay(self, decoder) -> None:
        """Apply dead-code delay configuration."""
        pass

    def decodeInferPtrBounds(self, decoder) -> None:
        """Apply pointer inference bounds."""
        pass

    def decodeFuncPtrAlign(self, decoder) -> None:
        """Apply function pointer alignment configuration."""
        pass

    def decodeSpacebase(self, decoder) -> None:
        """Create an additional indexed space."""
        pass

    def decodeNoHighPtr(self, decoder) -> None:
        """Apply memory alias configuration."""
        pass

    def decodePreferSplit(self, decoder) -> None:
        """Designate registers to be split."""
        pass

    def decodeAggressiveTrim(self, decoder) -> None:
        """Designate how to trim extension p-code ops."""
        pass

    def decodeIncidentalCopy(self, decoder) -> None:
        """Apply incidental copy configuration."""
        pass

    def decodeRegisterData(self, decoder) -> None:
        """Read specific register properties."""
        pass

    def printMessage(self, message: str) -> None:
        """Print an error message to console."""
        print(f"[Architecture] {message}")

    def __repr__(self) -> str:
        return f"Architecture({self.archid!r})"
