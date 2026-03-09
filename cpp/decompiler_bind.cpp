/**
 * decompiler_bind.cpp — pybind11 binding for the full Ghidra C++ decompiler
 *
 * Exposes a single high-level Python class `DecompilerNative` that:
 *   1. Initializes the decompiler library with spec file paths
 *   2. Accepts raw binary bytes + architecture info
 *   3. Decompiles a function at a given entry point
 *   4. Returns the C source code as a string
 *
 * Build as: decompiler_native.pyd
 */

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <sstream>
#include <string>
#include <vector>
#include <cstring>

#include "libdecomp.hh"
#include "raw_arch.hh"
#include "sleigh_arch.hh"
#include "loadimage.hh"
#include "printc.hh"
#include "funcdata.hh"
#include "flow.hh"
#include "coreaction.hh"

namespace py = pybind11;

using namespace ghidra;

// ---------------------------------------------------------------------------
// Custom LoadImage backed by a raw byte buffer (from Python)
// ---------------------------------------------------------------------------
class BufferImage : public LoadImage {
    const uint1 *buf_;
    int4 bufsize_;
    AddrSpace *spc_;
    uintb baseaddr_;
public:
    BufferImage(uintb baseaddr)
        : LoadImage("nofile"), buf_(nullptr), bufsize_(0), spc_(nullptr), baseaddr_(baseaddr) {}

    void setData(const uint1 *data, int4 sz) { buf_ = data; bufsize_ = sz; }
    void attachToSpace(AddrSpace *s) { spc_ = s; }

    void loadFill(uint1 *ptr, int4 size, const Address &addr) override {
        uintb off = addr.getOffset();
        if (off < baseaddr_ || buf_ == nullptr) {
            memset(ptr, 0, size);
            return;
        }
        uintb rel = off - baseaddr_;
        for (int4 i = 0; i < size; ++i) {
            if ((int4)(rel + i) < bufsize_)
                ptr[i] = buf_[rel + i];
            else
                ptr[i] = 0;
        }
    }

    string getArchType(void) const override { return "buffer"; }
    void adjustVma(long adjust) override {}
};

// ---------------------------------------------------------------------------
// Custom Architecture that uses our BufferImage
// ---------------------------------------------------------------------------
class BufferArchitecture : public SleighArchitecture {
    BufferImage *bufimg_;
    uintb baseaddr_;
public:
    BufferArchitecture(const string &slapath, const string &target,
                       uintb baseaddr, ostream *estream)
        : SleighArchitecture(slapath, target, estream),
          bufimg_(nullptr), baseaddr_(baseaddr) {}

    void setImageData(const uint1 *data, int4 sz) {
        if (bufimg_) bufimg_->setData(data, sz);
    }

protected:
    void buildLoader(DocumentStorage &store) override {
        collectSpecFiles(*errorstream);
        bufimg_ = new BufferImage(baseaddr_);
        loader = bufimg_;
    }

    void resolveArchitecture(void) override {
        archid = getTarget();
        SleighArchitecture::resolveArchitecture();
    }

    void postSpecFile(void) override {
        Architecture::postSpecFile();
        if (bufimg_)
            bufimg_->attachToSpace(getDefaultCodeSpace());
    }
};

// ---------------------------------------------------------------------------
// Main Python-facing class
// ---------------------------------------------------------------------------
class DecompilerNative {
    bool initialized_;
    vector<string> specpaths_;     // flat directories (direct addDir2Path)
    vector<string> ghidraroots_;   // Ghidra-layout roots (scanForSleighDirectories)
    ostringstream errstream_;

public:
    DecompilerNative() : initialized_(false) {}

    void addSpecPath(const string &path) {
        specpaths_.push_back(path);
    }

    void addGhidraRoot(const string &path) {
        ghidraroots_.push_back(path);
    }

    void initialize() {
        if (initialized_) return;
        // Initialize core decompiler subsystems
        AttributeId::initialize();
        ElementId::initialize();
        CapabilityPoint::initializeAll();
        ArchitectureCapability::sortCapabilities();

        // Scan Ghidra-layout directories (Ghidra/<proc>/data/languages/)
        for (const auto &root : ghidraroots_)
            SleighArchitecture::scanForSleighDirectories(root);

        // Add flat spec directories directly
        for (const auto &p : specpaths_)
            SleighArchitecture::specpaths.addDir2Path(p);

        initialized_ = true;
    }

    string decompile(const string &slapath,
                     const string &target,
                     const py::bytes &image,
                     uintb baseaddr,
                     uintb entry,
                     int4 funcsize) {
        try {
            if (!initialized_) initialize();
        } catch (LowlevelError &e) {
            throw std::runtime_error(string("Init error: ") + e.explain);
        } catch (std::exception &e) {
            throw std::runtime_error(string("Init error: ") + e.what());
        }

        errstream_.str("");
        errstream_.clear();

        // Get raw bytes from Python
        string imgstr = image;
        const uint1 *imgdata = (const uint1 *)imgstr.data();
        int4 imgsize = (int4)imgstr.size();

        // Build architecture
        try {
            BufferArchitecture arch(slapath, target, baseaddr, &errstream_);
            DocumentStorage store;
            arch.init(store);
            arch.setImageData(imgdata, imgsize);

            // Create the action group and set it as current
            arch.allacts.universalAction(&arch);
            arch.allacts.resetDefaults();

            // Find or create the function
            Address funcEntry(arch.getDefaultCodeSpace(), entry);
            Funcdata *fd = arch.symboltab->getGlobalScope()->findFunction(funcEntry);
            if (fd == nullptr) {
                string funcname = "func_" + to_string(entry);
                arch.symboltab->getGlobalScope()->addFunction(funcEntry, funcname);
                fd = arch.symboltab->getGlobalScope()->findFunction(funcEntry);
                if (fd == nullptr) {
                    throw std::runtime_error("Could not create function at 0x" + to_string(entry));
                }
            }

            // Run the decompiler action pipeline
            Action *act = arch.allacts.getCurrent();
            if (act == nullptr) {
                throw std::runtime_error("No current action set");
            }
            act->reset(*fd);
            int4 res = act->perform(*fd);
            if (res < 0) {
                throw std::runtime_error("Decompilation incomplete (breakpoint)");
            }

            // Print the result
            ostringstream codestream;
            arch.print->setOutputStream(&codestream);
            arch.print->docFunction(fd);

            return codestream.str();
        } catch (LowlevelError &e) {
            throw std::runtime_error(string("Decompiler error: ") + e.explain +
                                     "\nInternal log: " + errstream_.str());
        } catch (DecoderError &e) {
            throw std::runtime_error(string("Decoder error: ") + e.explain +
                                     "\nInternal log: " + errstream_.str());
        } catch (std::runtime_error &) {
            throw;  // re-throw our own runtime_errors
        } catch (std::exception &e) {
            throw std::runtime_error(string("C++ exception: ") + e.what() +
                                     "\nInternal log: " + errstream_.str());
        } catch (...) {
            throw std::runtime_error(string("Unknown C++ exception") +
                                     "\nInternal log: " + errstream_.str());
        }
    }

    string getErrors() const {
        return errstream_.str();
    }
};

// ---------------------------------------------------------------------------
// pybind11 module definition
// ---------------------------------------------------------------------------
PYBIND11_MODULE(decompiler_native, m) {
    m.doc() = "Native Ghidra decompiler engine (full C++ pipeline)";

    py::class_<DecompilerNative>(m, "DecompilerNative")
        .def(py::init<>())
        .def("add_spec_path", &DecompilerNative::addSpecPath,
             "Add a flat directory containing .ldefs/.pspec/.cspec files")
        .def("add_ghidra_root", &DecompilerNative::addGhidraRoot,
             "Add a Ghidra-layout root (scans <root>/Ghidra/*/data/languages/)")
        .def("initialize", &DecompilerNative::initialize,
             "Initialize the decompiler library")
        .def("decompile", &DecompilerNative::decompile,
             py::arg("sla_path"),
             py::arg("target"),
             py::arg("image"),
             py::arg("base_addr"),
             py::arg("entry"),
             py::arg("func_size") = 0,
             "Decompile a function from raw binary bytes.\n"
             "Returns C source code as a string.\n\n"
             "Args:\n"
             "  sla_path: Path to the .sla file\n"
             "  target: Language id (e.g. 'x86:LE:64:default')\n"
             "  image: Raw binary bytes\n"
             "  base_addr: Base address of the image\n"
             "  entry: Entry point address of the function\n"
             "  func_size: Size hint (0 = auto-detect)\n")
        .def("get_errors", &DecompilerNative::getErrors,
             "Get error messages from the last operation");
}
