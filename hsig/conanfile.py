#!/usr/bin/env python3

from conans import ConanFile, CMake

class DoryHsigConan(ConanFile):
    name = "dory-hsig"
    version = "0.1.0"
    license = "MIT"
    url = "TODO: Add your project URL here"
    description = "Hybrid signature implementation for secure communications"
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "log_level": ["TRACE", "DEBUG", "INFO", "WARN", "ERROR", "CRITICAL", "OFF"],
        "lto": [True, False],
    }
    default_options = {
        "shared": False,
        "log_level": "INFO",
        "lto": True,
    }
    generators = "cmake"
    exports_sources = "src/*"
    python_requires = "dory-compiler-options/0.0.1@dory/stable"

    def requirements(self):
        # Add dependencies here if required
        # self.requires("fmt/7.1.3")  # Example dependency
        self.requires("dory-crypto/0.0.1")
        self.requires("dory-crypto/0.0.1")
        self.requires("dory-memstore/0.0.1")
        self.requires("dory-shared/0.0.1")
        self.requires("fmt/7.1.3")
        self.requires("xxhash/0.8.0")

    def configure(self):
        pass

    def build(self):
        self.python_requires["dory-compiler-options"].module.setup_cmake(
            self.build_folder
        )
        generator = self.python_requires["dory-compiler-options"].module.generator()
        cmake = CMake(self, generator=generator)

        self.python_requires["dory-compiler-options"].module.set_options(cmake)
        lto_decision = self.python_requires[
            "dory-compiler-options"
        ].module.lto_decision(cmake, self.options.lto)
        cmake.definitions["DORY_LTO"] = str(lto_decision).upper()

        cmake.configure(source_folder="src")
        cmake.build()

    def package(self):
        # self.copy("*.hpp", dst="include/hsig", src="src")
        self.copy("*.a", dst="lib", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*", dst="bin", src="bin")

    def deploy(self):
        self.copy("*", dst="bin", src="bin")

    def package_info(self):
        self.cpp_info.libs = ["doryhsig"]
        self.cpp_info.cxxflags = self.python_requires[
            "dory-compiler-options"
        ].module.get_cxx_options_for(self.settings.compiler, self.settings.build_type)


if __name__ == "__main__":
    import os, pathlib, sys

    # Find dory root directory
    root_dir = pathlib.Path(os.path.dirname(os.path.abspath(__file__)))
    while not os.path.isfile(os.path.join(root_dir, ".dory-root")):
        root_dir = root_dir.parent

    sys.path.append(os.path.join(root_dir, "conan", "invoker"))

    import invoker

    invoker.run()