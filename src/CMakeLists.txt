# libtebako-crypto — the versioned C ABI shared library over static
# librnp + Botan + json-c + zlib + bzip2 (all built from source by
# tools/build into TEBAKO_DEPS_PREFIX / TEBAKO_RNP_PREFIX).
#
# The link is the whole point of the feedstock: every crypto dependency
# is a static archive, so the runtime dylib closure of the artifact is
# libc/libm and nothing else (libstdc++/libgcc linked statically on
# linux; libc++ is the OS on macOS). Only tebako_crypto_v1_* symbols are
# exported.

cmake_minimum_required(VERSION 3.20)
project(tebako-crypto C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT TEBAKO_DEPS_PREFIX)
  message(FATAL_ERROR "TEBAKO_DEPS_PREFIX (botan/json-c/zlib/bzip2 install prefix) is required")
endif()
if(NOT TEBAKO_RNP_PREFIX)
  message(FATAL_ERROR "TEBAKO_RNP_PREFIX (librnp install prefix) is required")
endif()

add_library(tebako-crypto SHARED tebako_crypto_v1.cpp)
target_compile_definitions(tebako-crypto PRIVATE TEBAKO_CRYPTO_BUILD=1)
target_include_directories(tebako-crypto PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
  ${TEBAKO_RNP_PREFIX}/include
  ${TEBAKO_DEPS_PREFIX}/include
  ${TEBAKO_DEPS_PREFIX}/include/botan-3)
set_target_properties(tebako-crypto PROPERTIES
  C_VISIBILITY_PRESET hidden
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN ON)

# Static archives, found explicitly — no shared variants may sneak in.
find_library(TEBAKO_RNP_LIB    NAMES librnp.a      PATHS ${TEBAKO_RNP_PREFIX}/lib  NO_DEFAULT_PATH REQUIRED)
find_library(TEBAKO_SEXPP_LIB  NAMES libsexpp.a    PATHS ${TEBAKO_RNP_PREFIX}/lib  NO_DEFAULT_PATH REQUIRED)
find_library(TEBAKO_BOTAN_LIB  NAMES libbotan-3.a  PATHS ${TEBAKO_DEPS_PREFIX}/lib NO_DEFAULT_PATH REQUIRED)
find_library(TEBAKO_JSONC_LIB  NAMES libjson-c.a   PATHS ${TEBAKO_DEPS_PREFIX}/lib NO_DEFAULT_PATH REQUIRED)
find_library(TEBAKO_Z_LIB      NAMES libz.a        PATHS ${TEBAKO_DEPS_PREFIX}/lib NO_DEFAULT_PATH REQUIRED)
find_library(TEBAKO_BZ2_LIB    NAMES libbz2.a      PATHS ${TEBAKO_DEPS_PREFIX}/lib NO_DEFAULT_PATH REQUIRED)

target_link_libraries(tebako-crypto PRIVATE
  ${TEBAKO_RNP_LIB} ${TEBAKO_SEXPP_LIB} ${TEBAKO_BOTAN_LIB}
  ${TEBAKO_JSONC_LIB} ${TEBAKO_Z_LIB} ${TEBAKO_BZ2_LIB})

if(APPLE)
  # One real file, no symlinks (the libtfs extractor cannot read symlink
  # inodes — the inkscape feedstock resolves them to copies; naming the
  # output directly avoids the issue by construction). Install name
  # @rpath/<leaf>: the consumer dlopens by absolute path or wires its
  # own rpath. The ".1" in the leaf is the soname-equivalent ABI tag.
  set_target_properties(tebako-crypto PROPERTIES
    OUTPUT_NAME "tebako-crypto.1"
    INSTALL_NAME_DIR "@rpath"
    MACOSX_RPATH ON)
  # ld64 has no --exclude-libs; whitelist the v1 ABI explicitly so the
  # static archives' symbols (botan/rnp/bz2/…) stay out of the export
  # table — the payload exposes tebako_crypto_v1_* and nothing else.
  set(TEBAKO_EXPORTS "${CMAKE_CURRENT_BINARY_DIR}/tebako_crypto_v1.exports")
  file(WRITE "${TEBAKO_EXPORTS}" "")
  foreach(sym IN ITEMS
      _tebako_crypto_v1_abi_version
      _tebako_crypto_rnp_version_string
      _tebako_crypto_v1_create
      _tebako_crypto_v1_destroy
      _tebako_crypto_v1_last_error
      _tebako_crypto_v1_load_keys
      _tebako_crypto_v1_generate_key
      _tebako_crypto_v1_export_key
      _tebako_crypto_v1_key_fingerprint
      _tebako_crypto_v1_keyid_from_fingerprint
      _tebako_crypto_v1_sign_detached
      _tebako_crypto_v1_verify_detached
      _tebako_crypto_v1_signature_issuer_fingerprint
      _tebako_crypto_v1_encrypt
      _tebako_crypto_v1_decrypt
      _tebako_crypto_v1_envelope_recipients
      _tebako_crypto_v1_armor_bytes
      _tebako_crypto_v1_dearmor_bytes)
    file(APPEND "${TEBAKO_EXPORTS}" "${sym}\n")
  endforeach()
  target_link_options(tebako-crypto PRIVATE
    "-Wl,-exported_symbols_list,${TEBAKO_EXPORTS}")
elseif(UNIX)
  # real libtebako-crypto.so.1.0.0 + soname libtebako-crypto.so.1;
  # tools/build collapses the symlinks to the single shipped file.
  set_target_properties(tebako-crypto PROPERTIES
    OUTPUT_NAME "tebako-crypto"
    VERSION 1.0.0
    SOVERSION 1)
  # libstdc++/libgcc ride inside: runtime deps shrink to libc/libm.
  target_link_options(tebako-crypto PRIVATE
    -static-libstdc++ -static-libgcc
    -Wl,--exclude-libs,ALL)
  target_link_libraries(tebako-crypto PRIVATE pthread)
endif()

install(TARGETS tebako-crypto LIBRARY DESTINATION lib)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/../include/tebako_crypto_v1.h
        DESTINATION include)
