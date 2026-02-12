cmake_minimum_required(VERSION 3.14)
project(superscalar C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

# --- secp256k1-zkp (BlockstreamResearch fork) with MuSig2 ---
set(SECP256K1_ENABLE_MODULE_MUSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_SCHNORRSIG ON CACHE BOOL "" FORCE)
set(SECP256K1_ENABLE_MODULE_EXTRAKEYS ON CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXHAUSTIVE_TESTS OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

FetchContent_Declare(secp256k1-zkp
    GIT_REPOSITORY https://github.com/BlockstreamResearch/secp256k1-zkp.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(secp256k1-zkp)

# --- cJSON for parsing bitcoin-cli output ---
set(CJSON_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(ENABLE_CJSON_TEST OFF CACHE BOOL "" FORCE)

FetchContent_Declare(cjson
    GIT_REPOSITORY https://github.com/DaveGamble/cJSON.git
    GIT_TAG        v1.7.18
)
FetchContent_MakeAvailable(cjson)

# --- Main library ---
add_library(superscalar
    src/dw_state.c
    src/tx_builder.c
    src/musig.c
    src/regtest.c
    src/util.c
)
target_include_directories(superscalar PUBLIC include)
target_include_directories(superscalar PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_include_directories(superscalar PRIVATE ${cjson_SOURCE_DIR})
target_link_libraries(superscalar PUBLIC secp256k1 cjson)

# --- Tests ---
add_executable(test_superscalar
    tests/test_main.c
    tests/test_dw_state.c
    tests/test_musig.c
    tests/test_tx_builder.c
    tests/test_regtest.c
)
target_include_directories(test_superscalar PRIVATE ${secp256k1-zkp_SOURCE_DIR}/include)
target_link_libraries(test_superscalar PRIVATE superscalar)
enable_testing()
add_test(NAME unit_tests COMMAND test_superscalar --unit)
add_test(NAME regtest_tests COMMAND test_superscalar --regtest)
