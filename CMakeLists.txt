cmake_minimum_required(VERSION 3.22)

project(ost2pst LANGUAGES CXX)

option(OST2PST_BUILD_GUI "Build the native Windows conversion wizard" OFF)
option(OST2PST_STATIC_RUNTIME "Use the static MSVC runtime in all native targets" OFF)
if(MSVC AND OST2PST_STATIC_RUNTIME)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8)
else()
  add_compile_options(-Wall -Wextra)
endif()

# util: byte/CRC/IO primitives. Knows nothing about PST concepts.
add_library(ost2pst_util STATIC
  src/util/workspace.cpp
  src/util/value_spool.cpp
  src/util/crc32.cpp
  src/util/inflate.cpp
  src/util/file_reader.cpp
  src/util/file_writer.cpp
  src/util/directory_pin.cpp
  src/util/sha256.cpp
  src/util/sig.cpp)
target_include_directories(ost2pst_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ndb: HEADER, ROOT, pages, blocks, allocation maps, B-trees. Format-only layer.
add_library(ost2pst_ndb STATIC
  src/ndb/amap.cpp
  src/ndb/bbt_index.cpp
  src/ndb/block_reader.cpp
  src/ndb/btree.cpp
  src/ndb/crc.cpp
  src/ndb/header.cpp
  src/ndb/ndb_read.cpp
  src/ndb/probe.cpp
  src/ndb/profile.cpp
  src/ndb/root.cpp
  src/ndb/trailer.cpp)
target_link_libraries(ost2pst_ndb PUBLIC ost2pst_util)

# ltp: heap nodes, BTree-on-Heap, property and table contexts. Sits on ndb and knows nothing above it.
add_library(ost2pst_ltp STATIC
  src/ltp/block_heap.cpp
  src/ltp/bth.cpp
  src/ltp/hn.cpp
  src/ltp/hn_block.cpp
  src/ltp/data_tree.cpp
  src/ltp/nid_map.cpp
  src/ltp/subtree_dump.cpp
  src/ltp/name_id.cpp
  src/ltp/node_open.cpp
  src/ltp/node_value.cpp
  src/ltp/pc.cpp
  src/ltp/ltp_read.cpp
  src/ltp/prop_type.cpp
  src/ltp/smq.cpp
  src/ltp/tc.cpp)
target_link_libraries(ost2pst_ltp PUBLIC ost2pst_ndb)

# msg: the folder/message/attachment/FAI model and the completeness report. Sits on ltp and knows nothing
# about how bytes get written to an output file.
add_library(ost2pst_msg STATIC
  src/msg/emit.cpp
  src/msg/inventory.cpp
  src/msg/item_conversion.cpp
  src/msg/mailbox.cpp
  src/msg/node_class.cpp
  src/msg/outcome.cpp
  src/msg/subset.cpp)
# msg reaches the writer through the request types in writer/content.h: the extractor hands one folder over
# as values, the writer decides how they become bytes (layer-boundaries.md draws exactly this edge).
target_link_libraries(ost2pst_msg PUBLIC ost2pst_ltp ost2pst_writer)

# writer: allocation, BBT/NBT emission, header CRCs and the required internal objects. It receives
# already-parsed values and never opens a source file (DEVELOPMENT.md).
add_library(ost2pst_writer STATIC
  src/writer/publication.cpp
  src/writer/staging_journal.cpp
  src/writer/staging_manifest.cpp
  src/writer/staging_workspace.cpp
  src/writer/staged_plan.cpp
  src/writer/heap.cpp
  src/writer/nid.cpp
  src/writer/pc.cpp
  src/writer/tc.cpp
  src/writer/store.cpp
  src/writer/content.cpp
  src/writer/empty_pst.cpp)
target_link_libraries(ost2pst_writer PUBLIC ost2pst_ltp)

add_library(ost2pst_cli STATIC src/cli/read_only.cpp)
target_link_libraries(ost2pst_cli PUBLIC ost2pst_msg)

add_library(ost2pst_gui_protocol STATIC src/gui/protocol.cpp)
add_library(ost2pst_gui_events STATIC src/cli/gui_events.cpp)
target_link_libraries(ost2pst_gui_events PUBLIC ost2pst_gui_protocol ost2pst_util)
add_executable(ost2pst src/cli/ost2pst.cpp src/cli/full_conversion.cpp)
target_link_libraries(ost2pst PRIVATE ost2pst_cli ost2pst_gui_events)

if(OST2PST_BUILD_GUI)
  if(NOT WIN32)
    message(FATAL_ERROR "The native wizard requires Windows; use OST2PST_BUILD_GUI=OFF for CLI only")
  endif()
  enable_language(RC)
  add_library(ost2pst_gui_native STATIC src/gui/process_host.cpp src/gui/localization.cpp src/gui/wizard.cpp)
  target_link_libraries(ost2pst_gui_native PUBLIC ost2pst_gui_protocol comctl32 ole32 shell32 uuid)
  target_compile_definitions(ost2pst_gui_native PUBLIC UNICODE _UNICODE _WIN32_WINNT=0x0A00)
  add_executable(ost2pst-gui WIN32 src/gui/main.cpp resources/gui/app.rc)
  target_link_libraries(ost2pst-gui PRIVATE ost2pst_gui_native)
  target_include_directories(ost2pst-gui PRIVATE resources/gui)
  target_link_options(ost2pst-gui PRIVATE /MANIFEST:NO)
  add_dependencies(ost2pst-gui ost2pst)
endif()

add_executable(ostinfo src/cli/ostinfo.cpp)
target_link_libraries(ostinfo PRIVATE ost2pst_cli)

# ostinfo --ndb reports peak RSS, which needs the process memory counters API.
if(WIN32)
  target_link_libraries(ost2pst_cli PUBLIC psapi)
  target_link_libraries(ostinfo PRIVATE psapi)
  target_link_libraries(ost2pst PRIVATE psapi)
endif()

include(CTest)
if(BUILD_TESTING)
  add_subdirectory(tests)
endif()





# Project-authored audits; external libpff is supplied separately to Python/tools.
option(OST2PST_BUILD_AUDIT_TOOLS "Build independent reference/content audit executables" OFF)
if(WIN32 AND OST2PST_BUILD_AUDIT_TOOLS)
  add_executable(verify_pst_refs tests/tools/verify_pst_refs.cpp)
  target_link_libraries(verify_pst_refs PRIVATE ost2pst_ltp)
  add_executable(mapped_content_compare tests/tools/mapped_content_compare.cpp)
  target_link_libraries(mapped_content_compare PRIVATE ost2pst_msg)
endif()
