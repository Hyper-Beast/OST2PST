find_package(Python3 3.8 REQUIRED COMPONENTS Interpreter)
set(OST2PST_FIXTURE_DIR "${CMAKE_CURRENT_BINARY_DIR}/fixtures")
set(OST2PST_GOLDEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/golden")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tools/generate_fixtures.py"
  "${CMAKE_CURRENT_BINARY_DIR}" RESULT_VARIABLE fixture_result)
if(NOT fixture_result EQUAL 0)
  message(FATAL_ERROR "Synthetic fixture generation failed")
endif()
option(OST2PST_EXTERNAL_GATE_TESTS "Run gate fault injection (requires separately built libpff)" OFF)

# Paths reach tests through a generated header: -DFOO="path" quoting on MSVC is a footgun.
configure_file(paths.h.in "${CMAKE_CURRENT_BINARY_DIR}/generated/test_paths.h" @ONLY)

function(ost2pst_add_unit_test name)
  add_executable(${name} "unit/${name}.cpp")
  # Extra libraries may be named after the test name, e.g. ost2pst_add_unit_test(ltp_bth_test ost2pst_ltp).
  target_link_libraries(${name} PRIVATE ost2pst_ndb ${ARGN})
  target_include_directories(${name} PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}/generated"
    "${CMAKE_CURRENT_SOURCE_DIR}/unit")
  add_test(NAME ${name} COMMAND ${name})
endfunction()

ost2pst_add_unit_test(crc_test)
ost2pst_add_unit_test(sha256_test)
ost2pst_add_unit_test(inflate_test)
ost2pst_add_unit_test(sig_test)
ost2pst_add_unit_test(header_test)
ost2pst_add_unit_test(trailer_test)
ost2pst_add_unit_test(golden_test)
ost2pst_add_unit_test(file_reader_test)
ost2pst_add_unit_test(file_identity_test)
ost2pst_add_unit_test(file_writer_test)
ost2pst_add_unit_test(value_spool_test)
ost2pst_add_unit_test(workspace_test)

# M1: the NDB reader and the index every later layer resolves BIDs through.
ost2pst_add_unit_test(bbt_index_test)
ost2pst_add_unit_test(ndb_reader_test)

# M2: the LTP layer's own tests.
ost2pst_add_unit_test(ltp_hn_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_hn_block_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_multi_block_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_data_tree_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_bth_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_pc_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_tc_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_nid_map_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_node_value_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_name_id_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_smq_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_ltp_read_test ost2pst_ltp)
ost2pst_add_unit_test(ltp_findings_test ost2pst_ltp)

# M3: the Messaging layer's own tests.
ost2pst_add_unit_test(msg_node_class_test ost2pst_msg)
ost2pst_add_unit_test(msg_inventory_test ost2pst_msg)
ost2pst_add_unit_test(msg_subset_test ost2pst_msg)
ost2pst_add_unit_test(msg_mailbox_test ost2pst_msg)
ost2pst_add_unit_test(msg_outcome_test ost2pst_msg)
ost2pst_add_unit_test(conversion_regressions_test ost2pst_msg)
# Includes a synthetic BBT just above the former 128 MiB ceiling.
set_tests_properties(conversion_regressions_test PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)

# M4: the writer's own components, each checked through the reader that has to accept its bytes.
ost2pst_add_unit_test(writer_heap_test ost2pst_writer)
ost2pst_add_unit_test(writer_pc_test ost2pst_writer)
ost2pst_add_unit_test(writer_tc_test ost2pst_writer)
ost2pst_add_unit_test(writer_empty_pst_test ost2pst_writer)
ost2pst_add_unit_test(writer_store_test ost2pst_writer)
ost2pst_add_unit_test(writer_streaming_test ost2pst_writer)
ost2pst_add_unit_test(writer_staging_journal_test ost2pst_writer)
ost2pst_add_unit_test(writer_staging_manifest_test ost2pst_writer)
if(WIN32)
  ost2pst_add_unit_test(writer_publication_test ost2pst_writer)
  ost2pst_add_unit_test(writer_staging_process_test ost2pst_writer)
  ost2pst_add_unit_test(writer_staging_workspace_test ost2pst_writer)
  ost2pst_add_unit_test(full_conversion_process_test ost2pst_cli ost2pst_gui_events psapi)
  target_sources(full_conversion_process_test PRIVATE "${PROJECT_SOURCE_DIR}/src/cli/full_conversion.cpp")
  target_include_directories(full_conversion_process_test PRIVATE "${PROJECT_SOURCE_DIR}/src/cli")
  set_tests_properties(full_conversion_process_test PROPERTIES TIMEOUT 180)
endif()
add_executable(gui_protocol_test unit/gui_protocol_test.cpp)
target_link_libraries(gui_protocol_test PRIVATE ost2pst_gui_protocol)
add_test(NAME gui_protocol_test COMMAND gui_protocol_test)
# M5: the content build checked against the readers that have to accept its bytes.
ost2pst_add_unit_test(writer_content_test ost2pst_writer)
ost2pst_add_unit_test(writer_item_plan_test ost2pst_msg)
ost2pst_add_unit_test(writer_staged_plan_test ost2pst_writer)

# W3: the CLI's own file handling, checked by running the built executable against real files.
ost2pst_add_unit_test(writer_cli_test ost2pst_writer ost2pst_msg)
target_compile_definitions(writer_cli_test PRIVATE OST2PST_OST2PST_EXE="$<TARGET_FILE:ost2pst>")
add_dependencies(writer_cli_test ost2pst)

# The CLI's own verdict: this test runs ostinfo as a child process, so it needs the built executable's
# path and has to be built after it.
ost2pst_add_unit_test(cli_inventory_test)
target_compile_definitions(cli_inventory_test PRIVATE OST2PST_OSTINFO_EXE="$<TARGET_FILE:ostinfo>")
add_dependencies(cli_inventory_test ostinfo)

add_executable(cli_fixture_builder cli_fixture_builder.cpp)
target_link_libraries(cli_fixture_builder PRIVATE ost2pst_writer ost2pst_msg)

# W4: the gate script's own failure semantics. Each case injects one fault into a real scripts/verify.sh
# run and checks the label and the exit code, so "ran and failed" cannot collapse back into NOT VERIFIED.
# It shells out to the built executables, which a build-then-ctest run already provides.
find_program(OST2PST_BASH bash)
if(OST2PST_EXTERNAL_GATE_TESTS AND NOT OST2PST_BASH)
  message(FATAL_ERROR "OST2PST_EXTERNAL_GATE_TESTS requires Git Bash")
endif()
if(OST2PST_BASH AND OST2PST_EXTERNAL_GATE_TESTS)
  file(RELATIVE_PATH OST2PST_GATE_BUILD "${PROJECT_SOURCE_DIR}" "${PROJECT_BINARY_DIR}")
  add_test(NAME verify_gate_test
    COMMAND "${CMAKE_COMMAND}" -E env
      "OST2PST_GATE_BUILD=${OST2PST_GATE_BUILD}" "OST2PST_GATE_CONFIG=$<CONFIG>"
      "${OST2PST_BASH}" "${CMAKE_CURRENT_SOURCE_DIR}/verify_gate_test.sh")
  # The meta-test runs scripts/verify.sh once per injected case, and every one of those runs configures and
  # builds the project and probes the OST sample, so it needs far longer than a unit test. Measured on
  # 2026-10-13 (build/scratch/ctest_gate_only.log): 301.16 s for its 15 injected cases, so the 290 s
  # ctest --timeout used by the previous batch cut it off mid-case. The injected cases still FAIL as before.
  set_tests_properties(verify_gate_test PROPERTIES TIMEOUT 900 RUN_SERIAL TRUE)
endif()

# Research comparison is Python-only; it adds no converter runtime dependency.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME gui_catalog_test COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/generate_gui_strings.py" --check)
  if(OST2PST_BUILD_GUI)
    add_executable(gui_host_boundaries_test unit/gui_host_boundaries_test.cpp)
    target_link_libraries(gui_host_boundaries_test PRIVATE ost2pst_gui_native)
    add_test(NAME gui_host_boundaries_test COMMAND gui_host_boundaries_test)
    set_tests_properties(gui_host_boundaries_test PROPERTIES TIMEOUT 90)
    add_executable(gui_native_test unit/gui_native_test.cpp "${PROJECT_SOURCE_DIR}/resources/gui/app.rc")
    target_include_directories(gui_native_test PRIVATE "${PROJECT_SOURCE_DIR}/resources/gui")
    target_link_options(gui_native_test PRIVATE /MANIFEST:NO)
    add_executable(gui_failure_worker gui_failure_worker.cpp "${PROJECT_SOURCE_DIR}/src/cli/full_conversion.cpp")
    target_link_libraries(gui_failure_worker PRIVATE ost2pst_cli ost2pst_gui_events psapi)
    target_link_libraries(gui_native_test PRIVATE ost2pst_gui_native)
    add_dependencies(gui_native_test ost2pst)
    add_test(NAME gui_native_test COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/gui_native_test.py"
      --native-test "$<TARGET_FILE:gui_native_test>" --worker "$<TARGET_FILE:ost2pst>"
      --failure-worker "$<TARGET_FILE:gui_failure_worker>"
      --fixture-builder "$<TARGET_FILE:cli_fixture_builder>" --evidence "${PROJECT_BINARY_DIR}/gui-evidence")
    set_tests_properties(gui_native_test PROPERTIES TIMEOUT 300 RUN_SERIAL TRUE)
  endif()
  add_test(NAME gui_worker_protocol_test COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/gui_protocol_test.py" --worker "$<TARGET_FILE:ost2pst>"
    --fixture-builder "$<TARGET_FILE:cli_fixture_builder>")
  add_test(NAME cli_read_only_test
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/cli_read_only_test.py"
      --ost2pst "$<TARGET_FILE:ost2pst>" --ostinfo "$<TARGET_FILE:ostinfo>"
      --fixture-builder "$<TARGET_FILE:cli_fixture_builder>")
  set_tests_properties(cli_read_only_test PROPERTIES TIMEOUT 90)
  add_test(NAME truncation_cli_test
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/truncation_cli_test.py"
      --ost2pst "$<TARGET_FILE:ost2pst>" --ostinfo "$<TARGET_FILE:ostinfo>"
      --fixture-builder "$<TARGET_FILE:cli_fixture_builder>")
  set_tests_properties(truncation_cli_test PROPERTIES TIMEOUT 180 LABELS truncation)
  add_test(NAME attachment_compare_test
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/unit/attachment_compare_test.py")
  add_test(NAME verify_full_test
    COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/unit/verify_full_test.py")
endif()




