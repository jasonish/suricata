if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
else ()
    set(CARGO_CMD cargo build --release)
endif ()

add_custom_target(rust ALL
    COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR}/target ${CARGO_CMD})
set_target_properties(rust PROPERTIES LOCATION ${CMAKE_CURRENT_BINARY_DIR})

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES target)
