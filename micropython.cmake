add_library(usermod_bitstruct INTERFACE)

target_sources(usermod_bitstruct INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/bitstruct/bitstruct.c
    ${CMAKE_CURRENT_LIST_DIR}/bitstruct/bitstream.c
)

target_include_directories(usermod_bitstruct INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}/bitstruct/
)

target_link_libraries(usermod INTERFACE usermod_bitstruct)
