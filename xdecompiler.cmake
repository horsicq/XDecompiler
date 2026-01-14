include_directories(${CMAKE_CURRENT_LIST_DIR})

set(XDECOMPILER_SOURCES
    ${XDECOMPILER_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xdecompiler.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xdecompiler.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xabstractparser.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arch/xabstractparser.h
    ${CMAKE_CURRENT_LIST_DIR}/arch/xx86parser.cpp
    ${CMAKE_CURRENT_LIST_DIR}/arch/xx86parser.h
)
