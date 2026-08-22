project(softhsm2-export)

set(INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../common
                 ${PROJECT_SOURCE_DIR}/../../lib
                 ${PROJECT_SOURCE_DIR}/../../lib/common
                 ${PROJECT_SOURCE_DIR}/../../lib/crypto
                 ${PROJECT_SOURCE_DIR}/../../lib/data_mgr
                 ${PROJECT_SOURCE_DIR}/../../lib/handle_mgr
                 ${PROJECT_SOURCE_DIR}/../../lib/object_store
                 ${PROJECT_SOURCE_DIR}/../../lib/pkcs11
                 ${PROJECT_SOURCE_DIR}/../../lib/session_mgr
                 ${PROJECT_SOURCE_DIR}/../../lib/slot_mgr
                 ${CRYPTO_INCLUDES}
                 ${SQLITE3_INCLUDES})

set(SOURCES softhsm2-export.cpp
            ${PROJECT_SOURCE_DIR}/../common/findslot.cpp
            ${PROJECT_SOURCE_DIR}/../common/getpw.cpp)

if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    list(APPEND INCLUDE_DIRS ${PROJECT_SOURCE_DIR}/../../lib/win32
                             ${PROJECT_SOURCE_DIR}/../win32)
    list(APPEND SOURCES ${PROJECT_SOURCE_DIR}/../win32/getopt.cpp)
endif()

include_directories(${INCLUDE_DIRS})
add_executable(${PROJECT_NAME} ${SOURCES})
target_compile_definitions(${PROJECT_NAME} PRIVATE SOFTHSM2_ENABLE_DEBUG_EXPORT=1)
target_link_libraries(${PROJECT_NAME} softhsm2-static ${CRYPTO_LIBS} ${SQLITE3_LIBS} ${CMAKE_DL_LIBS})
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_OPTIONS})

if(ENABLE_PORTABLE)
    if(MSVC)
        set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    elseif(UNIX AND NOT APPLE)
        target_link_options(${PROJECT_NAME} PRIVATE -static-libgcc -static-libstdc++ "-Wl,--exclude-libs,ALL")
    endif()
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR})
