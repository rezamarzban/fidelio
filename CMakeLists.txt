cmake_minimum_required(VERSION 3.5)

include(${CMAKE_CURRENT_SOURCE_DIR}/pico-sdk/lib/tinyusb/hw/bsp/family_support.cmake)


# gets PROJECT name for the example (e.g. <BOARD>-<DIR_NAME>)
family_get_project_name(PROJECT ${CMAKE_CURRENT_LIST_DIR})

project(${PROJECT})

# Checks this example is valid for the family and initializes the project
family_initialize_project(${PROJECT} ${CMAKE_CURRENT_LIST_DIR})

add_executable(${PROJECT})

#target_compile_options(${PROJECT} PUBLIC
#    "-Wno-cast-qual"
#    "-Wno-sign-conversion"
#    "-Wno-fatal-errors"
#)
#
# Example source
target_sources(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/fidelio.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/rand.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ctap2.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/u2f.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/se.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/cred_store.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/att_cert.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/att_der.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/hw_sign.c
        ${CMAKE_CURRENT_SOURCE_DIR}/src/usb_descriptors.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/asn.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/wc_port.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/wolfmath.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/hash.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/memory.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/misc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ecc.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/hmac.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/coding.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/random.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/aes.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sha256.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sha512.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ge_low_mem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/fe_low_mem.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/ge_operations.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sp_int.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sp_armthumb.c
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl/wolfcrypt/src/sp_c32.c
        )

# Example include
target_include_directories(${PROJECT} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src 
        ${CMAKE_CURRENT_SOURCE_DIR}/lib/wolfssl
        )

        target_compile_definitions( ${PROJECT} PUBLIC WOLFSSL_USER_SETTINGS)


        target_link_libraries(${PROJECT} PUBLIC pico_stdlib)
        target_link_libraries(${PROJECT} PUBLIC pico_multicore)
        target_link_libraries(${PROJECT} PUBLIC hardware_adc)
        target_link_libraries(${PROJECT} PUBLIC hardware_i2c)
        target_link_libraries(${PROJECT} PUBLIC hardware_flash)

# Configure compilation flags and libraries for the example... see the corresponding function
# in hw/bsp/FAMILY/family.cmake for details.
family_configure_device_example(${PROJECT})

# Flash writes (counter, master key, PIN) run from RAM; a build that executes
# from flash would stall/crash during them.  Force the RAM-resident layout
# whatever the configure command line says.
pico_set_binary_type(${PROJECT} copy_to_ram)

# Keep the image clear of the persistent-data sectors starting at 0x70000.
add_custom_command(TARGET ${PROJECT} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -DBIN=$<TARGET_FILE_DIR:${PROJECT}>/${PROJECT}.bin
            -DLIMIT=0x70000 -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/check_flash_size.cmake
    COMMENT "Checking firmware size against the persistent-data area")
