# Post-build guard: the firmware image must end before the persistent-data
# sectors (counter @0x70000, master key @0x72000, PIN @0x73000).  If the image
# ever grows into them, a flash write would silently corrupt the firmware or a
# flash *update* would silently destroy the device keys.  Fail the build instead.
#
#   cmake -DBIN=<fidelio.bin> -DLIMIT=<bytes> -P check_flash_size.cmake
if(NOT EXISTS "${BIN}")
    message(FATAL_ERROR "check_flash_size: ${BIN} not found")
endif()
file(SIZE "${BIN}" _size)
math(EXPR _limit "${LIMIT}")
if(_size GREATER _limit)
    message(FATAL_ERROR "firmware image is ${_size} bytes; it must stay below ${_limit} bytes to keep clear of the persistent-data sectors (0x70000)")
endif()
message(STATUS "firmware image: ${_size} bytes (limit ${_limit})")
