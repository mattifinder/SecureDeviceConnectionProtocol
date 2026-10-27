find_package(mbedTLS REQUIRED)
find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
  pkg_check_modules(LIBUSB libusb-1.0)
endif ()

if (NOT LIBUSB_FOUND OR NOT MBEDX509_LIBRARY)
  message(STATUS "libusb-1.0 or mbedx509 not found; not building sdcpusb")
  return()
endif ()

add_executable(sdcpusb main.c host.c claim.c verimark.c mock.c modelcerts.c)
target_include_directories(sdcpusb PRIVATE ${MBEDTLS_INCLUDE_DIR} ${LIBUSB_INCLUDE_DIRS})
target_link_libraries(sdcpusb sdcpcli ${MBEDX509_LIBRARY} ${MBEDCRYPTO_LIBRARY} ${LIBUSB_LIBRARIES})
