set(net_driver_tun_base ${CMAKE_CURRENT_LIST_DIR}/../../driver_tun)

file(GLOB net_driver_tun_source ${net_driver_tun_base}/src/*.c)

if (NET_TUN_USE_DEV_NE)
  set(net_driver_tun_compile_definitions
    ${net_driver_tun_compile_definitions}
    NET_TUN_USE_DEV_NE=1)

  set(net_driver_tun_compile_options
    ${net_driver_tun_compile_options}
    "-x" "objective-c")

  file(GLOB net_driver_tun_source_oc ${net_driver_tun_base}/src/*.m)
  set(net_driver_tun_source
    ${net_driver_tun_source} ${net_driver_tun_source_oc})

  # set_property(
  #   SOURCE ${net_driver_tun_source_oc}
  #   PROPERTY COMPILE_OPTIONS "-framework" "NetworkExtension")
endif()

add_library(net_driver_tun STATIC ${net_driver_tun_source})
set_property(TARGET net_driver_tun PROPERTY COMPILE_DEFINITIONS ${net_driver_tun_compile_definitions})
set_property(TARGET net_driver_tun PROPERTY COMPILE_OPTIONS ${net_driver_tun_compile_options})

set_property(TARGET net_driver_tun PROPERTY INCLUDE_DIRECTORIES
  ${CMAKE_CURRENT_LIST_DIR}/../custom/lwip
  ${CMAKE_CURRENT_LIST_DIR}/../../depends/lwip-2.1.1/src/include
  ${CMAKE_CURRENT_LIST_DIR}/../../depends/lwip-2.1.1/src/include/ipv4
  ${CMAKE_CURRENT_LIST_DIR}/../../depends/lwip-2.1.1/src/include/ipv6
  ${CMAKE_CURRENT_LIST_DIR}/../../../cpe/pal/include
  ${CMAKE_CURRENT_LIST_DIR}/../../../cpe/utils/include
  ${CMAKE_CURRENT_LIST_DIR}/../../../cpe/utils_sock/include
  ${CMAKE_CURRENT_LIST_DIR}/../../../net/depends/libev/include
  ${CMAKE_CURRENT_LIST_DIR}/../../../net/core/include
  ${net_driver_tun_base}/include
  )

target_link_libraries(net_driver_tun INTERFACE lwip)
