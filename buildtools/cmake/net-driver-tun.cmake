set(net_driver_tun_base ${CMAKE_CURRENT_LIST_DIR}/../../driver_tun)

file(GLOB net_driver_tun_source ${net_driver_tun_base}/src/*.c)

if (NET_TUN_USE_DEV_NE)
  set(net_driver_tun_compile_definitions ${net_driver_tun_compile_definitions} NET_TUN_USE_DEV_NE=1)
  set(net_driver_tun_compile_options ${net_driver_tun_compile_options} "-x" "objective-c" "-fno-objc-arc")
  file(GLOB net_driver_tun_source_oc ${net_driver_tun_base}/src/*.m)
  set(net_driver_tun_source ${net_driver_tun_source} ${net_driver_tun_source_oc})
endif()

add_library(net_driver_tun STATIC ${net_driver_tun_source})
set_property(TARGET net_driver_tun PROPERTY COMPILE_DEFINITIONS ${net_driver_tun_compile_definitions})
set_property(TARGET net_driver_tun PROPERTY COMPILE_OPTIONS ${net_driver_tun_compile_options})

set_property(TARGET net_driver_tun PROPERTY INCLUDE_DIRECTORIES
  ${lwip_custom}
  ${lwip_base}/src/include
  ${lwip_base}/src/include/ipv4
  ${lwip_base}/src/include/ipv6
  ${cpe_pal_base}/include
  ${cpe_utils_base}/include
  ${cpe_utils_sock_base}/include
  ${net_core_base}/include
  ${net_driver_tun_base}/include
  )

target_link_libraries(net_driver_tun INTERFACE lwip)
