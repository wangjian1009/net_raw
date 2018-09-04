set(net_driver_tun_base ${CMAKE_CURRENT_LIST_DIR}/../../driver_tun)

file(GLOB net_driver_tun_source ${net_driver_tun_base}/src/*.c)

add_library(net_driver_tun STATIC ${net_driver_tun_source})

set_property(TARGET net_driver_tun PROPERTY INCLUDE_DIRECTORIES
  ${CMAKE_CURRENT_LIST_DIR}/../custom/lwip
  ${CMAKE_CURRENT_LIST_DIR}/../../depends/lwip/src/include
  ${CMAKE_CURRENT_LIST_DIR}/../../depends/lwip/src/include/ipv4
  ${CMAKE_CURRENT_LIST_DIR}/../../depends/lwip/src/include/ipv6
  ${CMAKE_CURRENT_LIST_DIR}/../../../cpe/include
  ${CMAKE_CURRENT_LIST_DIR}/../../../net/core/include
  ${net_driver_tun_base}/include
  )
