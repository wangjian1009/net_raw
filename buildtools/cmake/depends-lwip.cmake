set(lwip_base ${CMAKE_CURRENT_LIST_DIR}/../../depends/lwip-2.1.1)

file(GLOB lwip_source ${lwip_base}/src/*.c)

set(lwip_source
  ${lwip_base}/src/core/timeouts.c
  ${lwip_base}/src/core/udp.c
  ${lwip_base}/src/core/memp.c
  ${lwip_base}/src/core/init.c
  ${lwip_base}/src/core/pbuf.c
  ${lwip_base}/src/core/tcp.c
  ${lwip_base}/src/core/tcp_out.c
  ${lwip_base}/src/core/sys.c
  ${lwip_base}/src/core/netif.c
  ${lwip_base}/src/core/def.c
  ${lwip_base}/src/core/mem.c
  ${lwip_base}/src/core/tcp_in.c
  ${lwip_base}/src/core/stats.c
  ${lwip_base}/src/core/inet_chksum.c
  ${lwip_base}/src/core/ip.c
  ${lwip_base}/src/core/ipv4/icmp.c
  ${lwip_base}/src/core/ipv4/ip4.c
  ${lwip_base}/src/core/ipv4/ip4_addr.c
  ${lwip_base}/src/core/ipv4/ip4_frag.c
  ${lwip_base}/src/core/ipv6/ip6.c
  ${lwip_base}/src/core/ipv6/nd6.c
  ${lwip_base}/src/core/ipv6/icmp6.c
  ${lwip_base}/src/core/ipv6/ip6_addr.c
  ${lwip_base}/src/core/ipv6/ip6_frag.c
  ${lwip_base}/src/api/err.c
  ${CMAKE_CURRENT_LIST_DIR}/../custom/lwip/sys.c
  ${CMAKE_CURRENT_LIST_DIR}/../custom/lwip/error.c
  )

if (MSVC)
elseif (CMAKE_C_COMPILER_ID MATCHES "Clang" OR CMAKE_C_COMPILER_IS_GNUCC)
set(lwip_compile_options
  -Wno-unused-value
  -Wno-bitwise-op-parentheses
  )
endif()

add_library(lwip STATIC ${lwip_source})

set_property(TARGET lwip PROPERTY INCLUDE_DIRECTORIES
  ${CMAKE_CURRENT_LIST_DIR}/../../../cpe/include
  ${lwip_base}/src/include
  ${lwip_base}/src/include/ipv4
  ${lwip_base}/src/include/ipv6
  ${CMAKE_CURRENT_LIST_DIR}/../custom/lwip
  )

set_property(TARGET lwip PROPERTY COMPILE_OPTIONS ${lwip_compile_options})
