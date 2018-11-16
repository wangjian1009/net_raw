lwip_base:=$(call my-dir)/../depends/lwip
lwip_output:=$(OUTPUT_PATH)/lib/liblwip.a
lwip_cpp_flags:=-I$(lwip_base)/../../../cpe/include \
                -I$(lwip_base)/src/include \
                -I$(lwip_base)/src/include/ipv4 \
                -I$(lwip_base)/src/include/ipv6 \
                -I$(lwip_base)/../../buildtools/custom/lwip \
                $(if $(filter 1,$D), -DLWIP_DEBUG)
lwip_c_flags:=-Wno-unused-value -Wno-bitwise-op-parentheses
lwip_src:=$(addprefix $(lwip_base)/, \
              src/core/timers.c \
              src/core/udp.c \
              src/core/memp.c \
              src/core/init.c \
              src/core/pbuf.c \
              src/core/tcp.c \
              src/core/tcp_out.c \
              src/core/sys.c \
              src/core/netif.c \
              src/core/def.c \
              src/core/mem.c \
              src/core/tcp_in.c \
              src/core/stats.c \
              src/core/inet_chksum.c \
              src/core/ipv4/icmp.c \
              src/core/ipv4/ip4.c \
              src/core/ipv4/ip4_addr.c \
              src/core/ipv4/ip_frag.c \
              src/core/ipv6/ip6.c \
              src/core/ipv6/nd6.c \
              src/core/ipv6/icmp6.c \
              src/core/ipv6/ip6_addr.c \
              src/core/ipv6/ip6_frag.c \
              src/api/err.c \
              ../../buildtools/custom/lwip/sys.c \
              ../../buildtools/custom/lwip/error.c \
           )

$(eval $(call def_library,lwip))
