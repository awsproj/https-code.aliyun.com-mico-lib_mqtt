#
#  UNPUBLISHED PROPRIETARY SOURCE CODE
#  Copyright (c) 2016 MXCHIP Inc.
#
#  The contents of this file may not be disclosed to third parties, copied or
#  duplicated in any form, in whole or in part, without the prior written
#  permission of MXCHIP Corporation.
#

NAME := Lib_MQTT_AWS

GLOBAL_INCLUDES += 	./include \
					./user_config

ifeq ($(BUILD_MXOS), 1)
GLOBAL_INCLUDES += 	./platform/mxos
else
GLOBAL_INCLUDES += 	./platform/mico
endif

$(NAME)_SOURCES := ./src/mqtt_client_common_internal.c \
				   ./src/mqtt_client_connect.c \
				   ./src/mqtt_client_publish.c \
				   ./src/mqtt_client_subscribe.c \
				   ./src/mqtt_client_unsubscribe.c \
				   ./src/mqtt_client_yield.c \
				   ./src/mqtt_client.c

ifeq ($(BUILD_MXOS), 1)
$(NAME)_SOURCES += ./platform/mxos/network_platform.c \
				   ./platform/mxos/threads_platform.c \
				   ./platform/mxos/timer_platform.c
else
$(NAME)_SOURCES += ./platform/mico/network_platform.c \
				   ./platform/mico/threads_platform.c \
				   ./platform/mico/timer_platform.c
endif
