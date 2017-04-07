/*******************************************************************************
 * Copyright (c) 2014 IBM Corp.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 *
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *   http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Ian Craggs - initial API and implementation and/or initial documentation
 *    Xiang Rong - 442039 Add makefile to Embedded C client
 *******************************************************************************/

/**
 * @file mqtt_client_common_internal.h
 * @brief Internal MQTT functions not exposed to application
 */

#ifndef MQTT_CLIENT_COMMON_INTERNAL_H
#define MQTT_CLIENT_COMMON_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "mqtt_log.h"
#include "mqtt_client_interface.h"

/* Enum order should match the packet ids array defined in MQTTFormat.c */
typedef enum msgTypes {
	UNKNOWN = -1,
	CONNECT = 1,
	CONNACK = 2,
	PUBLISH = 3,
	PUBACK = 4,
	PUBREC = 5,
	PUBREL = 6,
	PUBCOMP = 7,
	SUBSCRIBE = 8,
	SUBACK = 9,
	UNSUBSCRIBE = 10,
	UNSUBACK = 11,
	PINGREQ = 12,
	PINGRESP = 13,
	DISCONNECT = 14
} MessageTypes;

/**
 * Bitfields for the MQTT header byte.
 */
typedef union {
	unsigned char byte;				/**< the whole byte */
#if defined(REVERSED)
	struct {
		unsigned int type : 4;		/**< message type nibble */
		unsigned int dup : 1;		/**< DUP flag bit */
		unsigned int qos : 2;		/**< QoS value, 0, 1 or 2 */
		unsigned int retain : 1;	/**< retained flag bit */
	} bits;
#else
	struct {
		unsigned int retain : 1;	/**< retained flag bit */
		unsigned int qos : 2;		/**< QoS value, 0, 1 or 2 */
		unsigned int dup : 1;		/**< DUP flag bit */
		unsigned int type : 4;		/**< message type nibble */
	} bits;
#endif
} MQTTHeader;

IoT_Error_t mqtt_internal_init_header(MQTTHeader *pHeader, MessageTypes message_type,
											  QoS qos, uint8_t dup, uint8_t retained);

IoT_Error_t mqtt_internal_serialize_ack(unsigned char *pTxBuf, size_t txBufLen,
												MessageTypes msgType, uint8_t dup, uint16_t packetId,
												uint32_t *pSerializedLen);
IoT_Error_t mqtt_internal_deserialize_ack(unsigned char *, unsigned char *,
												  uint16_t *, unsigned char *, size_t);

uint32_t mqtt_internal_get_final_packet_length_from_remaining_length(uint32_t rem_len);

size_t mqtt_internal_write_len_to_buffer(unsigned char *buf, uint32_t length);
IoT_Error_t mqtt_internal_decode_remaining_length_from_buffer(unsigned char *buf, uint32_t *decodedLen,
																	  uint32_t *readBytesLen);

uint16_t mqtt_internal_read_uint16_t(unsigned char **pptr);
void mqtt_internal_write_uint_16(unsigned char **pptr, uint16_t anInt);

unsigned char mqtt_internal_read_char(unsigned char **pptr);
void mqtt_internal_write_char(unsigned char **pptr, unsigned char c);
void mqtt_internal_write_utf8_string(unsigned char **pptr, const char *string, uint16_t stringLen);

IoT_Error_t mqtt_internal_send_packet(MQTT_Client *pClient, size_t length, Timer *pTimer);
IoT_Error_t mqtt_internal_cycle_read(MQTT_Client *pClient, Timer *pTimer, uint8_t *pPacketType);
IoT_Error_t mqtt_internal_wait_for_read(MQTT_Client *pClient, uint8_t packetType, Timer *pTimer);
IoT_Error_t mqtt_internal_serialize_zero(unsigned char *pTxBuf, size_t txBufLen,
												 MessageTypes packetType, size_t *pSerializedLength);
IoT_Error_t mqtt_internal_deserialize_publish(uint8_t *dup, QoS *qos,
													  uint8_t *retained, uint16_t *pPacketId,
													  char **pTopicName, uint16_t *topicNameLen,
													  unsigned char **payload, size_t *payloadLen,
													  unsigned char *pRxBuf, size_t rxBufLen);

IoT_Error_t mqtt_set_client_state(MQTT_Client *pClient, ClientState expectedCurrentState,
										  ClientState newState);

#ifdef _ENABLE_THREAD_SUPPORT_

IoT_Error_t mqtt_client_lock_mutex(MQTT_Client *pClient, IoT_Mutex_t *pMutex);

IoT_Error_t mqtt_client_unlock_mutex(MQTT_Client *pClient, IoT_Mutex_t *pMutex);

#endif

#ifdef __cplusplus
}
#endif

#endif /* AWS_IOT_SDK_SRC_IOT_COMMON_INTERNAL_H */
