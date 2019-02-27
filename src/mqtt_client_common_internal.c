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
 *    Sergio R. Caprile - non-blocking packet read functions for stream transport
 *******************************************************************************/

/**
 * @file aws_iot_mqtt_client_common_internal.c
 * @brief MQTT client internal API definitions
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <mqtt_client.h>
#include <unistd.h>
#include "mqtt_client_common_internal.h"

/* Max length of packet header */
#define MAX_NO_OF_REMAINING_LENGTH_BYTES 4

/**
 * Encodes the message length according to the MQTT algorithm
 * @param buf the buffer into which the encoded data is written
 * @param length the length to be encoded
 * @return the number of bytes written to buffer
 */
size_t mqtt_internal_write_len_to_buffer(unsigned char *buf, uint32_t length) {
	size_t outLen = 0;
	unsigned char encodedByte;

	FUNC_ENTRY;
	do {
		encodedByte = (unsigned char) (length % 128);
		length /= 128;
		/* if there are more digits to encode, set the top bit of this digit */
		if(length > 0) {
			encodedByte |= 0x80;
		}
		buf[outLen++] = encodedByte;
	} while(length > 0);

	FUNC_EXIT_RC(outLen);
}

/**
 * Decodes the message length according to the MQTT algorithm
 * @param the buffer containing the message
 * @param value the decoded length returned
 * @return the number of bytes read from the socket
 */
IoT_Error_t mqtt_internal_decode_remaining_length_from_buffer(unsigned char *buf, uint32_t *decodedLen,
																	  uint32_t *readBytesLen) {
	unsigned char encodedByte;
	uint32_t multiplier, len;
	FUNC_ENTRY;

	multiplier = 1;
	len = 0;
	*decodedLen = 0;

	do {
		if(++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
			/* bad data */
			FUNC_EXIT_RC(MQTT_DECODE_REMAINING_LENGTH_ERROR);
		}
		encodedByte = *buf;
		buf++;
		*decodedLen += (encodedByte & 127) * multiplier;
		multiplier *= 128;
	} while((encodedByte & 128) != 0);

	*readBytesLen = len;

	FUNC_EXIT_RC(MQTT_SUCCESS);
}

uint32_t mqtt_internal_get_final_packet_length_from_remaining_length(uint32_t rem_len) {
	rem_len += 1; /* header byte */
	/* now remaining_length field (MQTT 3.1.1 - 2.2.3)*/
	if(rem_len < 128) {
		rem_len += 1;
	} else if(rem_len < 16384) {
		rem_len += 2;
	} else if(rem_len < 2097152) {
		rem_len += 3;
	} else {
		rem_len += 4;
	}
	return rem_len;
}

/**
 * Calculates uint16 packet id from two bytes read from the input buffer
 * Checks Endianness at runtime
 *
 * @param pptr pointer to the input buffer - incremented by the number of bytes used & returned
 * @return the value calculated
 */
uint16_t mqtt_internal_read_uint16_t(unsigned char **pptr) {
	unsigned char *ptr = *pptr;
	uint16_t len = 0;
	uint8_t firstByte = (uint8_t) (*ptr);
	uint8_t secondByte = (uint8_t) (*(ptr + 1));
	len = (uint16_t) (secondByte + (256 * firstByte));

	*pptr += 2;
	return len;
}

/**
 * Writes an integer as 2 bytes to an output buffer.
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param anInt the integer to write
 */
void mqtt_internal_write_uint_16(unsigned char **pptr, uint16_t anInt) {
	**pptr = (unsigned char) (anInt / 256);
	(*pptr)++;
	**pptr = (unsigned char) (anInt % 256);
	(*pptr)++;
}

/**
 * Reads one character from the input buffer.
 * @param pptr pointer to the input buffer - incremented by the number of bytes used & returned
 * @return the character read
 */
unsigned char mqtt_internal_read_char(unsigned char **pptr) {
	unsigned char c = **pptr;
	(*pptr)++;
	return c;
}

/**
 * Writes one character to an output buffer.
 * @param pptr pointer to the output buffer - incremented by the number of bytes used & returned
 * @param c the character to write
 */
void mqtt_internal_write_char(unsigned char **pptr, unsigned char c) {
	**pptr = c;
	(*pptr)++;
}

void mqtt_internal_write_utf8_string(unsigned char **pptr, const char *string, uint16_t stringLen) {
	/* Nothing that calls this function will have a stringLen with a size larger than 2 bytes (MQTT 3.1.1 - 1.5.3) */
	mqtt_internal_write_uint_16(pptr, stringLen);
	if(stringLen > 0) {
		memcpy(*pptr, string, stringLen);
		*pptr += stringLen;
	}
}

/**
 * Initialize the MQTTHeader structure. Used to ensure that Header bits are
 * always initialized using the proper mappings. No Endianness issues here since
 * the individual fields are all less than a byte. Also generates no warnings since
 * all fields are initialized using hex constants
 */
IoT_Error_t mqtt_internal_init_header(MQTTHeader *pHeader, MessageTypes message_type,
											  QoS qos, uint8_t dup, uint8_t retained) {
	FUNC_ENTRY;

	if(NULL == pHeader) {
		FUNC_EXIT_RC(NULL_VALUE_ERROR);
	}

	/* Set all bits to zero */
	pHeader->byte = 0;
	switch(message_type) {
		case UNKNOWN:
			/* Should never happen */
			return MQTT_FAILURE;
		case CONNECT:
			pHeader->bits.type = 0x01;
			break;
		case CONNACK:
			pHeader->bits.type = 0x02;
			break;
		case PUBLISH:
			pHeader->bits.type = 0x03;
			break;
		case PUBACK:
			pHeader->bits.type = 0x04;
			break;
		case PUBREC:
			pHeader->bits.type = 0x05;
			break;
		case PUBREL:
			pHeader->bits.type = 0x06;
			break;
		case PUBCOMP:
			pHeader->bits.type = 0x07;
			break;
		case SUBSCRIBE:
			pHeader->bits.type = 0x08;
			break;
		case SUBACK:
			pHeader->bits.type = 0x09;
			break;
		case UNSUBSCRIBE:
			pHeader->bits.type = 0x0A;
			break;
		case UNSUBACK:
			pHeader->bits.type = 0x0B;
			break;
		case PINGREQ:
			pHeader->bits.type = 0x0C;
			break;
		case PINGRESP:
			pHeader->bits.type = 0x0D;
			break;
		case DISCONNECT:
			pHeader->bits.type = 0x0E;
			break;
		default:
			/* Should never happen */
		FUNC_EXIT_RC(MQTT_FAILURE);
	}

	pHeader->bits.dup = (1 == dup) ? 0x01 : 0x00;
	switch(qos) {
		case QOS0:
			pHeader->bits.qos = 0x00;
			break;
		case QOS1:
			pHeader->bits.qos = 0x01;
			break;
		default:
			/* Using QOS0 as default */
			pHeader->bits.qos = 0x00;
			break;
	}

	pHeader->bits.retain = (1 == retained) ? 0x01 : 0x00;

	FUNC_EXIT_RC(MQTT_SUCCESS);
}

IoT_Error_t mqtt_internal_send_packet(MQTT_Client *pClient, size_t length, Timer *pTimer) {

	size_t sentLen, sent;
	IoT_Error_t rc;

	FUNC_ENTRY;

	if(NULL == pClient || NULL == pTimer) {
		FUNC_EXIT_RC(NULL_VALUE_ERROR);
	}

	if(length >= pClient->clientData.writeBufSize) {
		FUNC_EXIT_RC(MQTT_TX_BUFFER_TOO_SHORT_ERROR);
	}

#ifdef _ENABLE_THREAD_SUPPORT_
	rc = mqtt_client_lock_mutex(pClient, &(pClient->clientData.tls_write_mutex));
	if(MQTT_SUCCESS != rc) {
		FUNC_EXIT_RC(rc);
	}
#endif

	sentLen = 0;
	sent = 0;

	while(sent < length && !has_timer_expired(pTimer)) {
		rc = pClient->networkStack.write(&(pClient->networkStack), &pClient->clientData.writeBuf[sent], length, pTimer,
										 &sentLen);
		if(MQTT_SUCCESS != rc) {
			/* there was an error writing the data */
			break;
		}
		sent += sentLen;
	}

#ifdef _ENABLE_THREAD_SUPPORT_
	rc = mqtt_client_unlock_mutex(pClient, &(pClient->clientData.tls_write_mutex));
	if(MQTT_SUCCESS != rc) {
		FUNC_EXIT_RC(rc);
	}
#endif

	if(sent == length) {
		/* record the fact that we have successfully sent the packet */
		//countdown_sec(&c->pingTimer, c->clientData.keepAliveInterval);
		FUNC_EXIT_RC(MQTT_SUCCESS);
	}

	FUNC_EXIT_RC(MQTT_FAILURE);
}

static IoT_Error_t _aws_iot_mqtt_internal_decode_packet_remaining_len(MQTT_Client *pClient,
																	  size_t *rem_len, Timer *pTimer) {
	unsigned char encodedByte;
	size_t multiplier, len;
	IoT_Error_t rc;

	FUNC_ENTRY;

	multiplier = 1;
	len = 0;
	*rem_len = 0;

	do {
		if(++len > MAX_NO_OF_REMAINING_LENGTH_BYTES) {
			/* bad data */
			FUNC_EXIT_RC(MQTT_DECODE_REMAINING_LENGTH_ERROR);
		}

		rc = pClient->networkStack.read(&(pClient->networkStack), &encodedByte, 1, pTimer, &len);
		if(MQTT_SUCCESS != rc) {
			FUNC_EXIT_RC(rc);
		}

		*rem_len += ((encodedByte & 127) * multiplier);
		multiplier *= 128;
	} while((encodedByte & 128) != 0);

	FUNC_EXIT_RC(rc);
}

static IoT_Error_t _aws_iot_mqtt_internal_read_packet(MQTT_Client *pClient, Timer *pTimer, uint8_t *pPacketType) {
	size_t len, rem_len, total_bytes_read, bytes_to_be_read, read_len;
	IoT_Error_t rc;
	MQTTHeader header = {0};
	Timer packetTimer;
	init_timer(&packetTimer);
	countdown_ms(&packetTimer, pClient->clientData.packetTimeoutMs);

	len = 0;
	rem_len = 0;
	total_bytes_read = 0;
	bytes_to_be_read = 0;
	read_len = 0;

	rc = pClient->networkStack.read(&(pClient->networkStack), pClient->clientData.readBuf, 1, pTimer, &read_len);
	/* 1. read the header byte.  This has the packet type in it */
	if(NETWORK_SSL_NOTHING_TO_READ == rc) {
		return MQTT_NOTHING_TO_READ;
	} else if(MQTT_SUCCESS != rc) {
		return rc;
	}

	len = 1;

	/* Use the constant packet receive timeout, instead of the variable (remaining) pTimer time, to
	 * determine packet receiving timeout. This is done so we don't prematurely time out packet receiving
	 * if the remaining time in pTimer is too short.
	 */
	pTimer = &packetTimer;

	/* 2. read the remaining length.  This is variable in itself */
	rc = _aws_iot_mqtt_internal_decode_packet_remaining_len(pClient, &rem_len, pTimer);
	if(MQTT_SUCCESS != rc) {
		return rc;
	}

	/* if the buffer is too short then the message will be dropped silently */
	if(rem_len >= pClient->clientData.readBufSize) {
		bytes_to_be_read = pClient->clientData.readBufSize;
		do {
			rc = pClient->networkStack.read(&(pClient->networkStack), pClient->clientData.readBuf, bytes_to_be_read,
											pTimer, &read_len);
			if(MQTT_SUCCESS == rc) {
				total_bytes_read += read_len;
				if((rem_len - total_bytes_read) >= pClient->clientData.readBufSize) {
					bytes_to_be_read = pClient->clientData.readBufSize;
				} else {
					bytes_to_be_read = rem_len - total_bytes_read;
				}
			}
		} while(total_bytes_read < rem_len && MQTT_SUCCESS == rc);
		return MQTT_RX_BUFFER_TOO_SHORT_ERROR;
	}

	/* put the original remaining length into the read buffer */
	len += mqtt_internal_write_len_to_buffer(pClient->clientData.readBuf + 1, (uint32_t) rem_len);

	/* 3. read the rest of the buffer using a callback to supply the rest of the data */
	if(rem_len > 0) {
		rc = pClient->networkStack.read(&(pClient->networkStack), pClient->clientData.readBuf + len, rem_len, pTimer,
										&read_len);
		if(MQTT_SUCCESS != rc || read_len != rem_len) {
			return MQTT_FAILURE;
		}
	}

	header.byte = pClient->clientData.readBuf[0];
	*pPacketType = header.bits.type;

	FUNC_EXIT_RC(rc);
}

// assume topic filter and name is in correct format
// # can only be at end
// + and # can only be next to separator
static char _aws_iot_mqtt_internal_is_topic_matched(char *pTopicFilter, char *pTopicName, uint16_t topicNameLen) {

	char *curf, *curn, *curn_end;

	if(NULL == pTopicFilter || NULL == pTopicName) {
		return NULL_VALUE_ERROR;
	}

	curf = pTopicFilter;
	curn = pTopicName;
	curn_end = curn + topicNameLen;

	while(*curf && (curn < curn_end)) {
		if(*curn == '/' && *curf != '/') {
			break;
		}
		if(*curf != '+' && *curf != '#' && *curf != *curn) {
			break;
		}
		if(*curf == '+') {
			/* skip until we meet the next separator, or end of string */
			char *nextpos = curn + 1;
			while(nextpos < curn_end && *nextpos != '/')
				nextpos = ++curn + 1;
		} else if(*curf == '#') {
			/* skip until end of string */
			curn = curn_end - 1;
		}

		curf++;
		curn++;
	};

	return (curn == curn_end) && (*curf == '\0');
}

static IoT_Error_t _aws_iot_mqtt_internal_deliver_message(MQTT_Client *pClient, char *pTopicName,
														  uint16_t topicNameLen,
														  IoT_Publish_Message_Params *pMessageParams) {
	uint32_t itr;
	IoT_Error_t rc;
	ClientState clientState;

	FUNC_ENTRY;

	if(NULL == pTopicName) {
		FUNC_EXIT_RC(NULL_VALUE_ERROR);
	}

	/* This function can be called from all MQTT APIs
	 * But while callback return is in progress, Yield should not be called.
	 * The state for CB_RETURN accomplishes that, as yield cannot be called while in that state */
	clientState = mqtt_get_client_state(pClient);
	rc = mqtt_set_client_state(pClient, clientState, CLIENT_STATE_CONNECTED_WAIT_FOR_CB_RETURN);

	/* Find the right message handler - indexed by topic */
	for(itr = 0; itr < MQTT_NUM_SUBSCRIBE_HANDLERS; ++itr) {
		if(NULL != pClient->clientData.messageHandlers[itr].topicName) {
			if(((topicNameLen == pClient->clientData.messageHandlers[itr].topicNameLen)
				&&
				(strncmp(pTopicName, (char *) pClient->clientData.messageHandlers[itr].topicName, topicNameLen) == 0))
			   || _aws_iot_mqtt_internal_is_topic_matched((char *) pClient->clientData.messageHandlers[itr].topicName,
														  pTopicName, topicNameLen)) {
				if(NULL != pClient->clientData.messageHandlers[itr].pApplicationHandler) {
					pClient->clientData.messageHandlers[itr].pApplicationHandler(pClient, pTopicName, topicNameLen,
																				 pMessageParams,
																				 pClient->clientData.messageHandlers[itr].pApplicationHandlerData);
				}
			}
		}
	}
	rc = mqtt_set_client_state(pClient, CLIENT_STATE_CONNECTED_WAIT_FOR_CB_RETURN, clientState);

	FUNC_EXIT_RC(rc);
}

static IoT_Error_t _aws_iot_mqtt_internal_handle_publish(MQTT_Client *pClient, Timer *pTimer) {
	char *topicName;
	uint16_t topicNameLen;
	uint32_t len;
	IoT_Error_t rc;
	IoT_Publish_Message_Params msg;
	Timer timer;

	FUNC_ENTRY;

	topicName = NULL;
	topicNameLen = 0;
	len = 0;

	rc = mqtt_internal_deserialize_publish(&msg.isDup, &msg.qos, &msg.isRetained,
												   &msg.id, &topicName, &topicNameLen,
												   (unsigned char **) &msg.payload, &msg.payloadLen,
												   pClient->clientData.readBuf,
												   pClient->clientData.readBufSize);

	if(MQTT_SUCCESS != rc) {
		FUNC_EXIT_RC(rc);
	}

	rc = _aws_iot_mqtt_internal_deliver_message(pClient, topicName, topicNameLen, &msg);
	if(MQTT_SUCCESS != rc) {
		FUNC_EXIT_RC(rc);
	}

	if(QOS0 == msg.qos) {
		/* No further processing required for QoS0 */
		FUNC_EXIT_RC(MQTT_SUCCESS);
	}

	/* Message assumed to be QoS1 since we do not support QoS2 at this time */
	rc = mqtt_internal_serialize_ack(pClient->clientData.writeBuf, pClient->clientData.writeBufSize,
											 PUBACK, 0, msg.id, &len);

	if(MQTT_SUCCESS != rc) {
		FUNC_EXIT_RC(rc);
	}

    init_timer(&timer);
    countdown_ms(&timer, pClient->clientData.commandTimeoutMs);

	rc = mqtt_internal_send_packet(pClient, len, &timer);
	if(MQTT_SUCCESS != rc) {
		FUNC_EXIT_RC(rc);
	}

	FUNC_EXIT_RC(MQTT_SUCCESS);
}

IoT_Error_t mqtt_internal_cycle_read(MQTT_Client *pClient, Timer *pTimer, uint8_t *pPacketType) {
	IoT_Error_t rc;

#ifdef _ENABLE_THREAD_SUPPORT_
	IoT_Error_t threadRc;
#endif

	if(NULL == pClient || NULL == pTimer) {
		return NULL_VALUE_ERROR;
	}

#ifdef _ENABLE_THREAD_SUPPORT_
	threadRc = mqtt_client_lock_mutex(pClient, &(pClient->clientData.tls_read_mutex));
	if(MQTT_SUCCESS != threadRc) {
		FUNC_EXIT_RC(threadRc);
	}
#endif

	/* read the socket, see what work is due */
	rc = _aws_iot_mqtt_internal_read_packet(pClient, pTimer, pPacketType);

#ifdef _ENABLE_THREAD_SUPPORT_
	threadRc = mqtt_client_unlock_mutex(pClient, &(pClient->clientData.tls_read_mutex));
	if(MQTT_SUCCESS != threadRc && (MQTT_NOTHING_TO_READ == rc || MQTT_SUCCESS == rc)) {
		return threadRc;
	}
#endif

	if(MQTT_NOTHING_TO_READ == rc) {
		/* Nothing to read, not a cycle failure */
		return MQTT_SUCCESS;
	} else if(MQTT_SUCCESS != rc) {
		return rc;
	}

	switch(*pPacketType) {
		case CONNACK:
		case PUBACK:
		case SUBACK:
		case UNSUBACK:
			/* SDK is blocking, these responses will be forwarded to calling function to process */
			break;
		case PUBLISH: {
			rc = _aws_iot_mqtt_internal_handle_publish(pClient, pTimer);
			break;
		}
		case PUBREC:
		case PUBCOMP:
			/* QoS2 not supported at this time */
			break;
		case PINGRESP: {
			pClient->clientStatus.isPingOutstanding = 0;
			countdown_sec(&pClient->pingTimer, pClient->clientData.keepAliveInterval);
			break;
		}
		default: {
			/* Either unknown packet type or Failure occurred
             * Should not happen */
			rc = MQTT_RX_MESSAGE_PACKET_TYPE_INVALID_ERROR;
			break;
		}
	}

	return rc;
}

/* only used in single-threaded mode where one command at a time is in process */
IoT_Error_t mqtt_internal_wait_for_read(MQTT_Client *pClient, uint8_t packetType, Timer *pTimer) {
	IoT_Error_t rc;
	uint8_t read_packet_type;

	FUNC_ENTRY;
	if(NULL == pClient || NULL == pTimer) {
		FUNC_EXIT_RC(NULL_VALUE_ERROR);
	}

	read_packet_type = 0;
	do {
		if(has_timer_expired(pTimer)) {
			/* we timed out */
			rc = MQTT_REQUEST_TIMEOUT_ERROR;
			break;
		}
		rc = mqtt_internal_cycle_read(pClient, pTimer, &read_packet_type);
	} while(NETWORK_DISCONNECTED_ERROR != rc && read_packet_type != packetType);

	if(MQTT_REQUEST_TIMEOUT_ERROR != rc && NETWORK_DISCONNECTED_ERROR != rc && read_packet_type != packetType) {
		FUNC_EXIT_RC(MQTT_FAILURE);
	}

	/* Something failed or we didn't receive the expected packet, return error code */
	FUNC_EXIT_RC(rc);
}

/**
  * Serializes a 0-length packet into the supplied buffer, ready for writing to a socket
  * @param buf the buffer into which the packet will be serialized
  * @param buflen the length in bytes of the supplied buffer, to avoid overruns
  * @param packettype the message type
  * @param serialized length
  * @return IoT_Error_t indicating function execution status
  */
IoT_Error_t mqtt_internal_serialize_zero(unsigned char *pTxBuf, size_t txBufLen, MessageTypes packetType,
												 size_t *pSerializedLength) {
	unsigned char *ptr;
	IoT_Error_t rc;
	MQTTHeader header = {0};

	FUNC_ENTRY;
	if(NULL == pTxBuf || NULL == pSerializedLength) {
		FUNC_EXIT_RC(NULL_VALUE_ERROR);
	}

	/* Buffer should have at least 2 bytes for the header */
	if(4 > txBufLen) {
		FUNC_EXIT_RC(MQTT_TX_BUFFER_TOO_SHORT_ERROR);
	}

	ptr = pTxBuf;

	rc = mqtt_internal_init_header(&header, packetType, QOS0, 0, 0);
	if(MQTT_SUCCESS != rc) {
		FUNC_EXIT_RC(rc);
	}

	/* write header */
	mqtt_internal_write_char(&ptr, header.byte);

	/* write remaining length */
	ptr += mqtt_internal_write_len_to_buffer(ptr, 0);
	*pSerializedLength = (uint32_t) (ptr - pTxBuf);

	FUNC_EXIT_RC(MQTT_SUCCESS);
}

#ifdef __cplusplus
}
#endif
