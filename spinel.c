#include "spinel.h"

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/types.h>

#define SPINEL_MAX_PACK_LENGTH 32767

#define CHAR_BIT 8

spinel_ssize_t spinel_packed_uint_decode(const uint8_t *bytes, spinel_size_t len,
					 unsigned int *value_ptr)
{
	spinel_ssize_t ret = 0;
	unsigned int value = 0;

	unsigned int i = 0;

	do {
		if ((len < sizeof(uint8_t)) || (i >= sizeof(unsigned int) * CHAR_BIT)) {
			ret = -1;
			break;
		}

		value |= (unsigned int)(bytes[0] & 0x7F) << i;
		i += 7;
		ret += sizeof(uint8_t);
		bytes += sizeof(uint8_t);
		len -= sizeof(uint8_t);
	} while ((bytes[-1] & 0x80) == 0x80);

	if ((ret > 0) && (value_ptr != NULL)) {
		*value_ptr = value;
	}

	return ret;
}

// This function validates whether a given byte sequence (string) follows UTF8 encoding.
static bool spinel_validate_utf8(const uint8_t *string)
{
	bool ret = true;
	uint8_t byte;
	uint8_t continuation_bytes = 0;

	while ((byte = *string++) != 0) {
		if ((byte & 0x80) == 0) {
			continue;
		}

		// This is a leading byte 1xxx-xxxx.

		if ((byte & 0x40) == 0) // 10xx-xxxx
		{
			// We got a continuation byte pattern without seeing a leading byte earlier.
			ret = false;
			goto bail;
		} else if ((byte & 0x20) == 0) // 110x-xxxx
		{
			continuation_bytes = 1;
		} else if ((byte & 0x10) == 0) // 1110-xxxx
		{
			continuation_bytes = 2;
		} else if ((byte & 0x08) == 0) // 1111-0xxx
		{
			continuation_bytes = 3;
		} else // 1111-1xxx  (invalid pattern).
		{
			ret = false;
			goto bail;
		}

		while (continuation_bytes-- != 0) {
			byte = *string++;

			// Verify the continuation byte pattern 10xx-xxxx
			if ((byte & 0xc0) != 0x80) {
				ret = false;
				goto bail;
			}
		}
	}

bail:
	return ret;
}

spinel_ssize_t spinel_packed_uint_size(unsigned int value)
{
	spinel_ssize_t ret;

	if (value < (1 << 7)) {
		ret = 1;
	} else if (value < (1 << 14)) {
		ret = 2;
	} else if (value < (1 << 21)) {
		ret = 3;
	} else if (value < (1 << 28)) {
		ret = 4;
	} else {
		ret = 5;
	}

	return ret;
}

spinel_ssize_t spinel_packed_uint_encode(uint8_t *bytes, spinel_size_t len, unsigned int value)
{
	const spinel_ssize_t encoded_size = spinel_packed_uint_size(value);

	if ((spinel_ssize_t)len >= encoded_size) {
		spinel_ssize_t i;

		for (i = 0; i != encoded_size - 1; ++i) {
			*bytes++ = (value & 0x7F) | 0x80;
			value = (value >> 7);
		}

		*bytes++ = (value & 0x7F);
	}

	return encoded_size;
}

const char *spinel_next_packed_datatype(const char *pack_format)
{
	int depth = 0;

	do {
		switch (*++pack_format) {
		case '(':
			depth++;
			break;

		case ')':
			depth--;

			if (depth == 0) {
				pack_format++;
			}

			break;
		}
	} while ((depth > 0) && *pack_format != 0);

	return pack_format;
}

static spinel_ssize_t spinel_datatype_vunpack_(bool in_place, const uint8_t *data_in,
					       spinel_size_t data_len, const char *pack_format,
					       va_list args)
{
	spinel_ssize_t ret = 0;

	// Buffer length sanity check
	if (!(data_len <= SPINEL_MAX_PACK_LENGTH)) {
		ret = -EINVAL;
		goto bail;
	}

	for (; *pack_format != 0; pack_format = spinel_next_packed_datatype(pack_format)) {
		// pr_debug("%s: %d format %c\n", __func__, __LINE__, *pack_format);
		if (*pack_format == ')') {
			// Don't go past the end of a struct.
			break;
		}

		switch ((spinel_datatype_t)pack_format[0]) {
		case SPINEL_DATATYPE_BOOL_C: {
			bool *arg_ptr = va_arg(args, bool *);
			if (!(data_len >= sizeof(uint8_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (arg_ptr) {
				*arg_ptr = data_in[0] != 0;
			}

			ret += sizeof(uint8_t);
			data_in += sizeof(uint8_t);
			data_len -= sizeof(uint8_t);
			break;
		}

		case SPINEL_DATATYPE_INT8_C:
		case SPINEL_DATATYPE_UINT8_C: {
			uint8_t *arg_ptr = va_arg(args, uint8_t *);
			if (!(data_len >= sizeof(uint8_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (arg_ptr) {
				*arg_ptr = data_in[0];
			}

			ret += sizeof(uint8_t);
			data_in += sizeof(uint8_t);
			data_len -= sizeof(uint8_t);
			break;
		}

		case SPINEL_DATATYPE_INT16_C:
		case SPINEL_DATATYPE_UINT16_C: {
			uint16_t *arg_ptr = va_arg(args, uint16_t *);
			if (!(data_len >= sizeof(uint16_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (arg_ptr) {
				*arg_ptr = (uint16_t)((data_in[1] << 8) | data_in[0]);
			}

			ret += sizeof(uint16_t);
			data_in += sizeof(uint16_t);
			data_len -= sizeof(uint16_t);
			break;
		}

		case SPINEL_DATATYPE_INT32_C:
		case SPINEL_DATATYPE_UINT32_C: {
			uint32_t *arg_ptr = va_arg(args, uint32_t *);
			if (!(data_len >= sizeof(uint32_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (arg_ptr) {
				*arg_ptr = (uint32_t)((data_in[3] << 24) | (data_in[2] << 16) |
						      (data_in[1] << 8) | data_in[0]);
			}

			ret += sizeof(uint32_t);
			data_in += sizeof(uint32_t);
			data_len -= sizeof(uint32_t);
			break;
		}

		case SPINEL_DATATYPE_INT64_C:
		case SPINEL_DATATYPE_UINT64_C: {
			uint64_t *arg_ptr = va_arg(args, uint64_t *);
			if (!(data_len >= sizeof(uint64_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (arg_ptr) {
				uint32_t l32 = (uint32_t)((data_in[3] << 24) | (data_in[2] << 16) |
							  (data_in[1] << 8) | data_in[0]);
				uint32_t h32 = (uint32_t)((data_in[7] << 24) | (data_in[6] << 16) |
							  (data_in[5] << 8) | data_in[4]);

				*arg_ptr = ((uint64_t)l32) | (((uint64_t)h32) << 32);
			}

			ret += sizeof(uint64_t);
			data_in += sizeof(uint64_t);
			data_len -= sizeof(uint64_t);
			break;
		}

		case SPINEL_DATATYPE_IPv6ADDR_C: {
			if (!(data_len >= sizeof(spinel_ipv6addr_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (in_place) {
				spinel_ipv6addr_t *arg = va_arg(args, spinel_ipv6addr_t *);
				if (arg) {
					memcpy(arg, data_in, sizeof(spinel_ipv6addr_t));
				}
			} else {
				const spinel_ipv6addr_t **arg_ptr =
					va_arg(args, const spinel_ipv6addr_t **);
				if (arg_ptr) {
					*arg_ptr = (const spinel_ipv6addr_t *)data_in;
				}
			}

			ret += sizeof(spinel_ipv6addr_t);
			data_in += sizeof(spinel_ipv6addr_t);
			data_len -= sizeof(spinel_ipv6addr_t);
			break;
		}

		case SPINEL_DATATYPE_EUI64_C: {
			if (!(data_len >= sizeof(spinel_eui64_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (in_place) {
				spinel_eui64_t *arg = va_arg(args, spinel_eui64_t *);
				if (arg) {
					memcpy(arg, data_in, sizeof(spinel_eui64_t));
				}
			} else {
				const spinel_eui64_t **arg_ptr =
					va_arg(args, const spinel_eui64_t **);
				if (arg_ptr) {
					*arg_ptr = (const spinel_eui64_t *)data_in;
				}
			}

			ret += sizeof(spinel_eui64_t);
			data_in += sizeof(spinel_eui64_t);
			data_len -= sizeof(spinel_eui64_t);
			break;
		}

		case SPINEL_DATATYPE_EUI48_C: {
			if (!(data_len >= sizeof(spinel_eui48_t))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (in_place) {
				spinel_eui48_t *arg = va_arg(args, spinel_eui48_t *);
				if (arg) {
					memcpy(arg, data_in, sizeof(spinel_eui48_t));
				}
			} else {
				const spinel_eui48_t **arg_ptr =
					va_arg(args, const spinel_eui48_t **);
				if (arg_ptr) {
					*arg_ptr = (const spinel_eui48_t *)data_in;
				}
			}

			ret += sizeof(spinel_eui48_t);
			data_in += sizeof(spinel_eui48_t);
			data_len -= sizeof(spinel_eui48_t);
			break;
		}

		case SPINEL_DATATYPE_UINT_PACKED_C: {
			unsigned int *arg_ptr = va_arg(args, unsigned int *);
			spinel_ssize_t pui_len =
				spinel_packed_uint_decode(data_in, data_len, arg_ptr);

			// Range check
			if (!(NULL == arg_ptr || (*arg_ptr < SPINEL_MAX_UINT_PACKED))) {
				ret = -ERANGE;
				goto bail;
			}

			if (!(pui_len > 0)) {
				goto bail;
			}

			if (!(pui_len <= (spinel_ssize_t)data_len)) {
				goto bail;
			}

			ret += pui_len;
			data_in += pui_len;
			data_len -= (spinel_size_t)pui_len;
			break;
		}

		case SPINEL_DATATYPE_UTF8_C: {
			size_t len;

			// Make sure we have at least one byte.
			if (!(data_len > 0)) {
				ret = -EOVERFLOW;
				goto bail;
			}

			// Add 1 for zero termination. If not zero terminated,
			// len will then be data_len+1, which we will detect
			// in the next check.
			len = strnlen((const char *)data_in, data_len) + 1;

			// Verify that the string is zero terminated.
			if (!(len <= data_len)) {
				ret = -EOVERFLOW;
				goto bail;
			}

			// Verify the string follows valid UTF8 encoding.
			if (!(spinel_validate_utf8(data_in))) {
				ret = -EINVAL;
				goto bail;
			}

			if (in_place) {
				char *arg = va_arg(args, char *);
				size_t len_arg = va_arg(args, size_t);
				if (arg) {
					if (!(len_arg >= len)) {
						ret = -ENOMEM;
						goto bail;
					}
					memcpy(arg, data_in, len);
				}
			} else {
				const char **arg_ptr = va_arg(args, const char **);
				if (arg_ptr) {
					*arg_ptr = (const char *)data_in;
				}
			}

			ret += (spinel_size_t)len;
			data_in += len;
			data_len -= (spinel_size_t)len;
			break;
		}

		case SPINEL_DATATYPE_DATA_C:
		case SPINEL_DATATYPE_DATA_WLEN_C: {
			spinel_ssize_t pui_len = 0;
			uint16_t block_len = 0;
			const uint8_t *block_ptr = data_in;
			void *arg_ptr = va_arg(args, void *);
			unsigned int *block_len_ptr = va_arg(args, unsigned int *);
			char nextformat = *spinel_next_packed_datatype(pack_format);

			// pr_debug("%s: %d DATA_C\n", __func__, __LINE__);

			if ((pack_format[0] == SPINEL_DATATYPE_DATA_WLEN_C) ||
			    ((nextformat != 0) && (nextformat != ')'))) {
				pui_len = spinel_datatype_unpack(
					data_in, data_len, SPINEL_DATATYPE_UINT16_S, &block_len);
				block_ptr += pui_len;

				if (!(pui_len > 0)) {
					goto bail;
				}
				if (!(block_len < SPINEL_FRAME_MAX_SIZE)) {
					goto bail;
				}
			} else {
				block_len = (uint16_t)data_len;
				pui_len = 0;
			}

			if (!((spinel_ssize_t)data_len >= (block_len + pui_len))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (in_place) {
				if (!(NULL != block_len_ptr && *block_len_ptr >= block_len)) {
					ret = -EINVAL;
					goto bail;
				}
				memcpy(arg_ptr, block_ptr, block_len);
			} else {
				const uint8_t **block_ptr_ptr = (const uint8_t **)arg_ptr;
				if (NULL != block_ptr_ptr) {
					*block_ptr_ptr = block_ptr;
				}
			}

			if (NULL != block_len_ptr) {
				*block_len_ptr = block_len;
			}

			block_len += (uint16_t)pui_len;
			ret += block_len;
			data_in += block_len;
			data_len -= block_len;
			break;
		}

		case 'T':
		case SPINEL_DATATYPE_STRUCT_C: {
			spinel_ssize_t pui_len = 0;
			uint16_t block_len = 0;
			spinel_ssize_t actual_len = 0;
			const uint8_t *block_ptr = data_in;
			char nextformat = *spinel_next_packed_datatype(pack_format);

			if ((pack_format[0] == SPINEL_DATATYPE_STRUCT_C) ||
			    ((nextformat != 0) && (nextformat != ')'))) {
				pui_len = spinel_datatype_unpack(
					data_in, data_len, SPINEL_DATATYPE_UINT16_S, &block_len);
				block_ptr += pui_len;

				if (!(pui_len > 0)) {
					goto bail;
				}
				if (!(block_len < SPINEL_FRAME_MAX_SIZE)) {
					goto bail;
				}
			} else {
				block_len = (uint16_t)data_len;
				pui_len = 0;
			}

			if (!((spinel_ssize_t)data_len >= (block_len + pui_len))) {
				ret = -EOVERFLOW;
				goto bail;
			}

			actual_len = spinel_datatype_vunpack_(false, block_ptr, block_len,
							      pack_format + 2, args);

			if (!(actual_len > -1)) {
				ret = -EOVERFLOW;
				goto bail;
			}

			if (pui_len) {
				block_len += (uint16_t)pui_len;
			} else {
				block_len = (uint16_t)actual_len;
			}

			ret += block_len;
			data_in += block_len;
			data_len -= block_len;
			break;
		}

		case '.':
			// Skip.
			break;

		case SPINEL_DATATYPE_ARRAY_C:
		default:
			// Unsupported Type!
			ret = -EINVAL;
			goto bail;
		}
	}

	return ret;

bail:
	return ret;
}

static int spinel_datatype_vpack_(uint8_t *data_out, size_t data_len_max, const char *pack_format,
				  va_list *args)
{
	spinel_ssize_t ret = 0;

	if (!(data_len_max <= SPINEL_MAX_PACK_LENGTH)) {
		// pr_debug("%s: %d \n", __func__, __LINE__);
		ret = -EINVAL;
		goto bail;
	}

	if (data_out == NULL) {
		// pr_debug("%s: %d \n", __func__, __LINE__);
		data_len_max = 0;
	}

	for (; *pack_format != 0; pack_format = spinel_next_packed_datatype(pack_format)) {
		// pr_debug("%s: %d format %c\n", __func__, __LINE__, *pack_format);
		if (*pack_format == ')') {
			// Don't go past the end of a struct.
			break;
		}

		switch ((spinel_datatype_t)*pack_format) {
		case SPINEL_DATATYPE_BOOL_C: {
			bool arg = (bool)va_arg(*args, int);
			ret += sizeof(uint8_t);

			if (data_len_max >= sizeof(uint8_t)) {
				data_out[0] = (arg != false);
				data_out += sizeof(uint8_t);
				data_len_max -= sizeof(uint8_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_INT8_C:
		case SPINEL_DATATYPE_UINT8_C: {
			uint8_t arg = (uint8_t)va_arg(*args, int);
			ret += sizeof(uint8_t);

			if (data_len_max >= sizeof(uint8_t)) {
				data_out[0] = arg;
				data_out += sizeof(uint8_t);
				data_len_max -= sizeof(uint8_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_INT16_C:
		case SPINEL_DATATYPE_UINT16_C: {
			uint16_t arg = (uint16_t)va_arg(*args, int);
			ret += sizeof(uint16_t);

			if (data_len_max >= sizeof(uint16_t)) {
				data_out[1] = (arg >> 8) & 0xff;
				data_out[0] = (arg >> 0) & 0xff;
				data_out += sizeof(uint16_t);
				data_len_max -= sizeof(uint16_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_INT32_C:
		case SPINEL_DATATYPE_UINT32_C: {
			uint32_t arg = (uint32_t)va_arg(*args, int);
			ret += sizeof(uint32_t);

			if (data_len_max >= sizeof(uint32_t)) {
				data_out[3] = (arg >> 24) & 0xff;
				data_out[2] = (arg >> 16) & 0xff;
				data_out[1] = (arg >> 8) & 0xff;
				data_out[0] = (arg >> 0) & 0xff;
				data_out += sizeof(uint32_t);
				data_len_max -= sizeof(uint32_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_INT64_C:
		case SPINEL_DATATYPE_UINT64_C: {
			uint64_t arg = va_arg(*args, uint64_t);

			ret += sizeof(uint64_t);

			if (data_len_max >= sizeof(uint64_t)) {
				data_out[7] = (arg >> 56) & 0xff;
				data_out[6] = (arg >> 48) & 0xff;
				data_out[5] = (arg >> 40) & 0xff;
				data_out[4] = (arg >> 32) & 0xff;
				data_out[3] = (arg >> 24) & 0xff;
				data_out[2] = (arg >> 16) & 0xff;
				data_out[1] = (arg >> 8) & 0xff;
				data_out[0] = (arg >> 0) & 0xff;
				data_out += sizeof(uint64_t);
				data_len_max -= sizeof(uint64_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_IPv6ADDR_C: {
			spinel_ipv6addr_t *arg = va_arg(*args, spinel_ipv6addr_t *);
			ret += sizeof(spinel_ipv6addr_t);

			if (data_len_max >= sizeof(spinel_ipv6addr_t)) {
				*(spinel_ipv6addr_t *)data_out = *arg;
				data_out += sizeof(spinel_ipv6addr_t);
				data_len_max -= sizeof(spinel_ipv6addr_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_EUI48_C: {
			spinel_eui48_t *arg = va_arg(*args, spinel_eui48_t *);
			ret += sizeof(spinel_eui48_t);

			if (data_len_max >= sizeof(spinel_eui48_t)) {
				*(spinel_eui48_t *)data_out = *arg;
				data_out += sizeof(spinel_eui48_t);
				data_len_max -= sizeof(spinel_eui48_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_EUI64_C: {
			spinel_eui64_t *arg = va_arg(*args, spinel_eui64_t *);
			ret += sizeof(spinel_eui64_t);

			if (data_len_max >= sizeof(spinel_eui64_t)) {
				*(spinel_eui64_t *)data_out = *arg;
				data_out += sizeof(spinel_eui64_t);
				data_len_max -= sizeof(spinel_eui64_t);
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_UINT_PACKED_C: {
			uint32_t arg = va_arg(*args, uint32_t);
			spinel_ssize_t encoded_size;

			// Range Check
			if (!(arg < SPINEL_MAX_UINT_PACKED)) {
				ret = -EINVAL;
				goto bail;
			}

			encoded_size = spinel_packed_uint_encode(data_out, data_len_max, arg);
			ret += encoded_size;

			if ((spinel_ssize_t)data_len_max >= encoded_size) {
				data_out += encoded_size;
				data_len_max -= (size_t)encoded_size;
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_UTF8_C: {
			const char *string_arg = va_arg(*args, const char *);
			size_t string_arg_len = 0;

			if (string_arg) {
				string_arg_len = strlen(string_arg) + 1;
			} else {
				string_arg = "";
				string_arg_len = 1;
			}

			ret += (size_t)string_arg_len;

			if (data_len_max >= string_arg_len) {
				memcpy(data_out, string_arg, string_arg_len);

				data_out += string_arg_len;
				data_len_max -= (size_t)string_arg_len;
			} else {
				data_len_max = 0;
			}

			break;
		}

		case SPINEL_DATATYPE_DATA_WLEN_C:
		case SPINEL_DATATYPE_DATA_C: {
			const uint8_t *arg = va_arg(*args, const uint8_t *);
			uint32_t data_size_arg = va_arg(*args, uint32_t);
			spinel_ssize_t size_len = 0;
			char nextformat = *spinel_next_packed_datatype(pack_format);

			if ((pack_format[0] == SPINEL_DATATYPE_DATA_WLEN_C) ||
			    ((nextformat != 0) && (nextformat != ')'))) {
				size_len = spinel_datatype_pack(data_out, data_len_max,
								SPINEL_DATATYPE_UINT16_S,
								data_size_arg);

				if (!(size_len > 0)) {
					ret = -EINVAL;
					goto bail;
				}
			}

			ret += (size_t)size_len + data_size_arg;

			if (data_len_max >= (size_t)size_len + data_size_arg) {
				data_out += size_len;
				data_len_max -= (size_t)size_len;

				if (data_out && arg) {
					memcpy(data_out, arg, data_size_arg);
				}

				data_out += data_size_arg;
				data_len_max -= data_size_arg;
			} else {
				data_len_max = 0;
			}

			break;
		}

		case 'T':
		case SPINEL_DATATYPE_STRUCT_C: {
			spinel_ssize_t struct_len = 0;
			spinel_ssize_t size_len = 0;
			char nextformat = *spinel_next_packed_datatype(pack_format);

			if (!(pack_format[1] == '(')) {
				ret = -EINVAL;
				goto bail;
			}

			// First we figure out the size of the struct
			{
				va_list subargs;
				va_copy(subargs, *args);
				struct_len =
					spinel_datatype_vpack_(NULL, 0, pack_format + 2, &subargs);
				va_end(subargs);
				if (struct_len < 0) {
					ret = struct_len;
					goto bail;
				}
			}

			if ((pack_format[0] == SPINEL_DATATYPE_STRUCT_C) ||
			    ((nextformat != 0) && (nextformat != ')'))) {
				size_len =
					spinel_datatype_pack(data_out, data_len_max,
							     SPINEL_DATATYPE_UINT16_S, struct_len);
				if (!(size_len > 0)) {
					ret = -EINVAL;
					goto bail;
					if (!(data_len_max <= SPINEL_MAX_PACK_LENGTH)) {
						ret = -EINVAL;
						goto bail;
					}
				}
			}

			ret += size_len + struct_len;

			if (struct_len + size_len <= (spinel_ssize_t)data_len_max) {
				data_out += size_len;
				data_len_max -= (size_t)size_len;

				struct_len = spinel_datatype_vpack_(data_out, data_len_max,
								    pack_format + 2, args);
				if (struct_len < 0) {
					ret = struct_len;
					goto bail;
				}

				data_out += struct_len;
				data_len_max -= (size_t)struct_len;
			} else {
				data_len_max = 0;
			}

			break;
		}

		case '.':
			// Skip.
			break;

		default:
			// Unsupported Type!
			ret = -EINVAL;
			goto bail;
		}
	}

bail:
	// pr_debug("%s: %d %d\n", __func__, __LINE__, ret);
	return ret;
}

int spinel_datatype_pack(uint8_t *data_out, size_t data_len_max, const char *pack_format, ...)
{
	int ret;
	va_list args;
	va_start(args, pack_format);

	ret = spinel_datatype_vpack_(data_out, data_len_max, pack_format, &args);

	va_end(args);
	return ret;
}

int spinel_datatype_vpack(uint8_t *data_out, size_t data_len_max, const char *pack_format,
			  va_list args)
{
	int ret;
	va_list dupargs;
	va_copy(dupargs, args);

	ret = spinel_datatype_vpack_(data_out, data_len_max, pack_format, &dupargs);

	va_end(args);
	return ret;
}

spinel_ssize_t spinel_datatype_unpack(const uint8_t *data_in, spinel_size_t data_len,
				      const char *pack_format, ...)
{
	spinel_ssize_t ret;
	va_list args;
	va_start(args, pack_format);

	ret = spinel_datatype_vunpack_(false, data_in, data_len, pack_format, args);

	va_end(args);
	return ret;
}

spinel_ssize_t spinel_datatype_vunpack_in_place(const uint8_t *data_in, spinel_size_t data_len,
						const char *pack_format, va_list args)
{
	spinel_ssize_t ret;

	ret = spinel_datatype_vunpack_(true, data_in, data_len, pack_format, args);

	return ret;
}

int spinel_reset_command(uint8_t *buffer, size_t length, const char *format, va_list args)
{
	int packed;

	// Pack the header, command and key
	packed = spinel_datatype_vpack(buffer, length, format, args);

	if (packed < 0)
		return packed;

	if (!(packed > 0 && packed <= sizeof(buffer)))
		return -ENOBUFS;

	return packed;
}

int spinel_command(uint8_t *buffer, size_t length, uint32_t command, spinel_prop_key_t key,
		   spinel_tid_t tid, const char *format, va_list args)
{
	int packed;
	uint16_t offset;

	// Pack the header, command and key
	packed = spinel_datatype_pack(buffer, length, "Cii",
				      SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0 | tid, command, key);

	if (packed < 0) {
		// pr_debug("%s: %d\n", __func__, __LINE__);
		return packed;
	}

	if (!(packed > 0 && packed <= sizeof(buffer))) {
		// pr_debug("%s: %d\n", __func__, __LINE__);
		return -ENOBUFS;
	}

	offset = packed;

	// Pack the data (if any)
	if (format) {
		packed = spinel_datatype_vpack(buffer + offset, length - offset, format, args);

		if (packed < 0) {
			// pr_debug("%s: %d\n", __func__, __LINE__);
			return packed;
		}

		if (!(packed > 0 && (packed + offset) <= length)) {
			// pr_debug("%s: %d\n", __func__, __LINE__);
			return -ENOBUFS;
		}

		offset += packed;
	}

	return offset;
}

int spinel_prop_get_v(struct spinel_command *cmd, spinel_prop_key_t key, const char *fmt,
		      va_list args)
{
	int err;

	mutex_lock(cmd->send_mutex);
	err = spinel_command(cmd->buffer, cmd->length, SPINEL_CMD_PROP_VALUE_GET, key, cmd->tid,
			     NULL, 0);
	if (err >= 0) {
		err = cmd->send(cmd->ctx, cmd->buffer, err, SPINEL_CMD_PROP_VALUE_SET, key,
				cmd->tid);
	}
	mutex_unlock(cmd->send_mutex);
	if (err < 0) {
		return err;
	}

	err = cmd->resp(cmd->ctx, cmd->buffer, cmd->length, SPINEL_CMD_PROP_VALUE_SET, key,
			cmd->tid);
	if (err < 0) {
		return err;
	}
	mutex_lock(cmd->resp_mutex);
	err = spinel_datatype_vunpack_in_place(cmd->buffer, err, fmt, args);
	mutex_unlock(cmd->resp_mutex);
	return err;
}

int spinel_prop_set_v(struct spinel_command *cmd, spinel_prop_key_t key, const char *fmt,
		      va_list args)
{
	int err;

	mutex_lock(cmd->send_mutex);
	err = spinel_command(cmd->buffer, cmd->length, SPINEL_CMD_PROP_VALUE_SET, key, cmd->tid,
			     fmt, args);
	if (err >= 0) {
		err = cmd->send(cmd->ctx, cmd->buffer, err, SPINEL_CMD_PROP_VALUE_SET, key,
				cmd->tid);
	}
	mutex_unlock(cmd->send_mutex);
	if (err < 0) {
		return err;
	}

	err = cmd->resp(cmd->ctx, cmd->buffer, cmd->length, SPINEL_CMD_PROP_VALUE_SET, key,
			cmd->tid);
	return err;
}

int spinel_prop_set(struct spinel_command *cmd, spinel_prop_key_t key, const char *fmt, ...)
{
	va_list args;
	int rc;
	va_start(args, fmt);
	rc = spinel_prop_set_v(cmd, key, fmt, args);
	va_end(args);
	return rc;
}

int spinel_data_array_unpack(void *out, size_t out_len, uint8_t *data, size_t len, const char *fmt,
			     size_t datasize)
{
	int rc;
	int remains = out_len;
	void *start = out;

	while (len > 0) {
		if (remains <= 0) {
			pr_debug("%s: %d shotrage \n", __func__, __LINE__);
			return -1;
		}
		rc = spinel_datatype_unpack(data, len, fmt, out);
		if (rc < 0) {
			pr_debug("%s: %d rc=%d\n", __func__, __LINE__, rc);
			return rc;
		}
		data += rc;
		out += datasize;
		len -= rc;
		remains -= datasize;
	}

	return (out - start) / datasize;
}

uint32_t spinel_expected_command(uint32_t cmd)
{
	switch (cmd) {
	case SPINEL_CMD_PROP_VALUE_SET:
		return SPINEL_CMD_PROP_VALUE_IS;
	case SPINEL_CMD_PROP_VALUE_INSERT:
		return SPINEL_CMD_PROP_VALUE_INSERTED;
	case SPINEL_CMD_PROP_VALUE_REMOVE:
		return SPINEL_CMD_PROP_VALUE_REMOVED;
	}
	return 0;
}
