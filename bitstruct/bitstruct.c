/**
 * @file   bitstruct-micropython/bitstruct/bitstruct.c
 * @author Erik Moqvist
 * @author Peter Züger
 * @date   16.10.2019
 * @brief  bitstruct C implementation for micropython
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Erik Moqvist
 * Copyright (c) 2019 Peter Züger
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "py/obj.h"
#include "py/runtime.h"
#include "py/builtin.h"
#include "py/objstr.h"
#include "py/objarray.h"
#include "py/gc.h"
#include "py/objint.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bitstream.h"

struct field_info_t;

typedef void (*pack_field_t)(struct bitstream_writer_t* self_p,
                             mp_obj_t value_p,
                             struct field_info_t* field_info_p);

typedef mp_obj_t (*unpack_field_t)(struct bitstream_reader_t* self_p,
                                   struct field_info_t* field_info_p);

#define BITORDER_LSBFIRST (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
#define BITORDER_MSBFIRST (!BITORDER_LSBFIRST)

struct field_info_t{
    pack_field_t pack;
    unpack_field_t unpack;
    int number_of_bits;
    bool is_padding;
    bool bitorder;
};

#define BYTEORDER_LSBFIRST BITORDER_LSBFIRST
#define BYTEORDER_MSBFIRST BITORDER_MSBFIRST

struct info_t{
    int number_of_bits;
    int number_of_fields;
    int number_of_non_padding_fields;
    bool byteorder;
    struct field_info_t fields[1];
};

/**
 * Python: bitstruct.Error(msg)
 * @param msg
 */
MP_DEFINE_EXCEPTION(Error, Exception);

/**
 * @raises TypeError
 */
static void is_names_list(mp_obj_t names_p){
    if(!mp_obj_is_type(names_p, &mp_type_list))
        mp_raise_TypeError("Names is not a list.");
}

static inline uint8_t reverse(uint8_t b){
    b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
    b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
    b = (b & 0xAA) >> 1 | (b & 0x55) << 1;
    return b;
}

static void pack_signed_integer(struct bitstream_writer_t* self_p,
                                mp_obj_t value_p,
                                struct field_info_t* field_info_p){
    if(mp_obj_is_type(value_p, &mp_type_int)){
        field_info_p->number_of_bits--;
        size_t size = (field_info_p->number_of_bits + 7) / 8;
        uint8_t* buffer = alloca(size);
        mp_obj_int_to_bytes_impl(value_p, field_info_p->bitorder, size, buffer);
        int sign = ((mp_obj_int_t*)value_p)->mpz.neg;

        if(!field_info_p->bitorder){
            for(size_t i = 0; i < (field_info_p->number_of_bits / 8); ++i)
                bitstream_writer_write_u8(self_p, reverse(buffer[i]));
            for(size_t i = 0; i < (field_info_p->number_of_bits % 8); ++i)
                bitstream_writer_write_bit(self_p, buffer[size - 1] >> i);
            bitstream_writer_write_bit(self_p, sign);
        }else{
            bitstream_writer_write_bit(self_p, sign);
            if(field_info_p->number_of_bits % 8){
                bitstream_writer_write_u64_bits(self_p, buffer[0], field_info_p->number_of_bits % 8);
                buffer++;
            }
            bitstream_writer_write_bytes(self_p, buffer, field_info_p->number_of_bits / 8);
        }
    }else if(mp_obj_is_integer(value_p)){
        if(field_info_p->number_of_bits > 64)
            mp_raise_NotImplementedError("unsigned integer over 64 bits");

        // raises TypeError
        int64_t value = mp_obj_get_int(value_p);

        uint64_t limit = (1ull << (field_info_p->number_of_bits - 1));
        int64_t lower = -limit;
        int64_t upper = (limit - 1);

        if((value < lower) || (value > upper))
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error, "\"s%d\" requires %d <= integer <= %d (got %d)",
                                                    field_info_p->number_of_bits,
                                                    lower,
                                                    upper,
                                                    value));

        if(field_info_p->number_of_bits < 64){
            value &= ((1ull << field_info_p->number_of_bits) - 1);
        }

        bitstream_writer_write_u64_bits(self_p,
                                        (uint64_t)value,
                                        field_info_p->number_of_bits);
    }else{
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
                                                "can't convert %s to int", mp_obj_get_type_str(value_p)));
    }
}

static mp_obj_t unpack_signed_integer(struct bitstream_reader_t* self_p,
                                      struct field_info_t* field_info_p){
    if(field_info_p->number_of_bits > 64)
        mp_raise_NotImplementedError("signed integer over 64 bits");

    uint64_t value = bitstream_reader_read_u64_bits(self_p, field_info_p->number_of_bits);
    uint64_t sign_bit = (1ull << (field_info_p->number_of_bits - 1));

    if(value & sign_bit){
        value |= ~(((sign_bit) << 1) - 1);
    }

    // raises OverflowError, MemoryError
    return mp_obj_new_int_from_ll((long long)value);
}

static void pack_unsigned_integer(struct bitstream_writer_t* self_p,
                                  mp_obj_t value_p,
                                  struct field_info_t* field_info_p){
    if(mp_obj_is_type(value_p, &mp_type_int)){
        size_t size = (field_info_p->number_of_bits + 7) / 8;
        uint8_t* buffer = alloca(size);
        mp_obj_int_to_bytes_impl(value_p, field_info_p->bitorder, size, buffer);

        if(!field_info_p->bitorder){
            for(size_t i = 0; i < (field_info_p->number_of_bits / 8); ++i)
                bitstream_writer_write_u8(self_p, reverse(buffer[i]));
            for(size_t i = 0; i < (field_info_p->number_of_bits % 8); ++i)
                bitstream_writer_write_bit(self_p, buffer[size - 1] >> i);
        }else{
            if(field_info_p->number_of_bits % 8){
                bitstream_writer_write_u64_bits(self_p, buffer[0], field_info_p->number_of_bits % 8);
                buffer++;
            }
            bitstream_writer_write_bytes(self_p, buffer, field_info_p->number_of_bits / 8);
        }
    }else if(mp_obj_is_integer(value_p)){
        if(field_info_p->number_of_bits > 64)
            mp_raise_NotImplementedError("unsigned integer over 64 bits");

        // raises TypeError
        uint64_t value = mp_obj_get_int(value_p);

        uint64_t upper;
        if(field_info_p->number_of_bits < 64)
            upper = ((1ull << field_info_p->number_of_bits) - 1);
        else
            upper = (uint64_t)-1;

        // TODO: implement output of large integers
        if(value > upper)
            nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error, "\"u%d\" requires 0 <= integer <= %d (got %d)",
                                                    field_info_p->number_of_bits,
                                                    upper,
                                                    value));

        bitstream_writer_write_u64_bits(self_p,
                                        value,
                                        field_info_p->number_of_bits);

    }else{
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
                                                "can't convert %s to int", mp_obj_get_type_str(value_p)));
    }
}

static mp_obj_t unpack_unsigned_integer(struct bitstream_reader_t* self_p,
                                        struct field_info_t* field_info_p){
    if(field_info_p->number_of_bits > 64)
        mp_raise_NotImplementedError("unsigned integer over 64 bits");

    uint64_t value = bitstream_reader_read_u64_bits(self_p,
                                                    field_info_p->number_of_bits);

    // raises OverflowError, MemoryError
    return mp_obj_new_int_from_ull(value);
}

#if defined(_Float16)

static void pack_float_16(struct bitstream_writer_t* self_p,
                          mp_obj_t value_p,
                          struct field_info_t* field_info_p){
    if(mp_obj_is_float(value_p)){
        // relies on sizeof(float) == 4 this is always the case with gcc
        // raises TypeError
        _Float16 value = (_Float16)mp_obj_get_float(value_p);

        uint16_t data;
        memcpy(&data, &value, sizeof(data));
        bitstream_writer_write_u16(self_p, data);
    }else{
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
                                                "can't convert %s to float", mp_obj_get_type_str(value_p)));
    }
}

static mp_obj_t unpack_float_16(struct bitstream_reader_t* self_p,
                                struct field_info_t* field_info_p){
    // relies on sizeof(float) == 4 this is always the case with gcc
    uint16_t data = (_Float16)bitstream_reader_read_u16(self_p);

    _Float16 value;
    memcpy(&value, &data, sizeof(data));

    return mp_obj_new_float((mp_float_t)value);
}

#endif /* defined(_Float16) */

#if __SIZEOF_FLOAT__ == 4

static void pack_float_32(struct bitstream_writer_t* self_p,
                          mp_obj_t value_p,
                          struct field_info_t* field_info_p){
    if(mp_obj_is_float(value_p)){
        // relies on sizeof(float) == 4 this is always the case with gcc
        // raises TypeError
        float value = (float)mp_obj_get_float(value_p);

        uint32_t data;
        memcpy(&data, &value, sizeof(data));
        bitstream_writer_write_u32(self_p, data);
    }else{
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
                                                "can't convert %s to float", mp_obj_get_type_str(value_p)));
    }
}

static mp_obj_t unpack_float_32(struct bitstream_reader_t* self_p,
                                struct field_info_t* field_info_p){
    // relies on sizeof(float) == 4 this is always the case with gcc
    uint32_t data = (float)bitstream_reader_read_u32(self_p);

    float value;
    memcpy(&value, &data, sizeof(data));

    return mp_obj_new_float((mp_float_t)value);
}

#endif /* __SIZEOF_FLOAT__ == 4 */

#if __SIZEOF_DOUBLE__ == 8

static void pack_float_64(struct bitstream_writer_t* self_p,
                          mp_obj_t value_p,
                          struct field_info_t* field_info_p){
    if(mp_obj_is_float(value_p)){
        // raises TypeError
        double value = (double)mp_obj_get_float(value_p);

        uint64_t data;
        memcpy(&data, &value, sizeof(data));
        bitstream_writer_write_u64(self_p, data);
    }else{
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_ValueError,
                                                "can't convert %s to float", mp_obj_get_type_str(value_p)));
    }
}

static mp_obj_t unpack_float_64(struct bitstream_reader_t* self_p,
                                struct field_info_t* field_info_p){
    uint64_t data = (double)bitstream_reader_read_u64(self_p);

    double value;
    memcpy(&value, &data, sizeof(data));

    return mp_obj_new_float((mp_float_t)value);
}

#endif /* __SIZEOF_DOUBLE__ == 8 */

static void pack_bool(struct bitstream_writer_t* self_p,
                      mp_obj_t value_p,
                      struct field_info_t* field_info_p){
    bitstream_writer_write_repeated_bit(self_p,
                                        mp_obj_is_true(value_p),
                                        field_info_p->number_of_bits);
}

static mp_obj_t unpack_bool(struct bitstream_reader_t* self_p,
                            struct field_info_t* field_info_p){
    bool val = false;
    for(size_t i = 0; i < field_info_p->number_of_bits; ++i){
        val |= bitstream_reader_read_bit(self_p);
    }
    return val ? mp_const_true : mp_const_false;
}

static void pack_text(struct bitstream_writer_t* self_p,
                      mp_obj_t value_p,
                      struct field_info_t* field_info_p){

    // raises TypeError
    size_t size;
    const char* buf_p = mp_obj_str_get_data(value_p, &size);

    size_t required_bytes = field_info_p->number_of_bits / 8;
    size_t bytes_from_input = required_bytes > size ? size : required_bytes;

    bitstream_writer_write_bytes(self_p,
                                 (uint8_t*)buf_p,
                                 bytes_from_input);

    if(size < required_bytes)
        bitstream_writer_write_repeated_u8(self_p, 0, required_bytes - size);
}

static mp_obj_t unpack_text(struct bitstream_reader_t* self_p,
                            struct field_info_t* field_info_p){
    int number_of_bytes = (field_info_p->number_of_bits / 8);
    uint8_t* buf_p = alloca(number_of_bytes);

    bitstream_reader_read_bytes(self_p, buf_p, number_of_bytes);

    // raises MemoryError
    mp_obj_t value_p = mp_obj_new_str((const char*)buf_p, number_of_bytes);

    return value_p;
}

static void pack_raw(struct bitstream_writer_t* self_p,
                     mp_obj_t value_p,
                     struct field_info_t* field_info_p){
    size_t size;
    char* buf_p;

    if(mp_obj_is_type(value_p, &mp_type_bytearray) || mp_obj_is_type(value_p, &mp_type_memoryview)){
        buf_p = ((mp_obj_array_t*)value_p)->items;
        size = ((mp_obj_array_t*)value_p)->len;
    }else{
        // raises TypeError
        buf_p = (char*)mp_obj_str_get_data(value_p, &size);
    }

    size_t required_bytes = field_info_p->number_of_bits / 8;
    size_t bytes_from_input = required_bytes > size ? size : required_bytes;

    bitstream_writer_write_bytes(self_p,
                                 (uint8_t*)buf_p,
                                 bytes_from_input);

    if(size < required_bytes)
        bitstream_writer_write_repeated_u8(self_p, 0, required_bytes - size);

    if(field_info_p->number_of_bits % 8){
        uint8_t tmp = 0;
        if(((field_info_p->number_of_bits + 7) / 8) <= size)
            tmp = buf_p[required_bytes];

        bitstream_writer_write_u64_bits(self_p,
                                        tmp >> (8 - (field_info_p->number_of_bits % 8)),
                                        field_info_p->number_of_bits % 8);
    }
}

static mp_obj_t unpack_raw(struct bitstream_reader_t* self_p,
                           struct field_info_t* field_info_p){
    int size = (field_info_p->number_of_bits + 7) / 8;

    uint8_t* buf_p = alloca(size);

    bitstream_reader_read_bytes(self_p, buf_p, field_info_p->number_of_bits / 8);

    if(field_info_p->number_of_bits % 8){
        uint8_t tmp = bitstream_reader_read_u64_bits(self_p, field_info_p->number_of_bits % 8);
        buf_p[size - 1] = tmp << (8 - (field_info_p->number_of_bits % 8));
    }

    // raises MemoryError
    return mp_obj_new_bytes(buf_p, size);
}

static void pack_zero_padding(struct bitstream_writer_t* self_p,
                              mp_obj_t value_p,
                              struct field_info_t* field_info_p){
    if(mp_obj_is_true(value_p)){
        bitstream_writer_write_repeated_bit(self_p,
                                            0,
                                            field_info_p->number_of_bits);
    }else{
        bitstream_writer_seek(self_p, field_info_p->number_of_bits);
    }
}

static void pack_one_padding(struct bitstream_writer_t* self_p,
                             mp_obj_t value_p,
                             struct field_info_t* field_info_p){
    if(mp_obj_is_true(value_p)){
        bitstream_writer_write_repeated_bit(self_p,
                                            1,
                                            field_info_p->number_of_bits);
    }else{
        bitstream_writer_seek(self_p, field_info_p->number_of_bits);
    }
}

static mp_obj_t unpack_padding(struct bitstream_reader_t* self_p,
                               struct field_info_t* field_info_p){
    bitstream_reader_seek(self_p, field_info_p->number_of_bits);

    return mp_const_none;
}

static void field_info_init_signed(struct field_info_t* self_p,
                                   int number_of_bits){
    self_p->pack = pack_signed_integer;
    self_p->unpack = unpack_signed_integer;
}

static void field_info_init_unsigned(struct field_info_t* self_p,
                                     int number_of_bits){
    self_p->pack = pack_unsigned_integer;
    self_p->unpack = unpack_unsigned_integer;
}

static void field_info_init_float(struct field_info_t* self_p,
                                  int number_of_bits){
    switch(number_of_bits){
#if defined(_Float16)
    case 16:
        self_p->pack = pack_float_16;
        self_p->unpack = unpack_float_16;
        break;
#endif /* defined(_Float16) */

#if __SIZEOF_FLOAT__ == 4
    case 32:
        self_p->pack = pack_float_32;
        self_p->unpack = unpack_float_32;
        break;
#endif /* __SIZEOF_FLOAT__ == 4 */

#if __SIZEOF_DOUBLE__ == 8
    case 64:
        self_p->pack = pack_float_64;
        self_p->unpack = unpack_float_64;
        break;
#endif /* __SIZEOF_DOUBLE__ == 8 */

    default:
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                "expected float size of 16, 32, or 64 bits (got %d)",
                                                (uint)number_of_bits));
    }
}

static void field_info_init_bool(struct field_info_t* self_p,
                                 int number_of_bits){
    self_p->pack = pack_bool;
    self_p->unpack = unpack_bool;
}

static void field_info_init_text(struct field_info_t* self_p,
                                 int number_of_bits){
    self_p->pack = pack_text;
    self_p->unpack = unpack_text;

    if((number_of_bits % 8) != 0){
        mp_raise_NotImplementedError("Text not multiple of 8 bits.");
    }
}

static void field_info_init_raw(struct field_info_t* self_p,
                                int number_of_bits){
    self_p->pack = pack_raw;
    self_p->unpack = unpack_raw;
}

static void field_info_init_zero_padding(struct field_info_t* self_p){
    self_p->pack = pack_zero_padding;
    self_p->unpack = unpack_padding;
}

static void field_info_init_one_padding(struct field_info_t* self_p){
    self_p->pack = pack_one_padding;
    self_p->unpack = unpack_padding;
}

static void field_info_init(struct field_info_t* self_p,
                            int kind,
                            int number_of_bits,
                            bool bitorder){
    bool is_padding = false;

    switch(kind){
    case 's':
        // raises NotImplementedError
        field_info_init_signed(self_p, number_of_bits);
        break;

    case 'u':
        // raises NotImplementedError
        field_info_init_unsigned(self_p, number_of_bits);
        break;

    case 'f':
        // raises NotImplementedError
        field_info_init_float(self_p, number_of_bits);
        break;

    case 'b':
        // raises NotImplementedError
        field_info_init_bool(self_p, number_of_bits);
        break;

    case 't':
        // raises NotImplementedError
        field_info_init_text(self_p, number_of_bits);
        break;

    case 'r':
        // raises NotImplementedError
        field_info_init_raw(self_p, number_of_bits);
        break;

    case 'p':
        is_padding = true;
        // raises NotImplementedError
        field_info_init_zero_padding(self_p);
        break;

    case 'P':
        is_padding = true;
        // raises NotImplementedError
        field_info_init_one_padding(self_p);
        break;

    default:
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                "bad char '%c' in format",
                                                (uint)kind));
        break;
    }

    self_p->number_of_bits = number_of_bits;
    self_p->is_padding = is_padding;
    self_p->bitorder = bitorder;
}

static int count_number_of_fields(const char* format_p,
                                  int* number_of_padding_fields_p){
    int count = 0;
    *number_of_padding_fields_p = 0;

    while(*format_p != '\0'){
        if((*format_p >= 'A') && (*format_p <= 'z')){
            count++;

            if((*format_p == 'p') || (*format_p == 'P')){
                (*number_of_padding_fields_p)++;
            }
        }

        format_p++;
    }

    return count;
}

static inline int isspace(int c){return (((c>='\t')&&(c<='\r')) || (c==' '));}
static inline int isdigit(int c){return ((c>='0')&&(c<='9'));}
const char* parse_field(const char* format_p,
                        int* kind_p,
                        int* number_of_bits_p,
                        bool* bitorder){
    const char* tmp_format = format_p;
    while(isspace(*format_p)){
        format_p++;
    }

    switch(*format_p){
    case '<':
        mp_raise_NotImplementedError("bitorder little endian first in format");
        *bitorder = BITORDER_LSBFIRST;
        format_p++;
        break;
    case '>':
        *bitorder = BITORDER_MSBFIRST;
        format_p++;
        break;
    default:
        break;
    }

    *kind_p = *format_p;
    *number_of_bits_p = 0;
    format_p++;

    while(isdigit(*format_p)){
        if(*number_of_bits_p > (INT_MAX / 100)){
            mp_raise_ValueError("Field too long.");
        }

        *number_of_bits_p *= 10;
        *number_of_bits_p += (*format_p - '0');
        format_p++;
    }

    if(*number_of_bits_p == 0){
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                "bad format '%s'",
                                                tmp_format));
    }

    return format_p;
}

static struct info_t* parse_format(mp_obj_t format_obj_p){
    // raises TypeError
    const char* format_p = mp_obj_str_get_str(format_obj_p);

    int number_of_padding_fields;
    int number_of_fields = count_number_of_fields(format_p,
                                                  &number_of_padding_fields);

    struct info_t* info_p;
    size_t size = sizeof(*info_p) + number_of_fields * sizeof(info_p->fields[0]);
    info_p = alloca(size);

    info_p->number_of_bits = 0;
    info_p->number_of_fields = number_of_fields;
    info_p->number_of_non_padding_fields = (
        number_of_fields - number_of_padding_fields);

    bool bitorder = BITORDER_MSBFIRST; // bitorder carry's from the previous field
    for(int i = 0; i < info_p->number_of_fields; i++){
        // raises ValueError
        int kind;
        int number_of_bits;
        format_p = parse_field(format_p, &kind, &number_of_bits, &bitorder);

        // raises NotImplementedError, ValueError
        field_info_init(&info_p->fields[i], kind, number_of_bits, bitorder);

        info_p->number_of_bits += number_of_bits;
    }

    switch(*format_p){
    case '<':
        mp_raise_NotImplementedError("byteorder LSB first in format");
        info_p->byteorder = BYTEORDER_LSBFIRST;
        break;
    case '>':
        info_p->byteorder = BYTEORDER_MSBFIRST;
        break;
    default:
        break;
    }

    // raises MemoryError
    struct info_t* n_info_p = gc_alloc(size, 0);
    memcpy(n_info_p, info_p, size);

    return n_info_p;
}

static void pack_pack(struct info_t* info_p,
                      const mp_obj_t* args_p,
                      int consumed_args,
                      struct bitstream_writer_t* writer_p,
                      mp_obj_t fill_padding){
    for(int i = 0; i < info_p->number_of_fields; i++){
        struct field_info_t* field_p = &info_p->fields[i];

        mp_obj_t value_p;
        if(field_p->is_padding){
            value_p = fill_padding;
        }else{
            value_p = args_p[consumed_args];
            consumed_args++;
        }

        // raises NotImplementedError, OverflowError, TypeError
        info_p->fields[i].pack(writer_p, value_p, field_p);
    }
}

static uint8_t* pack_prepare(struct info_t* info_p,
                             struct bitstream_writer_t* writer_p){
    // raises MemoryError
    uint8_t* data = gc_alloc((info_p->number_of_bits + 7) / 8, 0);

    bitstream_writer_init(writer_p, data);

    return data;
}

static mp_obj_t pack(struct info_t* info_p,
                     const mp_obj_t* args_p,
                     int consumed_args,
                     size_t number_of_args){
    if(number_of_args < info_p->number_of_non_padding_fields){
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                "pack expected %d item(s) for packing (got %d)",
                                                (uint)info_p->number_of_non_padding_fields,
                                                (uint)number_of_args));
    }

    // raises MemoryError
    struct bitstream_writer_t writer;
    uint8_t* data = pack_prepare(info_p, &writer);

    // raises NotImplementedError, OverflowError, TypeError
    pack_pack(info_p, args_p, consumed_args, &writer, mp_const_true);

    // raises MemoryError
    mp_obj_t packed_p = mp_obj_new_bytes(data, (info_p->number_of_bits + 7) / 8);
    gc_free(data);

    return packed_p;
}

char* bitstruct_mp_obj_get_data(mp_obj_t data_p, size_t* size){
    char* packed_p;
    if(mp_obj_is_type(data_p, &mp_type_bytearray) || mp_obj_is_type(data_p, &mp_type_memoryview)){
        packed_p = ((mp_obj_array_t*)data_p)->items;
        *size = ((mp_obj_array_t*)data_p)->len;
    }else if(mp_obj_is_type(data_p, &mp_type_list)){
        size_t len;
        mp_obj_t* items;
        mp_obj_list_get(data_p, &len, &items);
        *size = len * sizeof(mp_int_t);
        packed_p = alloca(*size);
        for(size_t j = 0; j < len; j++){
            // raises TypeError
            packed_p[j] = mp_obj_get_int(items[j]);
        }
    }else{
        // raises TypeError
        packed_p = (char*)mp_obj_str_get_data(data_p, size);
    }
    return packed_p;
}

static mp_obj_t unpack(struct info_t* info_p, mp_obj_t data_p, long offset){
    size_t size;
    char* packed_p = bitstruct_mp_obj_get_data(data_p, &size);

    if(size < ((info_p->number_of_bits + offset + 7) / 8)){
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                "unpack requires at least %d bits to unpack (got %d)",
                                                (uint)(info_p->number_of_bits),
                                                (uint)(size * 8) - offset));
    }

    struct bitstream_reader_t reader;
    bitstream_reader_init(&reader, (uint8_t*)packed_p);
    bitstream_reader_seek(&reader, offset);

    // raises MemoryError
    mp_obj_t unpacked_p = mp_obj_new_tuple(info_p->number_of_non_padding_fields, NULL);

    size_t len;
    mp_obj_t* items;

    mp_obj_tuple_get(unpacked_p, &len, &items);

    int produced_args = 0;
    for(int i = 0; i < info_p->number_of_fields; i++){
        // raises MemoryError, OverflowError
        mp_obj_t value_p = info_p->fields[i].unpack(&reader, &info_p->fields[i]);

        if(value_p != mp_const_none){
            items[produced_args] = value_p;
            produced_args++;
        }
    }

    return unpacked_p;
}

static long parse_offset(mp_obj_t offset_p){
    // raises TypeError
    unsigned long offset = mp_obj_get_int(offset_p);

    if(offset == (unsigned long)-1){
        mp_raise_ValueError("negative offset");
    }

    if(offset > 0x7fffffff){
        mp_raise_ValueError("Offset must be less or equal to 2147483647 bits.");
    }

    return offset;
}

static void pack_into_prepare(struct info_t* info_p,
                              mp_obj_t buf_p,
                              mp_obj_t offset_p,
                              struct bitstream_writer_t* writer_p,
                              struct bitstream_writer_bounds_t* bounds_p){
    // raises TypeError, ValueError
    long offset = parse_offset(offset_p);

    if(!mp_obj_is_type(buf_p, &mp_type_bytearray)){
        mp_raise_TypeError("Bytearray needed.");
    }

    uint8_t* packed_p = ((mp_obj_array_t*)buf_p)->items;
    size_t size = ((mp_obj_array_t*)buf_p)->len;

    if(size < ((info_p->number_of_bits + offset + 7) / 8))
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                "pack_into requires a buffer of at least %d bits",
                                                (uint)info_p->number_of_bits));

    bitstream_writer_init(writer_p, packed_p);
    bitstream_writer_bounds_save(bounds_p,
                                 writer_p,
                                 offset,
                                 info_p->number_of_bits);
    bitstream_writer_seek(writer_p, offset);
}

static mp_obj_t pack_into_finalize(struct bitstream_writer_bounds_t* bounds_p){
    bitstream_writer_bounds_restore(bounds_p);

    return mp_const_none;
}

static mp_obj_t pack_into(struct info_t* info_p,
                          mp_obj_t buf_p,
                          mp_obj_t offset_p,
                          const mp_obj_t* args_p,
                          size_t consumed_args,
                          size_t number_of_args,
                          mp_obj_t fill_padding){
    struct bitstream_writer_t writer;
    struct bitstream_writer_bounds_t bounds;

    if((number_of_args - consumed_args) < info_p->number_of_non_padding_fields)
        nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                "pack expected %d item(s) for packing (got %d)",
                                                (uint)info_p->number_of_non_padding_fields,
                                                (uint)(number_of_args - consumed_args)));

    // raises TypeError, ValueError
    pack_into_prepare(info_p, buf_p, offset_p, &writer, &bounds);

    // raises NotImplementedError, OverflowError, TypeError
    pack_pack(info_p, args_p, consumed_args, &writer, fill_padding);

    return pack_into_finalize(&bounds);
}

static mp_obj_t unpack_from(struct info_t* info_p,
                            mp_obj_t data_p,
                            mp_obj_t offset_p){
    // raises TypeError, ValueError
    long offset = parse_offset(offset_p);

    // raises MemoryError, OverflowError, TypeError, ValueError
    return unpack(info_p, data_p, offset);
}

static void pack_dict_pack(struct info_t* info_p,
                           mp_obj_t names_p,
                           mp_obj_t data_p,
                           struct bitstream_writer_t* writer_p,
                           mp_obj_t fill_padding){
    size_t len;
    mp_obj_t* items;
    mp_obj_list_get(names_p, &len, &items);

    int consumed_args = 0;
    for(int i = 0; i < info_p->number_of_fields; i++){
        struct field_info_t* field_p = &info_p->fields[i];

        mp_obj_t value_p;
        if(field_p->is_padding){
            value_p = fill_padding;
        }else{
            mp_obj_dict_t *self = MP_OBJ_TO_PTR(data_p);
            mp_map_elem_t *elem = mp_map_lookup(&self->map, items[consumed_args], MP_MAP_LOOKUP);
            if(elem == NULL)
                nlr_raise(mp_obj_new_exception_msg_varg(&mp_type_Error,
                                                        "'%s' not found in data dictionary",
                                                        mp_obj_str_get_str(items[consumed_args])));
            value_p = elem->value;
            consumed_args++;

            if(value_p == mp_const_none){
                mp_raise_msg(&mp_type_Error, "Missing value.");
            }
        }

        // raises NotImplementedError, OverflowError, TypeError
        info_p->fields[i].pack(writer_p, value_p, field_p);
    }
}

static mp_obj_t pack_dict(struct info_t* info_p,
                          mp_obj_t names_p,
                          mp_obj_t data_p){
    struct bitstream_writer_t writer;

    if(((mp_obj_list_t*)MP_OBJ_TO_PTR(names_p))->len < info_p->number_of_non_padding_fields){
        mp_raise_ValueError("Too few names.");
    }

    // raises MemoryError
    uint8_t* data = pack_prepare(info_p, &writer);

    // raises KeyError, NotImplementedError, OverflowError, TypeError
    pack_dict_pack(info_p, names_p, data_p, &writer, mp_const_true);

    // raises MemoryError
    mp_obj_t packed_p = mp_obj_new_bytes(data, (info_p->number_of_bits + 7) / 8);
    gc_free(data);

    return packed_p;
}

static mp_obj_t unpack_dict(struct info_t* info_p,
                            mp_obj_t names_p,
                            mp_obj_t data_p,
                            long offset){
    if(((mp_obj_list_t*)MP_OBJ_TO_PTR(names_p))->len < info_p->number_of_non_padding_fields){
        mp_raise_ValueError("Too few names.");
    }

    // raises MemoryError
    mp_obj_t unpacked_p = mp_obj_new_dict(0);

    size_t size;
    char* packed_p = bitstruct_mp_obj_get_data(data_p, &size);

    if(size < ((info_p->number_of_bits + offset + 7) / 8)){
        mp_raise_ValueError("Short data.");
    }

    struct bitstream_reader_t reader;
    bitstream_reader_init(&reader, (uint8_t*)packed_p);
    bitstream_reader_seek(&reader, offset);

    size_t len;
    mp_obj_t* names;
    mp_obj_list_get(names_p, &len, &names);

    int produced_args = 0;
    for(int i = 0; i < info_p->number_of_fields; i++){
        // raises MemoryError, OverflowError
        mp_obj_t value_p = info_p->fields[i].unpack(&reader, &info_p->fields[i]);

        if(value_p != mp_const_none){
            // raises MemoryError
            mp_obj_dict_store(unpacked_p, names[produced_args], value_p);
            produced_args++;
        }
    }

    return unpacked_p;
}

static mp_obj_t unpack_from_dict(struct info_t* info_p,
                                 mp_obj_t names_p,
                                 mp_obj_t data_p,
                                 mp_obj_t offset_p){
    // raises TypeError, ValueError
    long offset = parse_offset(offset_p);

    // raises MemoryError, OverflowError, TypeError, ValueError
    return unpack_dict(info_p, names_p, data_p, offset);
}

static mp_obj_t pack_into_dict(struct info_t* info_p,
                               mp_obj_t names_p,
                               mp_obj_t buf_p,
                               mp_obj_t offset_p,
                               mp_obj_t data_p,
                               mp_obj_t fill_padding){
    struct bitstream_writer_t writer;
    struct bitstream_writer_bounds_t bounds;

    // raises TypeError, ValueError
    pack_into_prepare(info_p, buf_p, offset_p, &writer, &bounds);

    // raises KeyError, NotImplementedError, OverflowError, TypeError
    pack_dict_pack(info_p, names_p, data_p, &writer, fill_padding);

    return pack_into_finalize(&bounds);
}

static mp_obj_t calcsize(struct info_t* info_p){
    // raises MemoryError, OverflowError
    return mp_obj_new_int_from_ll(info_p->number_of_bits);
}

static mp_obj_t fill_pading_from_kwarg(mp_map_t* kw_args){
    static const mp_arg_t allowed_args[] = {
        { MP_QSTR_fill_padding, MP_ARG_KW_ONLY | MP_ARG_BOOL, {.u_bool = true} },
    };

    // parse args
    struct{
        mp_arg_val_t fill_padding;
    }args;
    mp_arg_parse_all(0, NULL, kw_args,
                     MP_ARRAY_SIZE(allowed_args), allowed_args, (mp_arg_val_t*)&args);

    if(!args.fill_padding.u_bool)
        mp_raise_NotImplementedError("fill_padding=False");

    return mp_obj_new_bool(args.fill_padding.u_bool);
}

typedef struct _bitstruct_CompiledFormat_obj_t{
    // base represents some basic information, like type
    mp_obj_base_t base;

    struct info_t* info_p;
}bitstruct_CompiledFormat_obj_t;

typedef struct _bitstruct_CompiledFormatDict_obj_t{
    // base represents some basic information, like type
    mp_obj_base_t base;

    struct info_t* info_p;
    mp_obj_t names_p;
}bitstruct_CompiledFormatDict_obj_t;

mp_obj_t bitstruct_CompiledFormat_make_new(const mp_obj_type_t* type, size_t n_args, size_t n_kw, const mp_obj_t* args);
STATIC void bitstruct_CompiledFormat_print(const mp_print_t* print, mp_obj_t self_in, mp_print_kind_t kind);
STATIC mp_obj_t bitstruct_CompiledFormat_pack(size_t n_args, const mp_obj_t* args);
STATIC mp_obj_t bitstruct_CompiledFormat_unpack(mp_obj_t self_in, mp_obj_t data);
STATIC mp_obj_t bitstruct_CompiledFormat_pack_into(size_t n_args, const mp_obj_t* args, mp_map_t* kw_args);
STATIC mp_obj_t bitstruct_CompiledFormat_unpack_from(size_t n_args, const mp_obj_t* args);
STATIC mp_obj_t bitstruct_CompiledFormat_calcsize(mp_obj_t self_in);

mp_obj_t bitstruct_CompiledFormatDict_make_new(const mp_obj_type_t* type, size_t n_args, size_t n_kw, const mp_obj_t* args);
STATIC void bitstruct_CompiledFormatDict_print(const mp_print_t* print, mp_obj_t self_in, mp_print_kind_t kind);
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack(mp_obj_t self_in, mp_obj_t data);
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack(mp_obj_t self_in, mp_obj_t data);
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack_into(size_t n_args, const mp_obj_t* pos_args, mp_map_t* kw_args);
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack_from(size_t n_args, const mp_obj_t* args);
STATIC mp_obj_t bitstruct_CompiledFormatDict_calcsize(mp_obj_t self_in);

STATIC mp_obj_t bitstruct_pack(size_t n_args, const mp_obj_t* args);
STATIC mp_obj_t bitstruct_unpack(mp_obj_t format, mp_obj_t data);
STATIC mp_obj_t bitstruct_pack_into(size_t n_args, const mp_obj_t* args, mp_map_t* kw_args);
STATIC mp_obj_t bitstruct_unpack_from(size_t n_args, const mp_obj_t* args);
STATIC mp_obj_t bitstruct_pack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data);
STATIC mp_obj_t bitstruct_unpack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data);
STATIC mp_obj_t bitstruct_pack_into_dict(size_t n_args, const mp_obj_t* pos_args, mp_map_t* kw_args);
STATIC mp_obj_t bitstruct_unpack_from_dict(size_t n_args, const mp_obj_t* args);
STATIC mp_obj_t bitstruct_calcsize(mp_obj_t format);
STATIC mp_obj_t bitstruct_byteswap(size_t n_args, const mp_obj_t* args);
STATIC mp_obj_t bitstruct_compile(size_t n_args, const mp_obj_t* args);

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(bitstruct_CompiledFormat_pack_fun_obj, 1, bitstruct_CompiledFormat_pack);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitstruct_CompiledFormat_unpack_fun_obj, bitstruct_CompiledFormat_unpack);
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(bitstruct_CompiledFormat_pack_into_fun_obj, 3, bitstruct_CompiledFormat_pack_into);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_CompiledFormat_unpack_from_fun_obj, 2, 3,
                                           bitstruct_CompiledFormat_unpack_from);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(bitstruct_CompiledFormat_calcsize_fun_obj, bitstruct_CompiledFormat_calcsize);

STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitstruct_CompiledFormatDict_pack_fun_obj, bitstruct_CompiledFormatDict_pack);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitstruct_CompiledFormatDict_unpack_fun_obj, bitstruct_CompiledFormatDict_unpack);
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(bitstruct_CompiledFormatDict_pack_into_fun_obj, 4, bitstruct_CompiledFormatDict_pack_into);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_CompiledFormatDict_unpack_from_fun_obj, 2, 3,
                                           bitstruct_CompiledFormatDict_unpack_from);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(bitstruct_CompiledFormatDict_calcsize_fun_obj, bitstruct_CompiledFormatDict_calcsize);

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(bitstruct_pack_fun_obj, 1, bitstruct_pack);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitstruct_unpack_fun_obj, bitstruct_unpack);
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(bitstruct_pack_into_fun_obj, 3, bitstruct_pack_into);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_unpack_from_fun_obj, 2, 3, bitstruct_unpack_from);
STATIC MP_DEFINE_CONST_FUN_OBJ_3(bitstruct_pack_dict_fun_obj, bitstruct_pack_dict);
STATIC MP_DEFINE_CONST_FUN_OBJ_3(bitstruct_unpack_dict_fun_obj, bitstruct_unpack_dict);
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(bitstruct_pack_into_dict_fun_obj, 5, bitstruct_pack_into_dict);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_unpack_from_dict_fun_obj, 3, 4, bitstruct_unpack_from_dict);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(bitstruct_calcsize_fun_obj, bitstruct_calcsize);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_byteswap_fun_obj, 2, 3, bitstruct_byteswap);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_compile_fun_obj, 1, 2, bitstruct_compile);

STATIC const mp_rom_map_elem_t bitstruct_CompiledFormat_locals_dict_table[]={
    // class methods
    { MP_ROM_QSTR(MP_QSTR_pack),        MP_ROM_PTR(&bitstruct_CompiledFormat_pack_fun_obj)        },
    { MP_ROM_QSTR(MP_QSTR_unpack),      MP_ROM_PTR(&bitstruct_CompiledFormat_unpack_fun_obj)      },
    { MP_ROM_QSTR(MP_QSTR_pack_into),   MP_ROM_PTR(&bitstruct_CompiledFormat_pack_into_fun_obj)   },
    { MP_ROM_QSTR(MP_QSTR_unpack_from), MP_ROM_PTR(&bitstruct_CompiledFormat_unpack_from_fun_obj) },
    { MP_ROM_QSTR(MP_QSTR_calcsize),    MP_ROM_PTR(&bitstruct_CompiledFormat_calcsize_fun_obj)    },
};
STATIC MP_DEFINE_CONST_DICT(bitstruct_CompiledFormat_locals_dict,bitstruct_CompiledFormat_locals_dict_table);

STATIC const mp_rom_map_elem_t bitstruct_CompiledFormatDict_locals_dict_table[]={
    // class methods
    { MP_ROM_QSTR(MP_QSTR_pack),        MP_ROM_PTR(&bitstruct_CompiledFormatDict_pack_fun_obj)        },
    { MP_ROM_QSTR(MP_QSTR_unpack),      MP_ROM_PTR(&bitstruct_CompiledFormatDict_unpack_fun_obj)      },
    { MP_ROM_QSTR(MP_QSTR_pack_into),   MP_ROM_PTR(&bitstruct_CompiledFormatDict_pack_into_fun_obj)   },
    { MP_ROM_QSTR(MP_QSTR_unpack_from), MP_ROM_PTR(&bitstruct_CompiledFormatDict_unpack_from_fun_obj) },
    { MP_ROM_QSTR(MP_QSTR_calcsize),    MP_ROM_PTR(&bitstruct_CompiledFormatDict_calcsize_fun_obj)    },
};
STATIC MP_DEFINE_CONST_DICT(bitstruct_CompiledFormatDict_locals_dict,bitstruct_CompiledFormatDict_locals_dict_table);


const mp_obj_type_t bitstruct_CompiledFormat_type={
    // "inherit" the type "type"
    { &mp_type_type },
    // give it a name
    .name = MP_QSTR_CompiledFormat,
    // give it a print-function
    .print = bitstruct_CompiledFormat_print,
    // give it a constructor
    .make_new = bitstruct_CompiledFormat_make_new,
    // and the global members
    .locals_dict = (mp_obj_dict_t*)&bitstruct_CompiledFormat_locals_dict,
};


const mp_obj_type_t bitstruct_CompiledFormatDict_type={
    // "inherit" the type "type"
    { &mp_type_type },
    // give it a name
    .name = MP_QSTR_CompiledFormatDict,
    // give it a print-function
    .print = bitstruct_CompiledFormatDict_print,
    // give it a constructor
    .make_new = bitstruct_CompiledFormatDict_make_new,
    // and the global members
    .locals_dict = (mp_obj_dict_t*)&bitstruct_CompiledFormatDict_locals_dict,
};

/**
 * Python: bitstruct.CompiledFormat(fmt)
 * @param fmt
 */
mp_obj_t bitstruct_CompiledFormat_make_new(const mp_obj_type_t* type,
                                           size_t n_args,
                                           size_t n_kw,
                                           const mp_obj_t* args){
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    // raises MemoryError
    bitstruct_CompiledFormat_obj_t* self = m_new_obj(bitstruct_CompiledFormat_obj_t);

    self->base.type = &bitstruct_CompiledFormat_type;

    // raises MemoryError, NotImplementedError, TypeError, ValueError
    self->info_p = parse_format(args[0]);

    return MP_OBJ_FROM_PTR(self);
}

/**
 * Python: print(bitstruct.CompiledFormat(fmt))
 * @param obj
 */
STATIC void bitstruct_CompiledFormat_print(const mp_print_t* print,
                                           mp_obj_t self_in, mp_print_kind_t kind){
    bitstruct_CompiledFormat_obj_t* self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "CompiledFormat(bits=%d, fields=%d, padding_fields=%d)",
              self->info_p->number_of_bits,
              self->info_p->number_of_fields,
              self->info_p->number_of_fields -
              self->info_p->number_of_non_padding_fields);
}

/**
 * Python: bitstruct.CompiledFormat.pack(*args)
 * @param self
 * @param args*
 */
STATIC mp_obj_t bitstruct_CompiledFormat_pack(size_t n_args, const mp_obj_t* args){
    bitstruct_CompiledFormat_obj_t* self = MP_OBJ_TO_PTR(args[0]);

    // raises MemoryError, ValueError
    return pack(self->info_p, &args[1], 0, n_args - 1);
}

/**
 * Python: bitstruct.CompiledFormat.unpack(data)
 * @param self
 * @param data
 */
STATIC mp_obj_t bitstruct_CompiledFormat_unpack(mp_obj_t self_in, mp_obj_t data){
    bitstruct_CompiledFormat_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises MemoryError, OverflowError, TypeError, ValueError
    return unpack(self->info_p, data, 0);
}

/**
 * Python: bitstruct.CompiledFormat.pack_into(buf, offset, *args, **kwargs)
 * @param self
 * @param buf
 * @param offset
 * @param args*
 * @param kwargs: fill_padding = true
 */
STATIC mp_obj_t bitstruct_CompiledFormat_pack_into(size_t n_args, const mp_obj_t* args, mp_map_t* kw_args){
    bitstruct_CompiledFormat_obj_t* self = MP_OBJ_TO_PTR(args[0]);

    mp_obj_t fill_padding = fill_pading_from_kwarg(kw_args);

    // raises NotImplementedError, OverflowError, TypeError, ValueError
    return pack_into(self->info_p, args[2], args[2], args, 3, n_args, fill_padding);
}

/**
 * Python: bitstruct.CompiledFormat.unpack_from(data, offset = 0)
 * @param self
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_CompiledFormat_unpack_from(size_t n_args, const mp_obj_t* args){
    bitstruct_CompiledFormat_obj_t* self = MP_OBJ_TO_PTR(args[0]);

    // raises OverflowError
    mp_obj_t offset = mp_obj_new_int(0);
    if(n_args == 3)
        offset = args[2];

    // raises MemoryError, OverflowError, TypeError, ValueError
    return unpack_from(self->info_p, args[1], offset);
}

/**
 * Python: bitstruct.CompiledFormat.calcsize()
 * @param self
 */
STATIC mp_obj_t bitstruct_CompiledFormat_calcsize(mp_obj_t self_in){
    bitstruct_CompiledFormat_obj_t* self = MP_OBJ_TO_PTR(self_in);
    return calcsize(self->info_p);
}

/**
 * Python: bitstruct.CompiledFormatDict(fmt, names = None)
 * @param fmt
 * @param opt: names = None
 */
mp_obj_t bitstruct_CompiledFormatDict_make_new(const mp_obj_type_t* type,
                                               size_t n_args,
                                               size_t n_kw,
                                               const mp_obj_t* args){
    mp_arg_check_num(n_args, n_kw, 1, 2, true);

    // raises MemoryError
    bitstruct_CompiledFormatDict_obj_t* self = m_new_obj(bitstruct_CompiledFormatDict_obj_t);

    self->base.type = &bitstruct_CompiledFormatDict_type;

    self->names_p = mp_const_none;
    if((n_args == 2) && (args[1] != mp_const_none)){
        // raises TypeError
        is_names_list(args[1]);
        self->names_p = args[1];
    }

    // raises MemoryError, NotImplementedError, TypeError, ValueError
    self->info_p = parse_format(args[0]);

    return MP_OBJ_FROM_PTR(self);
}

/**
 * Python: print(bitstruct.CompiledFormatDict(fmt))
 * @param obj
 */
STATIC void bitstruct_CompiledFormatDict_print(const mp_print_t* print,
                                               mp_obj_t self_in,mp_print_kind_t kind){
    bitstruct_CompiledFormatDict_obj_t* self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "CompiledFormat(bits=%d, fields=%d, padding_fields=%d, names=",
              self->info_p->number_of_bits,
              self->info_p->number_of_fields,
              self->info_p->number_of_fields -
              self->info_p->number_of_non_padding_fields);

    if(self->names_p == mp_const_none){
        mp_print_str(print, "None");
    }else{
        size_t len;
        mp_obj_t* items;
        mp_obj_list_get(self->names_p, &len, &items);

        mp_print_str(print, "[");
        if(len){
            mp_printf(print, "%s", mp_obj_str_get_str(items[0]));
            for(size_t i = 1; i < len; i++)
                mp_printf(print, ", %s", mp_obj_str_get_str(items[i]));
        }
        mp_print_str(print, "]");
    }

    mp_print_str(print, ")");
}

/**
 * Python: bitstruct.CompiledFormatDict.pack(data)
 * @param self
 * @param data
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack(mp_obj_t self_in, mp_obj_t data){
    bitstruct_CompiledFormatDict_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises KeyError, MemoryError, NotImplementedError, OverflowError, ValueError
    return pack_dict(self->info_p, self->names_p, data);
}

/**
 * Python: bitstruct.CompiledFormatDict.unpack(data)
 * @param self
 * @param data
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack(mp_obj_t self_in, mp_obj_t data){
    bitstruct_CompiledFormatDict_obj_t* self = MP_OBJ_TO_PTR(self_in);

    // raises MemoryError, OverflowError, TypeError, ValueError
    return unpack_dict(self->info_p, self->names_p, data, 0);
}

/**
 * Python: bitstruct.CompiledFormatDict.pack_into(buf, offset, data, **kwargs)
 * @param self
 * @param buf
 * @param offset
 * @param data
 * @param kwargs: fill_padding = true
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack_into(size_t n_args, const mp_obj_t* pos_args, mp_map_t* kw_args){
    bitstruct_CompiledFormatDict_obj_t* self = MP_OBJ_TO_PTR(pos_args[0]);

    mp_obj_t fill_padding = fill_pading_from_kwarg(kw_args);

    // raises KeyError, NotImplementedError, OverflowError, TypeError
    return pack_into_dict(self->info_p, self->names_p, pos_args[1], 0, pos_args[2], fill_padding);
}

/**
 * Python: bitstruct.CompiledFormatDict.unpack_from(data, offset = 0)
 * @param self
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack_from(size_t n_args, const mp_obj_t* args){
    bitstruct_CompiledFormatDict_obj_t* self = MP_OBJ_TO_PTR(args[0]);

    // raises OverflowError
    mp_obj_t offset = mp_obj_new_int(0);
    if(n_args == 3)
        offset = args[2];

    // raises MemoryError, OverflowError, TypeError, ValueError
    return unpack_from_dict(self->info_p, self->names_p, args[1], offset);
}

/**
 * Python: bitstruct.CompiledFormatDict.calcsize()
 * @param self
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_calcsize(mp_obj_t self_in){
    bitstruct_CompiledFormatDict_obj_t* self = MP_OBJ_TO_PTR(self_in);
    return calcsize(self->info_p);
}

/**
 * Python: bitstruct.pack(fmt, *args)
 * @param fmt
 * @param args*
 */
STATIC mp_obj_t bitstruct_pack(size_t n_args, const mp_obj_t* args){
    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(args[0]);

    // raises MemoryError, ValueError
    mp_obj_t packed_p = pack(info_p, &args[1], 0, n_args - 1);
    gc_free(info_p);

    return packed_p;
}

/**
 * Python: bitstruct.unpack(fmt, data)
 * @param fmt
 * @param data
 */
STATIC mp_obj_t bitstruct_unpack(mp_obj_t format, mp_obj_t data){
    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(format);

    // raises MemoryError, OverflowError, TypeError, ValueError
    mp_obj_t unpacked_p = unpack(info_p, data, 0);
    gc_free(info_p);

    return unpacked_p;
}

/**
 * Python: bitstruct.pack_into(fmt, buf, offset, *args, **kwargs)
 * @param fmt
 * @param buf
 * @param offset
 * @param args*
 * @param kwargs: fill_padding = true
 */
STATIC mp_obj_t bitstruct_pack_into(size_t n_args, const mp_obj_t* args, mp_map_t* kw_args){
    mp_obj_t fill_padding = fill_pading_from_kwarg(kw_args);

    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(args[0]);

    // raises NotImplementedError, OverflowError, TypeError, ValueError
    mp_obj_t res_p = pack_into(info_p,
                               args[1],
                               args[2],
                               args,
                               3,
                               n_args,
                               fill_padding);
    gc_free(info_p);

    return res_p;
}

/**
 * Python: bitstruct.unpack_from(fmt, data, offset=0)
 * @param fmt
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_unpack_from(size_t n_args, const mp_obj_t* args){
    // raises OverflowError
    mp_obj_t offset = mp_obj_new_int(0);
    if(n_args == 3)
        offset = args[2];

    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(args[0]);

    // raises MemoryError, OverflowError, TypeError, ValueError
    mp_obj_t unpacked_p = unpack_from(info_p, args[1], offset);
    gc_free(info_p);

    return unpacked_p;
}

/**
 * Python: bitstruct.pack_dict(fmt, names, data)
 * @param fmt
 * @param names
 * @param data
 */
STATIC mp_obj_t bitstruct_pack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data){
    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(format);

    // raises TypeError
    is_names_list(names);

    // raises KeyError, MemoryError, NotImplementedError, OverflowError, ValueError
    mp_obj_t packed_p = pack_dict(info_p, names, data);
    gc_free(info_p);

    return packed_p;
}

/**
 * Python: bitstruct.unpack_dict(fmt, names, data)
 * @param fmt
 * @param names
 * @param data
 */
STATIC mp_obj_t bitstruct_unpack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data){
    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(format);

    // raises TypeError
    is_names_list(names);

    // raises MemoryError, OverflowError, TypeError, ValueError
    mp_obj_t unpacked_p = unpack_dict(info_p, names, data, 0);
    gc_free(info_p);

    return unpacked_p;
}

/**
 * Python: bitstruct.pack_into_dict(fmt, names, buf, offset, data, **kwargs)
 * @param fmt
 * @param names
 * @param buf
 * @param offset
 * @param data
 * @param kwargs: fill_padding = true
 */
STATIC mp_obj_t bitstruct_pack_into_dict(size_t n_args, const mp_obj_t* pos_args, mp_map_t* kw_args){
    mp_obj_t fill_padding = fill_pading_from_kwarg(kw_args);

    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(pos_args[0]);

    // raises TypeError
    is_names_list(pos_args[1]);

    // raises KeyError, NotImplementedError, OverflowError, TypeError
    mp_obj_t res_p = pack_into_dict(info_p, pos_args[1], pos_args[2], pos_args[3], pos_args[4], fill_padding);
    gc_free(info_p);

    return res_p;
}

/**
 * Python: bitstruct.unpack_from_dict(fmt, names, data, offset=0)
 * @param fmt
 * @param names
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_unpack_from_dict(size_t n_args, const mp_obj_t* args){
    // raises OverflowError
    mp_obj_t offset = mp_obj_new_int(0);

    if(n_args == 4)
        offset = args[3];

    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(args[0]);

    // raises TypeError
    is_names_list(args[1]);

    // raises MemoryError, OverflowError, TypeError, ValueError
    mp_obj_t unpacked_p = unpack_from_dict(info_p, args[1], args[2], offset);
    gc_free(info_p);

    return unpacked_p;
}

/**
 * Python: bitstruct.calcsize(fmt)
 * @param fmt
 */
STATIC mp_obj_t bitstruct_calcsize(mp_obj_t format){
    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t* info_p = parse_format(format);

    // raises MemoryError, OverflowError
    mp_obj_t size = calcsize(info_p);
    gc_free(info_p);

    return size;
}

/**
 * Python: bitstruct.byteswap(fmt, data, offset=0)
 * @param fmt
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_byteswap(size_t n_args, const mp_obj_t* args){
    int offset = 0;
    if(n_args == 3){
        // raises TypeError
        offset = mp_obj_get_int(args[2]);
    }

    // raises TypeError
    const char* c_format_p = mp_obj_str_get_str(args[0]);

    // raises TypeError
    size_t size;
    uint8_t* src_p = (uint8_t*)mp_obj_str_get_data(args[1], &size);

    // raises MemoryError
    uint8_t* dst_p = alloca(size);

    while(*c_format_p != '\0'){
        switch(*c_format_p){
        case '1':
            if((size - offset) < 1){
                goto out1;
            }

            dst_p[offset] = src_p[offset];
            offset += 1;
            break;

        case '2':
            if((size - offset) < 2){
                goto out1;
            }

            dst_p[offset + 0] = src_p[offset + 1];
            dst_p[offset + 1] = src_p[offset + 0];
            offset += 2;
            break;

        case '4':
            if((size - offset) < 4){
                goto out1;
            }

            dst_p[offset + 0] = src_p[offset + 3];
            dst_p[offset + 1] = src_p[offset + 2];
            dst_p[offset + 2] = src_p[offset + 1];
            dst_p[offset + 3] = src_p[offset + 0];
            offset += 4;
            break;

        case '8':
            if((size - offset) < 8){
                goto out1;
            }

            dst_p[offset + 0] = src_p[offset + 7];
            dst_p[offset + 1] = src_p[offset + 6];
            dst_p[offset + 2] = src_p[offset + 5];
            dst_p[offset + 3] = src_p[offset + 4];
            dst_p[offset + 4] = src_p[offset + 3];
            dst_p[offset + 5] = src_p[offset + 2];
            dst_p[offset + 6] = src_p[offset + 1];
            dst_p[offset + 7] = src_p[offset + 0];
            offset += 8;
            break;

        default:
            mp_raise_ValueError("Expected 1, 2, 4 or 8, but got c.");
            return mp_const_none;
        }

        c_format_p++;
    }

    // raises MemoryError
    mp_obj_t swapped_p = mp_obj_new_bytes(dst_p, size);
    return (swapped_p);

out1:
    mp_raise_ValueError("Out of data to swap.");
    return mp_const_none;
}

/**
 * Python: bitstruct.compile(fmt, names=None)
 * @param fmt
 * @param opt: names = None
 */
STATIC mp_obj_t bitstruct_compile(size_t n_args, const mp_obj_t* args){
    if(n_args == 1){
        // raises MemoryError, NotImplementedError, TypeError, ValueError
        return bitstruct_CompiledFormat_make_new(&mp_type_NoneType, n_args, 0, args);
    }

    // raises MemoryError, NotImplementedError, TypeError, ValueError
    return bitstruct_CompiledFormatDict_make_new(&mp_type_NoneType, n_args, 0, args);
}


STATIC const mp_map_elem_t bitstruct_globals_table[] = {
    { MP_OBJ_NEW_QSTR(MP_QSTR___name__),           MP_OBJ_NEW_QSTR(MP_QSTR_bitstruct)            },
    { MP_OBJ_NEW_QSTR(MP_QSTR_pack),               (mp_obj_t)&bitstruct_pack_fun_obj             },
    { MP_OBJ_NEW_QSTR(MP_QSTR_unpack),             (mp_obj_t)&bitstruct_unpack_fun_obj           },
    { MP_OBJ_NEW_QSTR(MP_QSTR_pack_into),          (mp_obj_t)&bitstruct_pack_into_fun_obj        },
    { MP_OBJ_NEW_QSTR(MP_QSTR_unpack_from),        (mp_obj_t)&bitstruct_unpack_from_fun_obj      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_pack_dict),          (mp_obj_t)&bitstruct_pack_dict_fun_obj        },
    { MP_OBJ_NEW_QSTR(MP_QSTR_unpack_dict),        (mp_obj_t)&bitstruct_unpack_dict_fun_obj      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_pack_into_dict),     (mp_obj_t)&bitstruct_pack_into_dict_fun_obj   },
    { MP_OBJ_NEW_QSTR(MP_QSTR_unpack_from_dict),   (mp_obj_t)&bitstruct_unpack_from_dict_fun_obj },
    { MP_OBJ_NEW_QSTR(MP_QSTR_calcsize),           (mp_obj_t)&bitstruct_calcsize_fun_obj         },
    { MP_OBJ_NEW_QSTR(MP_QSTR_byteswap),           (mp_obj_t)&bitstruct_byteswap_fun_obj         },
    { MP_OBJ_NEW_QSTR(MP_QSTR_compile),            (mp_obj_t)&bitstruct_compile_fun_obj          },

    { MP_OBJ_NEW_QSTR(MP_QSTR_CompiledFormat),     (mp_obj_t)&bitstruct_CompiledFormat_type      },
    { MP_OBJ_NEW_QSTR(MP_QSTR_CompiledFormatDict), (mp_obj_t)&bitstruct_CompiledFormatDict_type  },
    { MP_OBJ_NEW_QSTR(MP_QSTR_Error),              (mp_obj_t)&mp_type_Error                      },
};

STATIC MP_DEFINE_CONST_DICT(
    mp_module_bitstruct_globals,
    bitstruct_globals_table
    );

const mp_obj_module_t mp_module_bitstruct = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_bitstruct_globals,
};

MP_REGISTER_MODULE(MP_QSTR_bitstruct, mp_module_bitstruct, MODULE_BITSTRUCT_ENABLED);
