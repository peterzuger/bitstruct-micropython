/**
 * @file   bitstruct.c
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

#include <stdbool.h>
#include "bitstream.h"

struct field_info_t;

typedef void (*pack_field_t)(struct bitstream_writer_t *self_p,
                             mp_obj_t value_p,
                             struct field_info_t *field_info_p);

typedef mp_obj_t (*unpack_field_t)(struct bitstream_reader_t *self_p,
                                   struct field_info_t *field_info_p);

struct field_info_t {
    pack_field_t pack;
    unpack_field_t unpack;
    int number_of_bits;
    bool is_padding;
    union {
        struct {
            int64_t lower;
            int64_t upper;
        } s;
        struct {
            uint64_t upper;
        } u;
    } limits;
};

struct info_t {
    int number_of_bits;
    int number_of_fields;
    int number_of_non_padding_fields;
    struct field_info_t fields[1];
};

struct compiled_format_t {
    PyObject_HEAD
    struct info_t *info_p;
};

struct compiled_format_dict_t {
    PyObject_HEAD
    struct info_t *info_p;
    PyObject *names_p;
};

/**
 * @raises TypeError
 */
static void is_names_list(mp_obj_t names_p)
{
    if(!mp_obj_is_type(names_p, &mp_type_list))
        mp_raise_TypeError("Names is not a list.");
}

static void pack_signed_integer(struct bitstream_writer_t *self_p,
                                mp_obj_t value_p,
                                struct field_info_t *field_info_p)
{
    int64_t value;
    int64_t lower;
    int64_t upper;

    // raises TypeError
    value = mp_obj_get_int(value_p);

    if (field_info_p->number_of_bits < 64) {
        lower = field_info_p->limits.s.lower;
        upper = field_info_p->limits.s.upper;

        if ((value < lower) || (value > upper)) {
            mp_raise_msg(&mp_type_OverflowError, "Signed integer out of range.");
        }

        value &= ((1ull << field_info_p->number_of_bits) - 1);
    }

    bitstream_writer_write_u64_bits(self_p,
                                    (uint64_t)value,
                                    field_info_p->number_of_bits);
}

static mp_obj_t unpack_signed_integer(struct bitstream_reader_t *self_p,
                                      struct field_info_t *field_info_p)
{
    uint64_t value;
    uint64_t sign_bit;

    value = bitstream_reader_read_u64_bits(self_p, field_info_p->number_of_bits);
    sign_bit = (1ull << (field_info_p->number_of_bits - 1));

    if (value & sign_bit) {
        value |= ~(((sign_bit) << 1) - 1);
    }

    // raises OverflowError, MemoryError
    return mp_obj_new_int_from_ll((long long)value);
}

static void pack_unsigned_integer(struct bitstream_writer_t *self_p,
                                  mp_obj_t value_p,
                                  struct field_info_t *field_info_p)
{
    uint64_t value;

    value = mp_obj_get_int(value_p);

    if (value > field_info_p->limits.u.upper) {
        mp_raise_msg(&mp_type_OverflowError, "Unsigned integer out of range.");
    }

    bitstream_writer_write_u64_bits(self_p,
                                    value,
                                    field_info_p->number_of_bits);
}

static mp_obj_t unpack_unsigned_integer(struct bitstream_reader_t *self_p,
                                        struct field_info_t *field_info_p)
{
    uint64_t value;

    value = bitstream_reader_read_u64_bits(self_p,
                                           field_info_p->number_of_bits);

    // raises OverflowError, MemoryError
    return mp_obj_new_int_from_ull(value);
}

static void pack_float_32(struct bitstream_writer_t *self_p,
                          mp_obj_t value_p,
                          struct field_info_t *field_info_p)
{
    mp_float_t value;
    uint32_t data;

    value = mp_obj_get_float(value_p);
    memcpy(&data, &value, sizeof(data));
    bitstream_writer_write_u32(self_p, data);
}

static mp_obj_t unpack_float_32(struct bitstream_reader_t *self_p,
                                struct field_info_t *field_info_p)
{
    mp_float_t value;
    uint32_t data;

    data = bitstream_reader_read_u32(self_p);
    memcpy(&value, &data, sizeof(value));

    return mp_obj_new_float(value);
}

static void pack_bool(struct bitstream_writer_t *self_p,
                      mp_obj_t value_p,
                      struct field_info_t *field_info_p)
{
    bitstream_writer_write_u64_bits(self_p,
                                    mp_obj_is_true(value_p),
                                    field_info_p->number_of_bits);
}

static mp_obj_t unpack_bool(struct bitstream_reader_t *self_p,
                            struct field_info_t *field_info_p)
{
    return ((long)bitstream_reader_read_u64_bits(
                self_p,
                field_info_p->number_of_bits))
        ? mp_const_true : mp_const_false;
}

static void pack_text(struct bitstream_writer_t *self_p,
                      mp_obj_t value_p,
                      struct field_info_t *field_info_p)
{
    size_t size;
    const char* buf_p;

    buf_p = mp_obj_str_get_data(value_p, &size);

    if (size < (field_info_p->number_of_bits / 8)) {
        mp_raise_NotImplementedError("Short text.");
    } else {
        bitstream_writer_write_bytes(self_p,
                                     (uint8_t *)buf_p,
                                     field_info_p->number_of_bits / 8);
    }
}

static mp_obj_t unpack_text(struct bitstream_reader_t *self_p,
                            struct field_info_t *field_info_p)
{
    uint8_t *buf_p;
    mp_obj_t value_p;
    int number_of_bytes;

    number_of_bytes = (field_info_p->number_of_bits / 8);
    buf_p = alloca(number_of_bytes);

    bitstream_reader_read_bytes(self_p, buf_p, number_of_bytes);
    value_p = mp_obj_new_str((const char *)buf_p, number_of_bytes);

    return value_p;
}

static void pack_raw(struct bitstream_writer_t *self_p,
                     mp_obj_t value_p,
                     struct field_info_t *field_info_p)
{
    size_t size;
    char* buf_p;
    int res;

    buf_p = (char*)mp_obj_str_get_data(value_p, &size);

    if (size < (field_info_p->number_of_bits / 8)) {
        mp_raise_NotImplementedError("Short raw data.");
    } else {
        bitstream_writer_write_bytes(self_p,
                                     (uint8_t *)buf_p,
                                     field_info_p->number_of_bits / 8);
    }
}

static mp_obj_t unpack_raw(struct bitstream_reader_t *self_p,
                           struct field_info_t *field_info_p)
{
    uint8_t *buf_p;
    mp_obj_t value_p;
    int number_of_bytes;

    number_of_bytes = (field_info_p->number_of_bits / 8);

    buf_p = alloca(number_of_bytes);

    bitstream_reader_read_bytes(self_p, buf_p, number_of_bytes);

    value_p = mp_obj_new_bytes(buf_p, number_of_bytes);

    return value_p;
}

static void pack_zero_padding(struct bitstream_writer_t *self_p,
                              mp_obj_t value_p,
                              struct field_info_t *field_info_p)
{
    bitstream_writer_write_repeated_bit(self_p,
                                        0,
                                        field_info_p->number_of_bits);
}

static void pack_one_padding(struct bitstream_writer_t *self_p,
                             mp_obj_t value_p,
                             struct field_info_t *field_info_p)
{
    bitstream_writer_write_repeated_bit(self_p,
                                        1,
                                        field_info_p->number_of_bits);
}

static mp_obj_t unpack_padding(struct bitstream_reader_t *self_p,
                               struct field_info_t *field_info_p)
{
    bitstream_reader_seek(self_p, field_info_p->number_of_bits);

    return mp_const_none;
}

static void field_info_init_signed(struct field_info_t *self_p,
                                  int number_of_bits)
{
    uint64_t limit;

    self_p->pack = pack_signed_integer;
    self_p->unpack = unpack_signed_integer;

    if (number_of_bits > 64) {
        mp_raise_NotImplementedError("Signed integer over 64 bits.");
    }

    limit = (1ull << (number_of_bits - 1));
    self_p->limits.s.lower = -limit;
    self_p->limits.s.upper = (limit - 1);
}

static void field_info_init_unsigned(struct field_info_t *self_p,
                                    int number_of_bits)
{
    self_p->pack = pack_unsigned_integer;
    self_p->unpack = unpack_unsigned_integer;

    if (number_of_bits > 64) {
        mp_raise_NotImplementedError("Unsigned integer over 64 bits.");
    }

    if (number_of_bits < 64) {
        self_p->limits.u.upper = ((1ull << number_of_bits) - 1);
    } else {
        self_p->limits.u.upper = (uint64_t)-1;
    }
}

static void field_info_init_float(struct field_info_t *self_p,
                                 int number_of_bits)
{
    switch (number_of_bits) {

    case 32:
        self_p->pack = pack_float_32;
        self_p->unpack = unpack_float_32;
        break;

    default:
        mp_raise_NotImplementedError("Float not 32 bits.");
    }
}

static void field_info_init_bool(struct field_info_t *self_p,
                                int number_of_bits)
{
    self_p->pack = pack_bool;
    self_p->unpack = unpack_bool;

    if (number_of_bits > 64) {
        mp_raise_NotImplementedError("Bool over 64 bits.");
    }
}

static void field_info_init_text(struct field_info_t *self_p,
                                int number_of_bits)
{
    self_p->pack = pack_text;
    self_p->unpack = unpack_text;

    if ((number_of_bits % 8) != 0) {
        mp_raise_NotImplementedError("Text not multiple of 8 bits.");
    }
}

static void field_info_init_raw(struct field_info_t *self_p,
                               int number_of_bits)
{
    self_p->pack = pack_raw;
    self_p->unpack = unpack_raw;

    if ((number_of_bits % 8) != 0) {
        mp_raise_NotImplementedError("Raw not multiple of 8 bits.");
    }
}

static void field_info_init_zero_padding(struct field_info_t *self_p)
{
    self_p->pack = pack_zero_padding;
    self_p->unpack = unpack_padding;
}

static void field_info_init_one_padding(struct field_info_t *self_p)
{
    self_p->pack = pack_one_padding;
    self_p->unpack = unpack_padding;
}

static void field_info_init(struct field_info_t *self_p,
                            int kind,
                            int number_of_bits)
{
    bool is_padding;

    is_padding = false;

    switch (kind) {

    case 's':
        field_info_init_signed(self_p, number_of_bits);
        break;

    case 'u':
        field_info_init_unsigned(self_p, number_of_bits);
        break;

    case 'f':
        field_info_init_float(self_p, number_of_bits);
        break;

    case 'b':
        field_info_init_bool(self_p, number_of_bits);
        break;

    case 't':
        field_info_init_text(self_p, number_of_bits);
        break;

    case 'r':
        field_info_init_raw(self_p, number_of_bits);
        break;

    case 'p':
        is_padding = true;
        field_info_init_zero_padding(self_p);
        break;

    case 'P':
        is_padding = true;
        field_info_init_one_padding(self_p);
        break;

    default:
        mp_raise_ValueError("Bad format field.");
        break;
    }

    self_p->number_of_bits = number_of_bits;
    self_p->is_padding = is_padding;
}

static int count_number_of_fields(const char *format_p,
                                  int *number_of_padding_fields_p)
{
    int count;

    count = 0;
    *number_of_padding_fields_p = 0;

    while (*format_p != '\0') {
        if ((*format_p >= 'A') && (*format_p <= 'z')) {
            count++;

            if ((*format_p == 'p') || (*format_p == 'P')) {
                (*number_of_padding_fields_p)++;
            }
        }

        format_p++;
    }

    return count;
}

static inline int isspace(int c){return (((c>='\t')&&(c<='\r')) || (c==' '));}
static inline int isdigit(int c){return ((c>='0')&&(c<='9'));}
const char *parse_field(const char *format_p,
                        int *kind_p,
                        int *number_of_bits_p)
{
    while (isspace(*format_p)) {
        format_p++;
    }

    *kind_p = *format_p;
    *number_of_bits_p = 0;
    format_p++;

    while (isdigit(*format_p)) {
        if (*number_of_bits_p > (INT_MAX / 100)) {
            mp_raise_ValueError("Field too long.");

            return NULL;
        }

        *number_of_bits_p *= 10;
        *number_of_bits_p += (*format_p - '0');
        format_p++;
    }

    if (*number_of_bits_p == 0) {
        mp_raise_ValueError("Field of size 0.");
        format_p = NULL;
    }

    return format_p;
}

static struct info_t *parse_format(PyObject *format_obj_p)
{
    int number_of_fields;
    struct info_t *info_p;
    const char *format_p;
    int i;
    int kind;
    int number_of_bits;
    int number_of_padding_fields;
    int res;

    // raises TypeError
    format_p = mp_obj_str_get_str(format_obj_p);

    number_of_fields = count_number_of_fields(format_p,
                                              &number_of_padding_fields);

    size_t size = sizeof(*info_p) + number_of_fields * sizeof(info_p->fields[0]);
    info_p = alloca(size);

    info_p->number_of_bits = 0;
    info_p->number_of_fields = number_of_fields;
    info_p->number_of_non_padding_fields = (
        number_of_fields - number_of_padding_fields);

    for (i = 0; i < info_p->number_of_fields; i++) {
        // raises ValueError
        format_p = parse_field(format_p, &kind, &number_of_bits);

        // raises NotImplementedError, ValueError
        field_info_init(&info_p->fields[i], kind, number_of_bits);

        info_p->number_of_bits += number_of_bits;
    }

    struct info_t* n_info_p = m_malloc(size);
    memcpy(n_info_p, info_p, size);

    return n_info_p;
}

static void pack_pack(struct info_t *info_p,
                      const mp_obj_t* args_p,
                      int consumed_args,
                      struct bitstream_writer_t *writer_p)
{
    mp_obj_t value_p;
    int i;
    struct field_info_t *field_p;

    for (i = 0; i < info_p->number_of_fields; i++) {
        field_p = &info_p->fields[i];

        if (field_p->is_padding) {
            value_p = mp_const_none;
        } else {
            value_p = args_p[consumed_args];
            consumed_args++;
        }

        // raises NotImplementedError, OverflowError, TypeError
        info_p->fields[i].pack(writer_p, value_p, field_p);
    }
}

static uint8_t* pack_prepare(struct info_t *info_p,
                             struct bitstream_writer_t *writer_p)
{
    uint8_t* data;

    // raises MemoryError
    data = m_new(uint8_t, (info_p->number_of_bits + 7) / 8);

    bitstream_writer_init(writer_p, data);

    return data;
}

static mp_obj_t pack(struct info_t *info_p,
                     const mp_obj_t* args_p,
                     int consumed_args,
                     size_t number_of_args)
{
    struct bitstream_writer_t writer;

    if (number_of_args < info_p->number_of_non_padding_fields) {
        mp_raise_ValueError("Too few arguments.");
    }

    uint8_t* data = pack_prepare(info_p, &writer);

    // raises NotImplementedError, OverflowError, TypeError
    pack_pack(info_p, args_p, consumed_args, &writer);

    // raises MemoryError
    mp_obj_t packed_p = mp_obj_new_bytes(data, (info_p->number_of_bits + 7) / 8);
    m_free(data);

    return packed_p;
}

static PyObject *m_pack(PyObject *module_p, PyObject *args_p)
{
    Py_ssize_t number_of_args;
    PyObject *packed_p;
    struct info_t *info_p;

    number_of_args = PyTuple_GET_SIZE(args_p);

    if (number_of_args < 1) {
        PyErr_SetString(PyExc_ValueError, "No format string.");

        return (NULL);
    }

    info_p = parse_format(PyTuple_GET_ITEM(args_p, 0));

    if (info_p == NULL) {
        return (NULL);
    }

    packed_p = pack(info_p, args_p, 1, number_of_args - 1);
    PyMem_RawFree(info_p);

    return (packed_p);
}

static mp_obj_t unpack(struct info_t *info_p, mp_obj_t data_p, long offset)
{
    struct bitstream_reader_t reader;
    mp_obj_t unpacked_p;
    mp_obj_t value_p;
    char *packed_p;
    int i;
    int produced_args;
    size_t size = 0;

    if(mp_obj_is_type(data_p, &mp_type_bytearray)){
        packed_p = ((mp_obj_array_t*)data_p)->items;
        size = ((mp_obj_array_t*)data_p)->len;
    }else if(mp_obj_is_type(data_p, &mp_type_list)){
        size_t len;
        mp_obj_t* items;
        mp_obj_list_get(data_p, &len, &items);
        size = len * sizeof(mp_int_t);
        packed_p = alloca(size);
        for(size_t j = 0; j < len; j++){
            // raises TypeError
            packed_p[j] = mp_obj_get_int(items[j]);
        }
    }else{
        // raises TypeError
        packed_p = (char*)mp_obj_str_get_data(data_p, &size);
    }

    if (size < ((info_p->number_of_bits + offset + 7) / 8)) {
        mp_raise_ValueError("Short data.");
    }

    bitstream_reader_init(&reader, (uint8_t *)packed_p);
    bitstream_reader_seek(&reader, offset);
    produced_args = 0;

    // raises MemoryError
    unpacked_p = mp_obj_new_tuple(info_p->number_of_non_padding_fields, NULL);

    size_t len;
    mp_obj_t* items;

    mp_obj_tuple_get(unpacked_p, &len, &items);

    for (i = 0; i < info_p->number_of_fields; i++) {
        // raises MemoryError, OverflowError
        value_p = info_p->fields[i].unpack(&reader, &info_p->fields[i]);

        if (value_p != mp_const_none) {
            items[produced_args] = value_p;
            produced_args++;
        }
    }

    return unpacked_p;
}

static PyObject *m_unpack(PyObject *module_p, PyObject *args_p)
{
    PyObject *format_p;
    PyObject *data_p;
    PyObject *unpacked_p;
    struct info_t *info_p;
    int res;

    res = PyArg_ParseTuple(args_p, "OO", &format_p, &data_p);

    if (res == 0) {
        return (NULL);
    }

    info_p = parse_format(format_p);

    if (info_p == NULL) {
        return (NULL);
    }

    unpacked_p = unpack(info_p, data_p, 0);
    PyMem_RawFree(info_p);

    return (unpacked_p);
}

static long parse_offset(PyObject *offset_p)
{
    unsigned long offset;

    offset = mp_obj_get_int(offset_p);

    if (offset == (unsigned long)-1) {
        mp_raise_ValueError("negative offset");
    }

    if (offset > 0x7fffffff) {
        mp_raise_ValueError("Offset must be less or equal to 2147483647 bits.");
    }

    return offset;
}

static void pack_into_prepare(struct info_t *info_p,
                             mp_obj_t buf_p,
                             mp_obj_t offset_p,
                             struct bitstream_writer_t *writer_p,
                             struct bitstream_writer_bounds_t *bounds_p)
{
    uint8_t *packed_p;
    size_t size;
    long offset;

    // raises TypeError, ValueError
    offset = parse_offset(offset_p);

    if (!mp_obj_is_type(buf_p, &mp_type_bytearray)) {
        mp_raise_TypeError("Bytearray needed.");
    }

    // raises TypeError
    packed_p = (uint8_t *)mp_obj_str_get_data(buf_p, &size);

    if (size < ((info_p->number_of_bits + offset + 7) / 8)) {
        mp_raise_ValueError("pack_into requires a buffer of at least enough bits");
    }

    bitstream_writer_init(writer_p, packed_p);
    bitstream_writer_bounds_save(bounds_p,
                                 writer_p,
                                 offset,
                                 info_p->number_of_bits);
    bitstream_writer_seek(writer_p, offset);
}

static mp_obj_t pack_into_finalize(struct bitstream_writer_bounds_t *bounds_p)
{
    bitstream_writer_bounds_restore(bounds_p);

    return mp_const_none;
}

static mp_obj_t pack_into(struct info_t *info_p,
                          mp_obj_t buf_p,
                          mp_obj_t offset_p,
                          mp_obj_t args_p,
                          size_t consumed_args,
                          size_t number_of_args)
{
    struct bitstream_writer_t writer;
    struct bitstream_writer_bounds_t bounds;

    if ((number_of_args - consumed_args) < info_p->number_of_non_padding_fields) {
        mp_raise_ValueError("Too few arguments.");
    }

    // raises TypeError, ValueError
    pack_into_prepare(info_p, buf_p, offset_p, &writer, &bounds);

    // raises NotImplementedError, OverflowError, TypeError
    pack_pack(info_p, args_p, consumed_args, &writer);

    return pack_into_finalize(&bounds);
}

static PyObject *m_pack_into(PyObject *module_p,
                             PyObject *args_p,
                             PyObject *kwargs_p)
{
    PyObject *format_p;
    PyObject *buf_p;
    PyObject *offset_p;
    PyObject *res_p;
    Py_ssize_t number_of_args;
    struct info_t *info_p;

    number_of_args = PyTuple_GET_SIZE(args_p);

    if (number_of_args < 3) {
        PyErr_SetString(PyExc_ValueError, "Too few arguments.");

        return (NULL);
    }

    format_p = PyTuple_GET_ITEM(args_p, 0);
    buf_p = PyTuple_GET_ITEM(args_p, 1);
    offset_p = PyTuple_GET_ITEM(args_p, 2);
    info_p = parse_format(format_p);

    if (info_p == NULL) {
        return (NULL);
    }

    res_p = pack_into(info_p,
                      buf_p,
                      offset_p,
                      args_p,
                      3,
                      number_of_args);
    PyMem_RawFree(info_p);

    return (res_p);
}

static mp_obj_t unpack_from(struct info_t *info_p,
                            mp_obj_t data_p,
                            mp_obj_t offset_p)
{
    long offset;

    offset = parse_offset(offset_p);

    return unpack(info_p, data_p, offset);
}

static PyObject *m_unpack_from(PyObject *module_p,
                               PyObject *args_p,
                               PyObject *kwargs_p)
{
    PyObject *format_p;
    PyObject *data_p;
    PyObject *offset_p;
    PyObject *unpacked_p;
    struct info_t *info_p;
    int res;
    static char *keywords[] = {
        "fmt",
        "data",
        "offset",
        NULL
    };

    offset_p = mp_obj_new_int(0);
    res = PyArg_ParseTupleAndKeywords(args_p,
                                      kwargs_p,
                                      "OO|O",
                                      &keywords[0],
                                      &format_p,
                                      &data_p,
                                      &offset_p);

    if (res == 0) {
        return (NULL);
    }

    info_p = parse_format(format_p);

    if (info_p == NULL) {
        return (NULL);
    }

    unpacked_p = unpack_from(info_p, data_p, offset_p);
    PyMem_RawFree(info_p);

    return (unpacked_p);
}

static void pack_dict_pack(struct info_t *info_p,
                           mp_obj_t names_p,
                           mp_obj_t data_p,
                           struct bitstream_writer_t *writer_p)
{
    mp_obj_t value_p;
    int i;
    int consumed_args;
    struct field_info_t *field_p;

    consumed_args = 0;

    size_t len;
    mp_obj_t* items;
    mp_obj_list_get(names_p, &len, &items);

    for (i = 0; i < info_p->number_of_fields; i++) {
        field_p = &info_p->fields[i];

        if (field_p->is_padding) {
            value_p = mp_const_none;
        } else {
            // raises KeyError
            value_p = mp_obj_dict_get(data_p, items[consumed_args]);
            consumed_args++;

            if (value_p == mp_const_none) {
                mp_raise_msg(&mp_type_KeyError, "Missing value.");
                break;
            }
        }

        // raises NotImplementedError, OverflowError, TypeError
        info_p->fields[i].pack(writer_p, value_p, field_p);
    }
}

static mp_obj_t pack_dict(struct info_t *info_p,
                          mp_obj_t names_p,
                          mp_obj_t data_p)
{
    struct bitstream_writer_t writer;
    mp_obj_t packed_p;


    if (((mp_obj_list_t*)MP_OBJ_TO_PTR(names_p))->len < info_p->number_of_non_padding_fields) {
        mp_raise_ValueError("Too few names.");
    }

    // raises MemoryError
    packed_p = pack_prepare(info_p, &writer);

    if (packed_p == mp_const_none) {
        return mp_const_none;
    }

    // raises KeyError, NotImplementedError, OverflowError, TypeError
    pack_dict_pack(info_p, names_p, data_p, &writer);

    return packed_p;
}

static PyObject *m_pack_dict(PyObject *module_p, PyObject *args_p)
{
    PyObject *format_p;
    PyObject *names_p;
    PyObject *data_p;
    PyObject *packed_p;
    struct info_t *info_p;
    int res;

    res = PyArg_ParseTuple(args_p, "OOO", &format_p, &names_p, &data_p);

    if (res == 0) {
        return (NULL);
    }

    info_p = parse_format(format_p);

    if (info_p == NULL) {
        return (NULL);
    }

    is_names_list(names_p);

    packed_p = pack_dict(info_p, names_p, data_p);
    PyMem_RawFree(info_p);

    return (packed_p);
}

static mp_obj_t unpack_dict(struct info_t *info_p,
                            mp_obj_t names_p,
                            mp_obj_t data_p,
                            long offset)
{
    struct bitstream_reader_t reader;
    mp_obj_t unpacked_p;
    mp_obj_t value_p;
    char *packed_p;
    int i;
    size_t size;
    int produced_args;

    if (((mp_obj_list_t*)MP_OBJ_TO_PTR(names_p))->len < info_p->number_of_non_padding_fields) {
        mp_raise_ValueError("Too few names.");
    }

    // raises MemoryError
    unpacked_p = mp_obj_new_dict(0);

    // raises TypeError
    packed_p = (char*)mp_obj_str_get_data(data_p, &size);

    if (size < ((info_p->number_of_bits + offset + 7) / 8)) {
        mp_raise_ValueError("Short data.");
    }

    bitstream_reader_init(&reader, (uint8_t *)packed_p);
    bitstream_reader_seek(&reader, offset);
    produced_args = 0;

    size_t len;
    mp_obj_t* names;
    mp_obj_list_get(names_p, &len, &names);

    for (i = 0; i < info_p->number_of_fields; i++) {
        // raises MemoryError, OverflowError
        value_p = info_p->fields[i].unpack(&reader, &info_p->fields[i]);

        if (value_p != mp_const_none) {
            // raises MemoryError
            mp_obj_dict_store(unpacked_p, names[produced_args], value_p);
            produced_args++;
        }
    }

    return unpacked_p;
}

static PyObject *m_unpack_dict(PyObject *module_p, PyObject *args_p)
{
    PyObject *format_p;
    PyObject *names_p;
    PyObject *data_p;
    PyObject *unpacked_p;
    struct info_t *info_p;
    int res;

    res = PyArg_ParseTuple(args_p, "OOO", &format_p, &names_p, &data_p);

    if (res == 0) {
        return (NULL);
    }

    info_p = parse_format(format_p);

    if (info_p == NULL) {
        return (NULL);
    }

    is_names_list(names_p);

    unpacked_p = unpack_dict(info_p, names_p, data_p, 0);
    PyMem_RawFree(info_p);

    return (unpacked_p);
}

static mp_obj_t unpack_from_dict(struct info_t *info_p,
                                 mp_obj_t names_p,
                                 mp_obj_t data_p,
                                 mp_obj_t offset_p)
{
    long offset;

    // raises TypeError, ValueError
    offset = parse_offset(offset_p);

    // raises MemoryError, OverflowError, TypeError, ValueError
    return unpack_dict(info_p, names_p, data_p, offset);
}

static mp_obj_t pack_into_dict(struct info_t *info_p,
                               mp_obj_t names_p,
                               mp_obj_t buf_p,
                               mp_obj_t offset_p,
                               mp_obj_t data_p)
{
    struct bitstream_writer_t writer;
    struct bitstream_writer_bounds_t bounds;

    // raises TypeError, ValueError
    pack_into_prepare(info_p, buf_p, offset_p, &writer, &bounds);

    // raises KeyError, NotImplementedError, OverflowError, TypeError
    pack_dict_pack(info_p, names_p, data_p, &writer);

    return pack_into_finalize(&bounds);
}

static PyObject *m_pack_into_dict(PyObject *module_p,
                                  PyObject *args_p,
                                  PyObject *kwargs_p)
{
    PyObject *format_p;
    PyObject *names_p;
    PyObject *buf_p;
    PyObject *offset_p;
    PyObject *data_p;
    PyObject *res_p;
    struct info_t *info_p;
    int res;
    static char *keywords[] = {
        "fmt",
        "names",
        "buf",
        "offset",
        "data",
        NULL
    };

    offset_p = mp_obj_new_int(0);;
    res = PyArg_ParseTupleAndKeywords(args_p,
                                      kwargs_p,
                                      "OOOOO",
                                      &keywords[0],
                                      &format_p,
                                      &names_p,
                                      &buf_p,
                                      &offset_p,
                                      &data_p);

    if (res == 0) {
        return (NULL);
    }

    info_p = parse_format(format_p);

    if (info_p == NULL) {
        return (NULL);
    }

    is_names_list(names_p);

    res_p = pack_into_dict(info_p, names_p, buf_p, offset_p, data_p);
    PyMem_RawFree(info_p);

    return (res_p);
}

static PyObject *m_unpack_from_dict(PyObject *module_p,
                                    PyObject *args_p,
                                    PyObject *kwargs_p)
{
    PyObject *format_p;
    PyObject *names_p;
    PyObject *data_p;
    PyObject *offset_p;
    PyObject *unpacked_p;
    struct info_t *info_p;
    int res;
    static char *keywords[] = {
        "fmt",
        "names",
        "data",
        "offset",
        NULL
    };

    offset_p = mp_obj_new_int(0);;
    res = PyArg_ParseTupleAndKeywords(args_p,
                                      kwargs_p,
                                      "OOO|O",
                                      &keywords[0],
                                      &format_p,
                                      &names_p,
                                      &data_p,
                                      &offset_p);

    if (res == 0) {
        return (NULL);
    }

    info_p = parse_format(format_p);

    if (info_p == NULL) {
        return (NULL);
    }

    is_names_list(names_p);

    unpacked_p = unpack_from_dict(info_p, names_p, data_p, offset_p);
    PyMem_RawFree(info_p);

    return (unpacked_p);
}

static mp_obj_t calcsize(struct info_t *info_p)
{
    // raises MemoryError, OverflowError
    return mp_obj_new_int_from_ll(info_p->number_of_bits);
}

static PyObject *compiled_format_new(PyTypeObject *subtype_p,
                                     PyObject *format_p)
{
    struct compiled_format_t *self_p;

    self_p = (struct compiled_format_t *)subtype_p->tp_alloc(subtype_p, 0);

    if (self_p != NULL) {
        self_p->info_p = parse_format(format_p);

        if (self_p->info_p == NULL) {
            PyObject_Free(self_p);
            self_p = NULL;
        }
    }

    return ((PyObject *)self_p);
}

static void compiled_format_dealloc(struct compiled_format_t *self_p)
{
    PyMem_RawFree(self_p->info_p);
}

static PyObject *m_compiled_format_pack(struct compiled_format_t *self_p,
                                        PyObject *args_p)
{
    return (pack(self_p->info_p, args_p, 0, PyTuple_GET_SIZE(args_p)));
}

static PyObject *m_compiled_format_unpack(struct compiled_format_t *self_p,
                                          PyObject *args_p)
{
    PyObject *data_p;
    int res;

    res = PyArg_ParseTuple(args_p, "O", &data_p);

    if (res == 0) {
        return (NULL);
    }

    return (unpack(self_p->info_p, data_p, 0));
}

static PyObject *m_compiled_format_pack_into(struct compiled_format_t *self_p,
                                             PyObject *args_p,
                                             PyObject *kwargs_p)
{
    PyObject *buf_p;
    PyObject *offset_p;
    Py_ssize_t number_of_args;

    number_of_args = PyTuple_GET_SIZE(args_p);

    if (number_of_args < 2) {
        PyErr_SetString(PyExc_ValueError, "Too few arguments.");

        return (NULL);
    }

    buf_p = PyTuple_GET_ITEM(args_p, 0);
    offset_p = PyTuple_GET_ITEM(args_p, 1);

    return (pack_into(self_p->info_p,
                      buf_p,
                      offset_p,
                      args_p,
                      2,
                      number_of_args));
}

static PyObject *m_compiled_format_unpack_from(struct compiled_format_t *self_p,
                                               PyObject *args_p,
                                               PyObject *kwargs_p)
{
    PyObject *data_p;
    PyObject *offset_p;
    int res;
    static char *keywords[] = {
        "data",
        "offset",
        NULL
    };

    offset_p = mp_obj_new_int(0);;
    res = PyArg_ParseTupleAndKeywords(args_p,
                                      kwargs_p,
                                      "O|O",
                                      &keywords[0],
                                      &data_p,
                                      &offset_p);

    if (res == 0) {
        return (NULL);
    }

    return (unpack_from(self_p->info_p, data_p, offset_p));
}

static PyObject *m_compiled_format_calcsize(struct compiled_format_t *self_p)
{
    return (calcsize(self_p->info_p));
}

static PyObject *compiled_format_dict_new(PyTypeObject *subtype_p,
                                          PyObject *format_p,
                                          PyObject *names_p)
{
    struct compiled_format_dict_t *self_p;

    is_names_list(names_p);

    self_p = (struct compiled_format_dict_t *)subtype_p->tp_alloc(subtype_p, 0);

    if (self_p != NULL) {
        self_p->info_p = parse_format(format_p);

        if (self_p->info_p == NULL) {
            PyObject_Free(self_p);
            self_p = NULL;
        } else {
            Py_INCREF(names_p);
            self_p->names_p = names_p;
        }
    }

    return ((PyObject *)self_p);
}

static void compiled_format_dict_dealloc(struct compiled_format_dict_t *self_p)
{
    PyMem_RawFree(self_p->info_p);
    Py_DECREF(self_p->names_p);
}

static PyObject *m_compiled_format_dict_pack(struct compiled_format_dict_t *self_p,
                                             PyObject *data_p)
{
    return (pack_dict(self_p->info_p, self_p->names_p, data_p));
}

static PyObject *m_compiled_format_dict_unpack(
    struct compiled_format_dict_t *self_p,
    PyObject *data_p)
{
    return (unpack_dict(self_p->info_p, self_p->names_p, data_p, 0));
}

static PyObject *m_compiled_format_dict_pack_into(
    struct compiled_format_dict_t *self_p,
    PyObject *args_p,
    PyObject *kwargs_p)
{
    PyObject *buf_p;
    PyObject *data_p;
    PyObject *offset_p;
    int res;
    static char *keywords[] = {
        "buf",
        "data",
        "offset",
        NULL
    };

    res = PyArg_ParseTupleAndKeywords(args_p,
                                      kwargs_p,
                                      "OOO",
                                      &keywords[0],
                                      &buf_p,
                                      &data_p,
                                      &offset_p);

    if (res == 0) {
        return (NULL);
    }

    return (pack_into_dict(self_p->info_p,
                           self_p->names_p,
                           buf_p,
                           data_p,
                           offset_p));
}

static PyObject *m_compiled_format_dict_unpack_from(
    struct compiled_format_dict_t *self_p,
    PyObject *args_p,
    PyObject *kwargs_p)
{
    PyObject *data_p;
    PyObject *offset_p;
    int res;
    static char *keywords[] = {
        "data",
        "offset",
        NULL
    };

    offset_p = mp_obj_new_int(0);;
    res = PyArg_ParseTupleAndKeywords(args_p,
                                      kwargs_p,
                                      "O|O",
                                      &keywords[0],
                                      &data_p,
                                      &offset_p);

    if (res == 0) {
        return (NULL);
    }

    return (unpack_from_dict(self_p->info_p, self_p->names_p, data_p, offset_p));
}

static PyObject *m_compiled_format_dict_calcsize(
    struct compiled_format_dict_t *self_p)
{
    return (calcsize(self_p->info_p));
}

static PyObject *m_compile(PyObject *module_p,
                           PyObject *args_p,
                           PyObject *kwargs_p)
{
    PyObject *format_p;
    PyObject *names_p;
    int res;
    static char *keywords[] = {
        "fmt",
        "names",
        NULL
    };

    names_p = Py_None;
    res = PyArg_ParseTupleAndKeywords(args_p,
                                      kwargs_p,
                                      "O|O",
                                      &keywords[0],
                                      &format_p,
                                      &names_p);

    if (res == 0) {
        return (NULL);
    }

    if (names_p == Py_None) {
        return (compiled_format_new(&compiled_format_type, format_p));
    } else {
        return (compiled_format_dict_new(&compiled_format_dict_type,
                                         format_p,
                                         names_p));
    }
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

mp_obj_t bitstruct_CompiledFormat_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args);
STATIC void bitstruct_CompiledFormat_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind);
STATIC mp_obj_t bitstruct_CompiledFormat_pack(size_t n_args, const mp_obj_t *args);
STATIC mp_obj_t bitstruct_CompiledFormat_unpack(mp_obj_t self_in, mp_obj_t data);
STATIC mp_obj_t bitstruct_CompiledFormat_pack_into(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args);
STATIC mp_obj_t bitstruct_CompiledFormat_unpack_from(size_t n_args, const mp_obj_t *args);

mp_obj_t bitstruct_CompiledFormatDict_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args);
STATIC void bitstruct_CompiledFormatDict_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind);
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack(mp_obj_t self_in, mp_obj_t data);
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack(mp_obj_t self_in, mp_obj_t data);
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack_into(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args);
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack_from(size_t n_args, const mp_obj_t *args);

STATIC mp_obj_t bitstruct_pack(size_t n_args, const mp_obj_t *args);
STATIC mp_obj_t bitstruct_unpack(mp_obj_t format, mp_obj_t data);
STATIC mp_obj_t bitstruct_pack_into(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args);
STATIC mp_obj_t bitstruct_unpack_from(size_t n_args, const mp_obj_t *args);
STATIC mp_obj_t bitstruct_pack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data);
STATIC mp_obj_t bitstruct_unpack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data);
STATIC mp_obj_t bitstruct_pack_into_dict(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args);
STATIC mp_obj_t bitstruct_unpack_from_dict(size_t n_args, const mp_obj_t *args);
STATIC mp_obj_t bitstruct_calcsize(mp_obj_t format);
STATIC mp_obj_t bitstruct_byteswap(size_t n_args, const mp_obj_t *args);
STATIC mp_obj_t bitstruct_compile(size_t n_args, const mp_obj_t *args);

STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(bitstruct_CompiledFormat_pack_fun_obj, 1, bitstruct_CompiledFormat_pack);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitstruct_CompiledFormat_unpack_fun_obj, bitstruct_CompiledFormat_unpack);
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(bitstruct_CompiledFormat_pack_into_fun_obj, 3, bitstruct_CompiledFormat_pack_into);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_CompiledFormat_unpack_from_fun_obj, 2, 3,
                                           bitstruct_CompiledFormat_unpack_from);

STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitstruct_CompiledFormatDict_pack_fun_obj, bitstruct_CompiledFormatDict_pack);
STATIC MP_DEFINE_CONST_FUN_OBJ_2(bitstruct_CompiledFormatDict_unpack_fun_obj, bitstruct_CompiledFormatDict_unpack);
STATIC MP_DEFINE_CONST_FUN_OBJ_KW(bitstruct_CompiledFormatDict_pack_into_fun_obj, 4, bitstruct_CompiledFormatDict_pack_into);
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(bitstruct_CompiledFormatDict_unpack_from_fun_obj, 2, 3,
                                           bitstruct_CompiledFormatDict_unpack_from);

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
};
STATIC MP_DEFINE_CONST_DICT(bitstruct_CompiledFormat_locals_dict,bitstruct_CompiledFormat_locals_dict_table);

STATIC const mp_rom_map_elem_t bitstruct_CompiledFormatDict_locals_dict_table[]={
    // class methods
    { MP_ROM_QSTR(MP_QSTR_pack),        MP_ROM_PTR(&bitstruct_CompiledFormatDict_pack_fun_obj)        },
    { MP_ROM_QSTR(MP_QSTR_unpack),      MP_ROM_PTR(&bitstruct_CompiledFormatDict_unpack_fun_obj)      },
    { MP_ROM_QSTR(MP_QSTR_pack_into),   MP_ROM_PTR(&bitstruct_CompiledFormatDict_pack_into_fun_obj)   },
    { MP_ROM_QSTR(MP_QSTR_unpack_from), MP_ROM_PTR(&bitstruct_CompiledFormatDict_unpack_from_fun_obj) },
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


mp_obj_t bitstruct_CompiledFormat_make_new(const mp_obj_type_t *type,
                                           size_t n_args,
                                           size_t n_kw,
                                           const mp_obj_t *args){
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    bitstruct_CompiledFormat_obj_t *self = m_new_obj(bitstruct_CompiledFormat_obj_t);

    self->base.type = &bitstruct_CompiledFormat_type;

    return MP_OBJ_FROM_PTR(self);
}

STATIC void bitstruct_CompiledFormat_print(const mp_print_t *print,
                                           mp_obj_t self_in,mp_print_kind_t kind){
    bitstruct_CompiledFormat_obj_t *self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "CompiledFormat()");
}

/**
 * Python: bitstruct.CompiledFormat.pack(*args)
 * @param self
 * @param args*
 */
STATIC mp_obj_t bitstruct_CompiledFormat_pack(size_t n_args, const mp_obj_t *args){
    bitstruct_CompiledFormat_obj_t *self = MP_OBJ_TO_PTR(args[0]);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.CompiledFormat.unpack(data)
 * @param self
 * @param data
 */
STATIC mp_obj_t bitstruct_CompiledFormat_unpack(mp_obj_t self_in, mp_obj_t data){
    bitstruct_CompiledFormat_obj_t *self = MP_OBJ_TO_PTR(self_in);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.CompiledFormat.pack_into(buf, offset, *args, **kwargs)
 * @param self
 * @param buf
 * @param offset
 * @param args*
 * @param kwargs:
 */
STATIC mp_obj_t bitstruct_CompiledFormat_pack_into(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
    bitstruct_CompiledFormat_obj_t *self = MP_OBJ_TO_PTR(pos_args[0]);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.CompiledFormat.unpack_from(data, offset = 0)
 * @param self
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_CompiledFormat_unpack_from(size_t n_args, const mp_obj_t *args){
    bitstruct_CompiledFormat_obj_t *self = MP_OBJ_TO_PTR(args[0]);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.CompiledFormatDict(fmt, names = None)
 * @param fmt
 * @param opt: names = None
 */
mp_obj_t bitstruct_CompiledFormatDict_make_new(const mp_obj_type_t *type,
                                               size_t n_args,
                                               size_t n_kw,
                                               const mp_obj_t *args){
    mp_arg_check_num(n_args, n_kw, 1, 2, true);

    bitstruct_CompiledFormatDict_obj_t *self = m_new_obj(bitstruct_CompiledFormatDict_obj_t);

    self->base.type = &bitstruct_CompiledFormatDict_type;

    return MP_OBJ_FROM_PTR(self);
}

STATIC void bitstruct_CompiledFormatDict_print(const mp_print_t *print,
                                               mp_obj_t self_in,mp_print_kind_t kind){
    bitstruct_CompiledFormatDict_obj_t *self = MP_OBJ_TO_PTR(self_in);
    mp_printf(print, "CompiledFormatDict()");
}

/**
 * Python: bitstruct.CompiledFormatDict.pack(data)
 * @param self
 * @param data
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack(mp_obj_t self_in, mp_obj_t data){
    bitstruct_CompiledFormatDict_obj_t *self = MP_OBJ_TO_PTR(self_in);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.CompiledFormatDict.unpack(data)
 * @param self
 * @param data
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack(mp_obj_t self_in, mp_obj_t data){
    bitstruct_CompiledFormatDict_obj_t *self = MP_OBJ_TO_PTR(self_in);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.CompiledFormatDict.pack_into(buf, offset, data, **kwargs)
 * @param self
 * @param buf
 * @param offset
 * @param data
 * @param kwargs:
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_pack_into(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
    bitstruct_CompiledFormatDict_obj_t *self = MP_OBJ_TO_PTR(pos_args[0]);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.CompiledFormatDict.unpack_from(data, offset = 0)
 * @param self
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_CompiledFormatDict_unpack_from(size_t n_args, const mp_obj_t *args){
    bitstruct_CompiledFormatDict_obj_t *self = MP_OBJ_TO_PTR(args[0]);
    (void)self;
    return mp_const_none;
}

/**
 * Python: bitstruct.pack(fmt, *args)
 * @param fmt
 * @param args*
 */
STATIC mp_obj_t bitstruct_pack(size_t n_args, const mp_obj_t *args){
    return mp_const_none;
}

/**
 * Python: bitstruct.unpack(fmt, data)
 * @param fmt
 * @param data
 */
STATIC mp_obj_t bitstruct_unpack(mp_obj_t format, mp_obj_t data){
    return mp_const_none;
}

/**
 * Python: bitstruct.pack_into(fmt, buf, offset, *args, **kwargs)
 * @param fmt
 * @param buf
 * @param offset
 * @param args*
 * @param kwargs:
 */
STATIC mp_obj_t bitstruct_pack_into(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
    return mp_const_none;
}

/**
 * Python: bitstruct.unpack_from(fmt, data, offset=0)
 * @param fmt
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_unpack_from(size_t n_args, const mp_obj_t *args){
    return mp_const_none;
}

/**
 * Python: bitstruct.pack_dict(fmt, names, data)
 * @param fmt
 * @param names
 * @param data
 */
STATIC mp_obj_t bitstruct_pack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data){
    return mp_const_none;
}

/**
 * Python: bitstruct.unpack_dict(fmt, names, data)
 * @param fmt
 * @param names
 * @param data
 */
STATIC mp_obj_t bitstruct_unpack_dict(mp_obj_t format, mp_obj_t names, mp_obj_t data){
    return mp_const_none;
}

/**
 * Python: bitstruct.pack_into_dict(fmt, names, buf, offset, data, **kwargs)
 * @param fmt
 * @param names
 * @param buf
 * @param offset
 * @param data
 * @param kwargs:
 */
STATIC mp_obj_t bitstruct_pack_into_dict(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args){
    return mp_const_none;
}

/**
 * Python: bitstruct.unpack_from_dict(fmt, names, data, offset=0)
 * @param fmt
 * @param names
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_unpack_from_dict(size_t n_args, const mp_obj_t *args){
    return mp_const_none;
}

/**
 * Python: bitstruct.calcsize(fmt)
 * @param fmt
 */
STATIC mp_obj_t bitstruct_calcsize(mp_obj_t format){
    // raises MemoryError, NotImplementedError, TypeError, ValueError
    struct info_t *info_p = parse_format(format_p);

    // raises MemoryError, OverflowError
    size_p = calcsize(info_p);
    m_free(info_p);

    return size_p;
}

/**
 * Python: bitstruct.byteswap(fmt, data, offset=0)
 * @param fmt
 * @param data
 * @param opt: offset = 0
 */
STATIC mp_obj_t bitstruct_byteswap(size_t n_args, const mp_obj_t *args){
    const char *c_format_p;
    uint8_t *src_p;
    uint8_t *dst_p;
    size_t size;
    int offset = 0;

    if(n_args == 3){
        // raises TypeError
        offset = mp_obj_get_int(args[2]);
    }

    // raises TypeError
    c_format_p = mp_obj_str_get_str(args[0]);

    // raises TypeError
    src_p = (uint8_t*)mp_obj_str_get_data(args[1], &size);

    // raises MemoryError
    dst_p = alloca(size);

    while (*c_format_p != '\0') {
        switch (*c_format_p) {

        case '1':
            if ((size - offset) < 1) {
                goto out1;
            }

            dst_p[offset] = src_p[offset];
            offset += 1;
            break;

        case '2':
            if ((size - offset) < 2) {
                goto out1;
            }

            dst_p[offset + 0] = src_p[offset + 1];
            dst_p[offset + 1] = src_p[offset + 0];
            offset += 2;
            break;

        case '4':
            if ((size - offset) < 4) {
                goto out1;
            }

            dst_p[offset + 0] = src_p[offset + 3];
            dst_p[offset + 1] = src_p[offset + 2];
            dst_p[offset + 2] = src_p[offset + 1];
            dst_p[offset + 3] = src_p[offset + 0];
            offset += 4;
            break;

        case '8':
            if ((size - offset) < 8) {
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
STATIC mp_obj_t bitstruct_compile(size_t n_args, const mp_obj_t *args){
    return mp_const_none;
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
};

STATIC MP_DEFINE_CONST_DICT(
    mp_module_bitstruct_globals,
    bitstruct_globals_table
    );

const mp_obj_module_t mp_module_bitstruct = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&mp_module_bitstruct_globals,
};
