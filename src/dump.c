/*
 * Copyright (c) 2009-2014 Petri Lehtinen <petri@digip.org>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "jansson.h"
#include "jansson_private.h"
#include "strbuffer.h"
#include "utf.h"

#define MAX_INTEGER_STR_LENGTH  100
#define MAX_REAL_STR_LENGTH     100

#define FLAGS_TO_INDENT(f)      ((f) & 0x1F)
#define FLAGS_TO_PRECISION(f)   (((f) >> 11) & 0x1F)

struct object_key {
    size_t serial;
    const char *key;
};

static int dump_to_strbuffer(const char *buffer, size_t size, void *data)
{
    return strbuffer_append_bytes((strbuffer_t *)data, buffer, size);
}

static int dump_to_file(const char *buffer, size_t size, void *data)
{
    FILE *dest = (FILE *)data;
    if(fwrite(buffer, size, 1, dest) != 1)
        return -1;
    return 0;
}

/* 32 spaces (the maximum indentation size) */
static const char whitespace[] = "                                ";

static int dump_indent(size_t flags, int depth, int space, json_dump_callback_t dump, void *data)
{
    if(FLAGS_TO_INDENT(flags) > 0)
    {
        unsigned int ws_count = FLAGS_TO_INDENT(flags), n_spaces = depth * ws_count;

        if(dump("\n", 1, data))
            return -1;

        while(n_spaces > 0)
        {
            int cur_n = n_spaces < sizeof whitespace - 1 ? n_spaces : sizeof whitespace - 1;

            if(dump(whitespace, cur_n, data))
                return -1;

            n_spaces -= cur_n;
        }
    }
    else if(space && !(flags & JSON_COMPACT))
    {
        return dump(" ", 1, data);
    }
    return 0;
}

static int dump_string(const char *str, size_t len, json_dump_callback_t dump, void *data, size_t flags)
{
    const char *pos, *end, *lim;
    int32_t codepoint;

    if(dump("\"", 1, data))
        return -1;

    end = pos = str;
    lim = str + len;
    while(1)
    {
        const char *text;
        char seq[13];
        int length;

        while(end < lim)
        {
            end = utf8_iterate(pos, lim - pos, &codepoint);
            if(!end)
                return -1;

            /* mandatory escape or control char */
            if(codepoint == '\\' || codepoint == '"' || codepoint < 0x20)
                break;

            /* slash */
            if((flags & JSON_ESCAPE_SLASH) && codepoint == '/')
                break;

            /* non-ASCII */
            if((flags & JSON_ENSURE_ASCII) && codepoint > 0x7F)
                break;

            pos = end;
        }

        if(pos != str) {
            if(dump(str, pos - str, data))
                return -1;
        }

        if(end == pos)
            break;

        /* handle \, /, ", and control codes */
        length = 2;
        switch(codepoint)
        {
            case '\\': text = "\\\\"; break;
            case '\"': text = "\\\""; break;
            case '\b': text = "\\b"; break;
            case '\f': text = "\\f"; break;
            case '\n': text = "\\n"; break;
            case '\r': text = "\\r"; break;
            case '\t': text = "\\t"; break;
            case '/':  text = "\\/"; break;
            default:
            {
                /* codepoint is in BMP */
                if(codepoint < 0x10000)
                {
                    snprintf(seq, 13, "\\u%04X", codepoint);
                    length = 6;
                }

                /* not in BMP -> construct a UTF-16 surrogate pair */
                else
                {
                    int32_t first, last;

                    codepoint -= 0x10000;
                    first = 0xD800 | ((codepoint & 0xffc00) >> 10);
                    last = 0xDC00 | (codepoint & 0x003ff);

                    snprintf(seq, 13, "\\u%04X\\u%04X", first, last);
                    length = 12;
                }

                text = seq;
                break;
            }
        }

        if(dump(text, length, data))
            return -1;

        str = pos = end;
    }

    return dump("\"", 1, data);
}

static int object_key_compare_keys(const void *key1, const void *key2)
{
    return strcmp(((const struct object_key *)key1)->key,
                  ((const struct object_key *)key2)->key);
}

static int object_key_compare_serials(const void *key1, const void *key2)
{
    size_t a = ((const struct object_key *)key1)->serial;
    size_t b = ((const struct object_key *)key2)->serial;

    return a < b ? -1 : a == b ? 0 : 1;
}

struct dump_ctx {
    const json_t *json;
    struct dump_ctx *next;
};

static int detect_cycle(struct dump_ctx *ctx, const json_t *json)
{
    while(ctx)
    {
        if(ctx->json == json) return 1;
        ctx = ctx->next;
    }
    return 0;
}

static int do_dump(struct dump_ctx *ctx, const json_t *json, size_t flags, int depth,
                   json_dump_callback_t dump, void *data)
{
    if(!json)
        return -1;

    switch(json_typeof(json)) {
        case JSON_NULL:
            return dump("null", 4, data);

        case JSON_TRUE:
            return dump("true", 4, data);

        case JSON_FALSE:
            return dump("false", 5, data);

        case JSON_INTEGER:
        {
            char buffer[MAX_INTEGER_STR_LENGTH];
            int size;

            size = snprintf(buffer, MAX_INTEGER_STR_LENGTH,
                            "%" JSON_INTEGER_FORMAT,
                            json_integer_value(json));
            if(size < 0 || size >= MAX_INTEGER_STR_LENGTH)
                return -1;

            return dump(buffer, size, data);
        }

        case JSON_REAL:
        {
            char buffer[MAX_REAL_STR_LENGTH];
            int size;
            double value = json_real_value(json);

            size = jsonp_dtostr(buffer, MAX_REAL_STR_LENGTH, value,
                                FLAGS_TO_PRECISION(flags));
            if(size < 0)
                return -1;

            return dump(buffer, size, data);
        }

        case JSON_STRING:
            return dump_string(json_string_value(json), json_string_length(json), dump, data, flags);

        case JSON_ARRAY:
        {
            struct dump_ctx child_ctx;
            size_t n;
            size_t i;

            /* detect circular references */
            if (detect_cycle(ctx, json))
                return -1;

            n = json_array_size(json);

            if(dump("[", 1, data))
                return -1;

            if(n == 0)
                return dump("]", 1, data);

            child_ctx.json = json;
            child_ctx.next = ctx;

            if(dump_indent(flags, depth + 1, 0, dump, data))
                return -1;

            for(i = 0; i < n; ++i) {
                if(do_dump(&child_ctx, json_array_get(json, i), flags, depth + 1,
                           dump, data))
                    return -1;

                if(i < n - 1)
                {
                    if(dump(",", 1, data) ||
                       dump_indent(flags, depth + 1, 1, dump, data))
                        return -1;
                }
                else
                {
                    if(dump_indent(flags, depth, 0, dump, data))
                        return -1;
                }
            }

            return dump("]", 1, data);
        }

        case JSON_OBJECT:
        {
            struct dump_ctx child_ctx;
            void *iter;
            const char *separator;
            int separator_length;

            if(flags & JSON_COMPACT) {
                separator = ":";
                separator_length = 1;
            }
            else {
                separator = ": ";
                separator_length = 2;
            }

            /* detect circular references */
            if (detect_cycle(ctx, json))
                return -1;

            iter = json_object_iter((json_t *)json);

            if(dump("{", 1, data))
                return -1;

            if(!iter)
                return dump("}", 1, data);

            child_ctx.json = json;
            child_ctx.next = ctx;

            if(dump_indent(flags, depth + 1, 0, dump, data))
                return -1;

            if(flags & JSON_SORT_KEYS || flags & JSON_PRESERVE_ORDER)
            {
                struct object_key *keys;
                size_t size, i;
                int (*cmp_func)(const void *, const void *);

                size = json_object_size(json);
                keys = jsonp_malloc(size * sizeof(struct object_key));
                if(!keys)
                    return -1;

                i = 0;
                while(iter)
                {
                    keys[i].serial = hashtable_iter_serial(iter);
                    keys[i].key = json_object_iter_key(iter);
                    iter = json_object_iter_next((json_t *)json, iter);
                    i++;
                }
                assert(i == size);

                if(flags & JSON_SORT_KEYS)
                    cmp_func = object_key_compare_keys;
                else
                    cmp_func = object_key_compare_serials;

                qsort(keys, size, sizeof(struct object_key), cmp_func);

                for(i = 0; i < size; i++)
                {
                    const char *key;
                    json_t *value;

                    key = keys[i].key;
                    value = json_object_get(json, key);
                    assert(value);

                    dump_string(key, strlen(key), dump, data, flags);
                    if(dump(separator, separator_length, data) ||
                       do_dump(&child_ctx, value, flags, depth + 1, dump, data))
                    {
                        jsonp_free(keys);
                        return -1;
                    }

                    if(i < size - 1)
                    {
                        if(dump(",", 1, data) ||
                           dump_indent(flags, depth + 1, 1, dump, data))
                        {
                            jsonp_free(keys);
                            return -1;
                        }
                    }
                    else
                    {
                        if(dump_indent(flags, depth, 0, dump, data))
                        {
                            jsonp_free(keys);
                            return -1;
                        }
                    }
                }

                jsonp_free(keys);
            }
            else
            {
                /* Don't sort keys */

                while(iter)
                {
                    void *next = json_object_iter_next((json_t *)json, iter);
                    const char *key = json_object_iter_key(iter);

                    dump_string(key, strlen(key), dump, data, flags);
                    if(dump(separator, separator_length, data) ||
                       do_dump(&child_ctx, json_object_iter_value(iter), flags, depth + 1,
                               dump, data))
                        return -1;

                    if(next)
                    {
                        if(dump(",", 1, data) ||
                           dump_indent(flags, depth + 1, 1, dump, data))
                            return -1;
                    }
                    else
                    {
                        if(dump_indent(flags, depth, 0, dump, data))
                            return -1;
                    }

                    iter = next;
                }
            }

            return dump("}", 1, data);
        }

        default:
            /* not reached */
            return -1;
    }
}

char *json_dumps(const json_t *json, size_t flags)
{
    strbuffer_t strbuff;
    char *result;

    if(strbuffer_init(&strbuff))
        return NULL;

    if(json_dump_callback(json, dump_to_strbuffer, (void *)&strbuff, flags))
        result = NULL;
    else
        result = jsonp_strdup(strbuffer_value(&strbuff));

    strbuffer_close(&strbuff);
    return result;
}

int json_dumpf(const json_t *json, FILE *output, size_t flags)
{
    return json_dump_callback(json, dump_to_file, (void *)output, flags);
}

int json_dump_file(const json_t *json, const char *path, size_t flags)
{
    int result;

    FILE *output = fopen(path, "w");
    if(!output)
        return -1;

    result = json_dumpf(json, output, flags);

    fclose(output);
    return result;
}

int json_dump_callback(const json_t *json, json_dump_callback_t callback, void *data, size_t flags)
{
    if(!(flags & JSON_ENCODE_ANY)) {
        if(!json_is_array(json) && !json_is_object(json))
           return -1;
    }

    return do_dump(NULL, json, flags, 0, callback, data);
}
