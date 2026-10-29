package com.krestfield.ezsign.client;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * KJson
 *
 * A minimal JSON writer and reader for the REST API requests and responses, so the client has no dependencies.
 * Objects are read as maps, arrays as lists, numbers as Long or Double
 *
 * Copyright (C) 2026 Krestfield Ltd - All Rights Reserved
 */
class KJson
{
    private KJson()
    {
    }

    /**
     * Thrown when text is not valid JSON
     */
    static class KJsonException extends Exception
    {
        KJsonException(String message)
        {
            super(message);
        }
    }

    static String write(Object value)
    {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object value)
    {
        if (value == null)
            sb.append("null");
        else if (value instanceof String)
            writeString(sb, (String) value);
        else if (value instanceof Boolean || value instanceof Number)
            sb.append(value.toString());
        else if (value instanceof Map)
        {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet())
            {
                if (!first)
                    sb.append(',');
                first = false;
                writeString(sb, String.valueOf(entry.getKey()));
                sb.append(':');
                write(sb, entry.getValue());
            }
            sb.append('}');
        }
        else if (value instanceof Iterable)
        {
            sb.append('[');
            boolean first = true;
            for (Object item : (Iterable<?>) value)
            {
                if (!first)
                    sb.append(',');
                first = false;
                write(sb, item);
            }
            sb.append(']');
        }
        else
            writeString(sb, value.toString());
    }

    private static void writeString(StringBuilder sb, String s)
    {
        sb.append('"');
        for (int i = 0; i < s.length(); i++)
        {
            char c = s.charAt(i);
            switch (c)
            {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20)
                        sb.append(String.format("\\u%04x", (int) c));
                    else
                        sb.append(c);
            }
        }
        sb.append('"');
    }

    /**
     * Parses a JSON object
     */
    @SuppressWarnings("unchecked")
    static Map<String, Object> parseObject(String text) throws KJsonException
    {
        Parser parser = new Parser(text);
        parser.skipSpace();
        Object value = parser.value();
        parser.skipSpace();
        if (parser.m_pos != text.length())
            throw new KJsonException("Unexpected content after the JSON at position " + parser.m_pos);
        if (!(value instanceof Map))
            throw new KJsonException("The JSON is not an object");
        return (Map<String, Object>) value;
    }

    private static class Parser
    {
        final String m_text;
        int m_pos = 0;

        Parser(String text)
        {
            m_text = text;
        }

        void skipSpace()
        {
            while (m_pos < m_text.length() && Character.isWhitespace(m_text.charAt(m_pos)))
                m_pos++;
        }

        char peek() throws KJsonException
        {
            if (m_pos >= m_text.length())
                throw new KJsonException("Unexpected end of the JSON");
            return m_text.charAt(m_pos);
        }

        void expect(char c) throws KJsonException
        {
            if (peek() != c)
                throw new KJsonException("Expected '" + c + "' at position " + m_pos);
            m_pos++;
        }

        Object value() throws KJsonException
        {
            char c = peek();
            if (c == '{')
                return object();
            if (c == '[')
                return array();
            if (c == '"')
                return string();
            if (m_text.startsWith("true", m_pos))
            {
                m_pos += 4;
                return Boolean.TRUE;
            }
            if (m_text.startsWith("false", m_pos))
            {
                m_pos += 5;
                return Boolean.FALSE;
            }
            if (m_text.startsWith("null", m_pos))
            {
                m_pos += 4;
                return null;
            }
            return number();
        }

        Map<String, Object> object() throws KJsonException
        {
            Map<String, Object> map = new LinkedHashMap<String, Object>();
            expect('{');
            skipSpace();
            if (peek() == '}')
            {
                m_pos++;
                return map;
            }
            while (true)
            {
                skipSpace();
                String key = string();
                skipSpace();
                expect(':');
                skipSpace();
                map.put(key, value());
                skipSpace();
                if (peek() == ',')
                {
                    m_pos++;
                    continue;
                }
                expect('}');
                return map;
            }
        }

        List<Object> array() throws KJsonException
        {
            List<Object> list = new ArrayList<Object>();
            expect('[');
            skipSpace();
            if (peek() == ']')
            {
                m_pos++;
                return list;
            }
            while (true)
            {
                skipSpace();
                list.add(value());
                skipSpace();
                if (peek() == ',')
                {
                    m_pos++;
                    continue;
                }
                expect(']');
                return list;
            }
        }

        String string() throws KJsonException
        {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true)
            {
                char c = peek();
                m_pos++;
                if (c == '"')
                    return sb.toString();
                if (c != '\\')
                {
                    sb.append(c);
                    continue;
                }
                char e = peek();
                m_pos++;
                switch (e)
                {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u':
                        if (m_pos + 4 > m_text.length())
                            throw new KJsonException("Invalid \\u escape at position " + m_pos);
                        try
                        {
                            sb.append((char) Integer.parseInt(m_text.substring(m_pos, m_pos + 4), 16));
                        }
                        catch (NumberFormatException ex)
                        {
                            throw new KJsonException("Invalid \\u escape at position " + m_pos);
                        }
                        m_pos += 4;
                        break;
                    default:
                        throw new KJsonException("Invalid escape at position " + m_pos);
                }
            }
        }

        Object number() throws KJsonException
        {
            int start = m_pos;
            while (m_pos < m_text.length() && "+-0123456789.eE".indexOf(m_text.charAt(m_pos)) >= 0)
                m_pos++;
            String n = m_text.substring(start, m_pos);
            if (n.isEmpty())
                throw new KJsonException("Unexpected character '" + peek() + "' at position " + start);
            try
            {
                if (n.indexOf('.') >= 0 || n.indexOf('e') >= 0 || n.indexOf('E') >= 0)
                    return Double.valueOf(n);
                return Long.valueOf(n);
            }
            catch (NumberFormatException e)
            {
                throw new KJsonException("Invalid number '" + n + "' at position " + start);
            }
        }
    }
}
/********************************************* END OF FILE *****************************************************
 ***************************************************************************************************************/
