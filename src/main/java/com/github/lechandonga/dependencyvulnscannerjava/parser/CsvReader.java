package com.github.lechandonga.dependencyvulnscannerjava.parser;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 最小 RFC 4180 风格 CSV 读取器：支持引号包裹、双引号转义、表头映射。
 * 表头重复、列数与表头不一致都会被显式拒绝。
 */
public final class CsvReader {

    private CsvReader() {
    }

    public static List<Map<String, String>> readWithHeader(String content, String fileName) {
        List<List<String>> rows = parse(content, fileName);
        if (rows.isEmpty()) {
            throw new ParseException(true, fileName, "CSV 文件为空，缺少表头");
        }
        List<String> header = rows.get(0);
        List<String> normalizedHeader = new ArrayList<>();
        for (String h : header) {
            String key = h.trim();
            if (key.isEmpty()) {
                throw new ParseException(true, fileName, "CSV 表头存在空列名");
            }
            if (normalizedHeader.contains(key)) {
                throw new ParseException(true, fileName, "CSV 表头存在重复列: " + key);
            }
            normalizedHeader.add(key);
        }
        List<Map<String, String>> result = new ArrayList<>();
        for (int r = 1; r < rows.size(); r++) {
            List<String> row = rows.get(r);
            if (row.size() == 1 && row.get(0).isEmpty()) {
                continue; // 允许末尾空行
            }
            if (row.size() != normalizedHeader.size()) {
                throw new ParseException(true, fileName + ":" + (r + 1),
                        "CSV 第 " + (r + 1) + " 行有 " + row.size() + " 列，与表头 " + normalizedHeader.size() + " 列不一致");
            }
            Map<String, String> record = new LinkedHashMap<>();
            for (int c = 0; c < normalizedHeader.size(); c++) {
                record.put(normalizedHeader.get(c), row.get(c).trim());
            }
            record.put("__row__", String.valueOf(r + 1));
            result.add(record);
        }
        return result;
    }

    static List<List<String>> parse(String content, String fileName) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;
        boolean fieldStarted = false;
        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    if (i + 1 < content.length() && content.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    field.append(c);
                }
                continue;
            }
            if (c == '"') {
                if (fieldStarted || field.length() > 0) {
                    throw new ParseException(true, fileName, "CSV 引号必须出现在字段开头，位置偏移 " + i);
                }
                inQuotes = true;
                fieldStarted = true;
            } else if (c == ',') {
                row.add(field.toString());
                field.setLength(0);
                fieldStarted = false;
            } else if (c == '\n') {
                row.add(field.toString());
                field.setLength(0);
                fieldStarted = false;
                rows.add(row);
                row = new ArrayList<>();
            } else if (c == '\r') {
                // 吞掉，兼容 CRLF
            } else {
                field.append(c);
            }
        }
        if (inQuotes) {
            throw new ParseException(true, fileName, "CSV 存在未闭合的引号");
        }
        if (field.length() > 0 || !row.isEmpty()) {
            row.add(field.toString());
            rows.add(row);
        }
        return rows;
    }
}
