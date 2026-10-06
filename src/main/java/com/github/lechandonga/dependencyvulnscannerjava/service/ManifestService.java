package com.github.lechandonga.dependencyvulnscannerjava.service;

import com.github.lechandonga.dependencyvulnscannerjava.config.ScannerProperties;
import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;
import com.github.lechandonga.dependencyvulnscannerjava.parser.JsonManifestParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.ManifestParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.ParseOutcome;
import com.github.lechandonga.dependencyvulnscannerjava.parser.PomManifestParser;
import com.github.lechandonga.dependencyvulnscannerjava.parser.TextManifestParser;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** 清单获取与解析：支持 content 直传或从受限本地目录按文件名读取。 */
@Service
public class ManifestService {

    private final ScannerProperties properties;
    private final List<ManifestParser> parsers = List.of(
            new JsonManifestParser(),
            new PomManifestParser(),
            new TextManifestParser());

    public ManifestService(ScannerProperties properties) {
        this.properties = properties;
    }

    public record LoadedManifest(String content, String sourceName) {
    }

    public LoadedManifest load(String filename, String content) {
        if (content != null && !content.isEmpty()) {
            String name = filename == null || filename.isBlank() ? "inline-manifest" : filename;
            return new LoadedManifest(content, name);
        }
        if (filename == null || filename.isBlank()) {
            throw new ManifestReadException("必须提供 content 或 filename", List.of());
        }
        Path base = properties.getManifestDir().toAbsolutePath().normalize();
        Path resolved = base.resolve(filename).normalize();
        if (!resolved.startsWith(base)) {
            throw new ManifestReadException("filename 越出清单目录: " + filename, List.of());
        }
        if (!Files.isRegularFile(resolved)) {
            throw new ManifestReadException("清单文件不存在: " + resolved, List.of());
        }
        try {
            return new LoadedManifest(Files.readString(resolved, StandardCharsets.UTF_8),
                    resolved.getFileName().toString());
        } catch (IOException e) {
            throw new ManifestReadException("清单文件读取失败: " + e.getMessage(), List.of());
        }
    }

    public List<Dependency> parse(LoadedManifest manifest, String formatHint) {
        String format;
        try {
            format = ManifestParser.formatOf(manifest.sourceName(), formatHint);
        } catch (IllegalArgumentException e) {
            throw new ManifestReadException(e.getMessage(), List.of());
        }
        ManifestParser parser = parsers.stream()
                .filter(p -> p.supports(manifest.sourceName(), format))
                .findFirst()
                .orElseThrow(() -> new ManifestReadException("不支持的清单格式: " + format, List.of()));
        ParseOutcome<Dependency> outcome = parser.parse(manifest.content(), manifest.sourceName());
        if (outcome.hasIssues() && properties.isRejectOnIssue()) {
            throw new ManifestReadException("清单存在 " + outcome.issues().size() + " 个问题，已拒绝",
                    outcome.issues());
        }
        return outcome.items();
    }
}
