package com.github.lechandonga.dependencyvulnscannerjava.web;

import com.github.lechandonga.dependencyvulnscannerjava.service.LibraryLoadException;
import com.github.lechandonga.dependencyvulnscannerjava.service.LibrarySnapshot;
import com.github.lechandonga.dependencyvulnscannerjava.service.VulnerabilityLibraryService;
import com.github.lechandonga.dependencyvulnscannerjava.web.dto.ErrorResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** 漏洞库状态查询与手动重载（只读本地目录，重载失败时保留旧快照）。 */
@RestController
@RequestMapping("/api/library")
public class LibraryController {

    private final VulnerabilityLibraryService libraryService;

    public LibraryController(VulnerabilityLibraryService libraryService) {
        this.libraryService = libraryService;
    }

    @GetMapping
    public Map<String, Object> status() {
        LibrarySnapshot snapshot = libraryService.current();
        return Map.of("fingerprint", snapshot.fingerprint(),
                "loadedAt", snapshot.loadedAt(),
                "ruleCount", snapshot.rules().size());
    }

    @PostMapping("/reload")
    public Map<String, Object> reload() {
        LibrarySnapshot snapshot = libraryService.reload();
        return Map.of("fingerprint", snapshot.fingerprint(),
                "loadedAt", snapshot.loadedAt(),
                "ruleCount", snapshot.rules().size());
    }

    @ExceptionHandler(LibraryLoadException.class)
    public ResponseEntity<ErrorResponse> handleLibrary(LibraryLoadException e) {
        return ResponseEntity.status(409).body(new ErrorResponse(
                "LIBRARY_ERROR", "LIBRARY_ERROR", e.getMessage(), e.issues()));
    }
}
