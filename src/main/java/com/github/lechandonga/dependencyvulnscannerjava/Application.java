package com.github.lechandonga.dependencyvulnscannerjava;

import com.github.lechandonga.dependencyvulnscannerjava.config.ScannerProperties;
import com.github.lechandonga.dependencyvulnscannerjava.service.VulnerabilityLibraryService;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(ScannerProperties.class)
public class Application {

    public static void main(String[] args) {
        var context = SpringApplication.run(Application.class, args);
        context.getBean(VulnerabilityLibraryService.class).init();
    }
}
