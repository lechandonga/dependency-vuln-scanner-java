package com.github.lechandonga.dependencyvulnscannerjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 扫描服务配置项（前缀 scanner.*）。
 */
@ConfigurationProperties(prefix = "scanner")
public class ScannerProperties {

    /** 本地漏洞库目录，只读取目录内文件，不联网。 */
    private Path libraryDir = Paths.get("data", "vulnerability-db");

    /** 允许按文件名读取的本地清单根目录（content 直传不受此限制）。 */
    private Path manifestDir = Paths.get("data", "manifests");

    /** 清单/漏洞库出现解析问题时是否整体拒绝（默认 true，绝不静默跳过）。 */
    private boolean rejectOnIssue = true;

    /** 任务结果内存保留秒数，到期后查询返回 404。 */
    private long taskTtlSeconds = 3600;

    /** 内存任务表最大条目，超出淘汰最老任务。 */
    private int maxTasks = 10000;

    /** 是否对相同清单内容（同库指纹）的重复提交复用既有任务。 */
    private boolean dedupeSameContent = true;

    public Path getLibraryDir() {
        return libraryDir;
    }

    public void setLibraryDir(Path libraryDir) {
        this.libraryDir = libraryDir;
    }

    public Path getManifestDir() {
        return manifestDir;
    }

    public void setManifestDir(Path manifestDir) {
        this.manifestDir = manifestDir;
    }

    public boolean isRejectOnIssue() {
        return rejectOnIssue;
    }

    public void setRejectOnIssue(boolean rejectOnIssue) {
        this.rejectOnIssue = rejectOnIssue;
    }

    public long getTaskTtlSeconds() {
        return taskTtlSeconds;
    }

    public void setTaskTtlSeconds(long taskTtlSeconds) {
        this.taskTtlSeconds = taskTtlSeconds;
    }

    public int getMaxTasks() {
        return maxTasks;
    }

    public void setMaxTasks(int maxTasks) {
        this.maxTasks = maxTasks;
    }

    public boolean isDedupeSameContent() {
        return dedupeSameContent;
    }

    public void setDedupeSameContent(boolean dedupeSameContent) {
        this.dedupeSameContent = dedupeSameContent;
    }
}
