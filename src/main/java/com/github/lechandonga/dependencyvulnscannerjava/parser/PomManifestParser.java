package com.github.lechandonga.dependencyvulnscannerjava.parser;

import com.github.lechandonga.dependencyvulnscannerjava.model.Dependency;
import com.github.lechandonga.dependencyvulnscannerjava.model.Issue;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;

/**
 * Maven pom.xml 清单解析：
 * 读取 {@code <dependencies>}（含 dependencyManagement）中的直接依赖；
 * {@code ${project.version}} / {@code ${revision}} 等属性按 pom 属性及 GAV 解析；
 * 无法解析的属性、缺失字段、缺失版本都会作为条目级问题拒绝。
 */
public class PomManifestParser implements ManifestParser {

    @Override
    public boolean supports(String filename, String formatHint) {
        return "pom".equals(formatHint) || "xml".equals(formatHint)
                || (filename != null && filename.toLowerCase(Locale.ROOT).endsWith(".xml"));
    }

    @Override
    public ParseOutcome<Dependency> parse(String content, String sourceName) {
        if (content == null || content.isBlank()) {
            return ParseOutcome.fatal(new Issue(IssueKinds.FILE_FORMAT_ERROR, sourceName, -1, "pom 内容为空"));
        }
        Document doc;
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setNamespaceAware(false);
            doc = factory.newDocumentBuilder().parse(
                    new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            return ParseOutcome.fatal(new Issue(IssueKinds.FILE_FORMAT_ERROR, sourceName, -1,
                    "XML/pom 整体解析失败: " + e.getMessage()));
        }
        Element root = doc.getDocumentElement();
        if (root == null) {
            return ParseOutcome.fatal(new Issue(IssueKinds.FILE_FORMAT_ERROR, sourceName, -1, "缺少 XML 根节点"));
        }
        Properties props = collectProperties(root);
        String projectVersion = childText(root, "version");
        if (projectVersion != null) {
            props.putIfAbsent("project.version", projectVersion);
            props.putIfAbsent("pom.version", projectVersion);
        }
        String parentVersion = parentVersion(root);
        if (parentVersion != null) {
            props.putIfAbsent("project.parent.version", parentVersion);
        }

        List<Dependency> items = new ArrayList<>();
        List<Issue> issues = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        int index = 0;
        NodeList allDeps = doc.getElementsByTagName("dependency");
        for (int i = 0; i < allDeps.getLength(); i++) {
            Node node = allDeps.item(i);
            if (node.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element dep = (Element) node;
            String scope = childText(dep, "scope");
            if ("test".equalsIgnoreCase(scope) || "provided".equalsIgnoreCase(scope)) {
                continue;
            }
            String group = childText(dep, "groupId");
            String artifact = childText(dep, "artifactId");
            String version = childText(dep, "version");
            if (isBlank(group) || isBlank(artifact)) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                        "依赖缺少 groupId/artifactId"));
                index++;
                continue;
            }
            if (isBlank(version)) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                        group + ":" + artifact + " 缺少 version（pom 未声明直接版本）"));
                index++;
                continue;
            }
            String resolved = resolvePlaceholders(version, props);
            if (resolved.indexOf('$') >= 0 || resolved.indexOf('{') >= 0) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                        group + ":" + artifact + " 的版本含无法解析的属性: " + version));
                index++;
                continue;
            }
            try {
                com.github.lechandonga.dependencyvulnscannerjava.version.Version.parse(resolved);
            } catch (IllegalArgumentException e) {
                issues.add(new Issue(IssueKinds.ENTRY_FIELD_ERROR, sourceName, index,
                        group + ":" + artifact + " 的版本号无法识别: " + resolved));
                index++;
                continue;
            }
            String key = group.trim() + ":" + artifact.trim() + "@" + resolved.trim();
            if (seen.add(key)) {
                items.add(new Dependency("maven", group.trim(), artifact.trim(), resolved.trim(), sourceName));
            }
            index++;
        }
        return new ParseOutcome<>(items, issues, false);
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private String parentVersion(Element root) {
        NodeList parents = root.getElementsByTagName("parent");
        for (int i = 0; i < parents.getLength(); i++) {
            if (parents.item(i).getNodeType() == Node.ELEMENT_NODE
                    && parents.item(i).getParentNode() == root) {
                return childText((Element) parents.item(i), "version");
            }
        }
        return null;
    }

    private Properties collectProperties(Element root) {
        Properties props = new Properties();
        NodeList propsNodes = root.getElementsByTagName("properties");
        for (int i = 0; i < propsNodes.getLength(); i++) {
            if (propsNodes.item(i).getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element properties = (Element) propsNodes.item(i);
            NodeList children = properties.getChildNodes();
            for (int j = 0; j < children.getLength(); j++) {
                if (children.item(j).getNodeType() == Node.ELEMENT_NODE) {
                    props.setProperty(children.item(j).getNodeName(), children.item(j).getTextContent().trim());
                }
            }
        }
        return props;
    }

    private String resolvePlaceholders(String value, Properties props) {
        String result = value.trim();
        for (int guard = 0; guard < 10; guard++) {
            int start = result.indexOf("${");
            if (start < 0) {
                return result;
            }
            int end = result.indexOf('}', start);
            if (end < 0) {
                return result;
            }
            String key = result.substring(start + 2, end);
            String replacement = props.getProperty(key);
            if (replacement == null) {
                return result;
            }
            result = result.substring(0, start) + replacement + result.substring(end + 1);
        }
        return result;
    }

    private String childText(Element parent, String tag) {
        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node n = nodes.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE && n.getNodeName().equals(tag)) {
                return n.getTextContent().trim();
            }
        }
        return null;
    }
}
