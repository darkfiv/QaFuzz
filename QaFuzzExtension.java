package burp;
import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.scanner.Scanner;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;

import burp.QaFuzzMainPanel;

import javax.swing.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.net.URL;
import java.net.MalformedURLException;

import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import static burp.api.montoya.core.Annotations.annotations;
import static burp.api.montoya.core.Marker.marker;

import javax.swing.JMenuItem;
import java.util.List;
import java.util.ArrayList;
import java.awt.Component;
import java.awt.Frame;
import java.awt.MenuBar;
import java.awt.Container;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import javax.swing.AbstractButton;
import javax.swing.text.JTextComponent;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.nio.charset.StandardCharsets;

public class QaFuzzExtension implements BurpExtension, QaFuzzMainPanel.TableActionListener, ContextMenuItemsProvider {

    // Custom class to hold vulnerability details including original and modified requests/responses
    static class VulnerabilityEntry {
        HttpRequest originalRequest;
        HttpResponse originalResponse;
        HttpRequest modifiedRequest;
        HttpResponse receivedResponse;

        VulnerabilityEntry(HttpRequest originalRequest, HttpResponse originalResponse, HttpRequest modifiedRequest, HttpResponse receivedResponse) {
            this.originalRequest = originalRequest;
            this.originalResponse = originalResponse;
            this.modifiedRequest = modifiedRequest;
            this.receivedResponse = receivedResponse;
        }
    }

    // 扩展名称常量
    private static final String EXTENSION_NAME = "QaFuzz";
    private static final String EXTENSION_VERSION = "1.0";

    // 请求处理相关的常量
    private static final String REQUEST_HANDLER_KEYWORDS = "scan,send,test,check,analyze";
    private static final String REQUEST_EDITOR_KEYWORDS = "Editor,TextArea,TextField";
    private static final int DEFAULT_THREAD_POOL_SIZE = 10;
    private static final int DEFAULT_TIMEOUT_SECONDS = 5;

    private MontoyaApi api;
    private Logging logging;
    private QaFuzzMainPanel mainPanel;
    // Thread pool for sending requests asynchronously
    private ExecutorService requestExecutor;

    // Set to store hostname + second-level directory combinations that have already found vulnerabilities
    private Set<String> processedVulnerableResources = new HashSet<>();

    private Properties config;
    private static final String CONFIG_FILE = "config.properties";

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        // 从配置或环境中获取扩展名称
        String extensionName = getExtensionName();
        api.extension().setName(extensionName);
        logging.logToOutput(extensionName + " 插件已成功加载！");

        mainPanel = new QaFuzzMainPanel();
        mainPanel.setLogging(this.logging);

        // 创建 HTTP 消息编辑器
        HttpRequestEditor originalRequestEditor = api.userInterface().createHttpRequestEditor();
        HttpResponseEditor originalResponseEditor = api.userInterface().createHttpResponseEditor();
        HttpRequestEditor vulnerableRequestEditor = api.userInterface().createHttpRequestEditor();
        HttpResponseEditor vulnerableResponseEditor = api.userInterface().createHttpResponseEditor();

        // 设置编辑器到主面板
        mainPanel.setRequestResponseEditors(
            originalRequestEditor,
            originalResponseEditor,
            vulnerableRequestEditor,
            vulnerableResponseEditor
        );

        api.userInterface().registerSuiteTab(extensionName, mainPanel);
        mainPanel.setTableActionListener(this);
        
        // Register context menu items provider
        api.userInterface().registerContextMenuItemsProvider(this);

        // Initialize the thread pool with configurable size
        requestExecutor = initializeThreadPool();

        // Register extension unloading handler to shutdown the thread pool
        api.extension().registerUnloadingHandler(() -> {
            logging.logToOutput("正在关闭请求执行器线程池...");
            handleRequestTimeout(requestExecutor);
            logging.logToOutput("请求执行器线程池已关闭。");
        });

        // Initialize configuration
        initializeConfig();
    }

    // 获取扩展名称
    private String getExtensionName() {
        // 优先从配置文件获取
        String configName = loadConfigurationValue("extensionName");
        if (configName != null && !configName.isEmpty()) {
            return configName;
        }
        // 如果配置文件中没有，使用默认值
        return EXTENSION_NAME;
    }

    // 获取线程池大小
    private int getThreadPoolSize() {
        String configSize = loadConfigurationValue("threadPoolSize");
        if (configSize != null) {
            try {
                return Integer.parseInt(configSize);
            } catch (NumberFormatException e) {
                logging.logToError("配置的线程池大小无效: " + configSize);
            }
        }
        return DEFAULT_THREAD_POOL_SIZE;
    }

    // 初始化配置
    private void initializeConfig() {
        config = new Properties();
        try {
            // 首先尝试从工作目录加载
            File configFile = new File(CONFIG_FILE);
            if (configFile.exists()) {
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    config.load(fis);
                    logging.logToOutput("成功从工作目录加载配置文件");
                    return;
                }
            }

            // 如果工作目录没有配置文件，尝试从类路径加载
            try (InputStream is = getClass().getClassLoader().getResourceAsStream(CONFIG_FILE)) {
                if (is != null) {
                    config.load(is);
                    logging.logToOutput("成功从类路径加载配置文件");
                    return;
                }
            }

            // 如果都没有找到，创建默认配置文件
            createDefaultConfig(configFile);
            logging.logToOutput("已创建默认配置文件");

        } catch (IOException e) {
            logging.logToError("加载配置文件失败: " + e.getMessage());
            // 使用默认值
            setDefaultConfig();
        }
    }

    // 创建默认配置文件
    private void createDefaultConfig(File configFile) throws IOException {
        Properties defaultConfig = new Properties();
        defaultConfig.setProperty("extensionName", EXTENSION_NAME);
        defaultConfig.setProperty("extensionVersion", EXTENSION_VERSION);
        defaultConfig.setProperty("threadPoolSize", String.valueOf(DEFAULT_THREAD_POOL_SIZE));
        defaultConfig.setProperty("timeoutSeconds", String.valueOf(DEFAULT_TIMEOUT_SECONDS));
        defaultConfig.setProperty("requestHandlerKeywords", REQUEST_HANDLER_KEYWORDS);
        defaultConfig.setProperty("requestEditorKeywords", REQUEST_EDITOR_KEYWORDS);
        defaultConfig.setProperty("maxUrlLength", "30");
        defaultConfig.setProperty("maxPathPreviewLength", "15");
        defaultConfig.setProperty("logLevel", "INFO");
        defaultConfig.setProperty("enableDebugLogging", "false");

        try (FileOutputStream fos = new FileOutputStream(configFile)) {
            defaultConfig.store(fos, "QaFuzz Extension Configuration");
        }
        config = defaultConfig;
    }

    // 设置默认配置
    private void setDefaultConfig() {
        config = new Properties();
        config.setProperty("extensionName", EXTENSION_NAME);
        config.setProperty("extensionVersion", EXTENSION_VERSION);
        config.setProperty("threadPoolSize", String.valueOf(DEFAULT_THREAD_POOL_SIZE));
        config.setProperty("timeoutSeconds", String.valueOf(DEFAULT_TIMEOUT_SECONDS));
        config.setProperty("requestHandlerKeywords", REQUEST_HANDLER_KEYWORDS);
        config.setProperty("requestEditorKeywords", REQUEST_EDITOR_KEYWORDS);
        config.setProperty("maxUrlLength", "30");
        config.setProperty("maxPathPreviewLength", "15");
        config.setProperty("logLevel", "INFO");
        config.setProperty("enableDebugLogging", "false");
    }

    // 从配置文件加载配置值
    private String loadConfigurationValue(String key) {
        if (config == null) {
            initializeConfig();
        }
        return config.getProperty(key);
    }

    // 更新配置值
    public void updateConfigurationValue(String key, String value) {
        if (config == null) {
            initializeConfig();
        }
        config.setProperty(key, value);
        // 保存更新后的配置
        try {
            File configFile = new File(CONFIG_FILE);
            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                config.store(fos, "QaFuzz Extension Configuration");
                logging.logToOutput("配置已更新: " + key + " = " + value);
            }
        } catch (IOException e) {
            logging.logToError("保存配置失败: " + e.getMessage());
        }
    }

    // 获取所有配置
    public Properties getConfiguration() {
        if (config == null) {
            initializeConfig();
        }
        return new Properties(config); // 返回配置的副本
    }

    @Override
    public void sendRequestToRepeater(HttpRequest request) {
        logging.logToOutput("将特定请求发送到 Repeater: " + request.url());

        // 生成标签名称
        String tabCaption = generateRepeaterTabCaption(request);
        api.repeater().sendToRepeater(request, tabCaption);
    }

    // 生成 Repeater 标签页标题
    private String generateRepeaterTabCaption(HttpRequest request) {
        StringBuilder caption = new StringBuilder();

        // 添加扩展名称前缀
        caption.append(getExtensionName()).append("-");

        // 提取 URL 的关键部分
        String url = request.url();
        String path = extractPathFromUrl(url);

        // 如果路径太长，进行智能截断
        if (path.length() > 30) {
            // 保留开头和结尾的重要部分
            caption.append(path.substring(0, 15))
                  .append("...")
                  .append(path.substring(path.length() - 10));
        } else {
            caption.append(path);
        }

        return caption.toString();
    }

    // 从 URL 中提取路径
    private String extractPathFromUrl(String url) {
        try {
            URL urlObj = new URL(url);
            String path = urlObj.getPath();
            return path.isEmpty() ? "/" : path;
        } catch (MalformedURLException e) {
            return url;
        }
    }

    @Override
    public void sendRequestToIntruder(HttpRequest request) {
        logging.logToOutput("将特定请求发送到 Intruder: " + request.url());
        api.intruder().sendToIntruder(request);
    }

    @Override
    public void sendRequestToScanner(HttpRequest request) {
        logging.logToOutput("将特定请求发送到 Scanner: " + request.url());
        try {
            // 创建扫描配置
            AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
            // 启动扫描
            Audit audit = api.scanner().startAudit(auditConfig);
            // 添加请求到扫描范围
            audit.addRequest(request);
            logging.logToOutput("请求已添加到扫描队列");
        } catch (Exception e) {
            logging.logToError("无法将请求发送到扫描器: " + e.getMessage());
        }
    }

    @Override
    public void sendRequestToDecoder(HttpRequest request) {
        logging.logToOutput("将特定请求发送到 Decoder: " + request.url());
        // 发送请求到 Decoder
        api.decoder().sendToDecoder(ByteArray.byteArray(request.toString().getBytes()));
    }

    @Override
    public void sendRequestToComparer(HttpRequest request) {
        logging.logToOutput("将特定请求发送到 Comparer: " + request.url());
        // 发送请求到 Comparer
        api.comparer().sendToComparer(ByteArray.byteArray(request.toString().getBytes()));
    }

    @Override
    public void sendRequestToExtension(HttpRequest request, String extensionName) {
        logging.logToOutput("将特定请求发送到扩展 " + extensionName + ": " + request.url());

        // 检查扩展是否是当前扩展
        if (extensionName.equals("QaFuzz")) {
            logging.logToOutput("不能发送请求到当前扩展自身");
            return;
        }

        try {
            // 创建一个带注释的请求
            HttpRequestResponse requestResponse = HttpRequestResponse.httpRequestResponse(
                request,
                null,
                annotations().withNotes("Sent from QaFuzz")
            );

            // 将请求添加到站点地图
            api.siteMap().add(requestResponse);

            // 获取主窗口
            Frame mainFrame = api.userInterface().swingUtils().suiteFrame();

            // 查找目标扩展的标签页
            Component extensionTab = findExtensionComponent(mainFrame, extensionName);
            if (extensionTab != null) {
                // 尝试查找扩展中的请求处理组件
                Component requestHandler = findRequestHandler(extensionTab);
                if (requestHandler != null) {
                    // 如果找到了请求处理组件，触发它的动作
                    triggerRequestHandler(requestHandler, requestResponse);
                    logging.logToOutput("成功触发扩展 " + extensionName + " 的请求处理");
                } else {
                    // 如果没有找到专门的处理组件，尝试通用的处理方式
                    handleRequestGeneric(extensionTab, requestResponse);
                }

                // 切换到扩展标签页
                switchToExtensionTab(extensionName);
                logging.logToOutput("已切换到扩展 " + extensionName + " 的标签页");
            } else {
                logging.logToError("未找到扩展 " + extensionName + " 的界面组件");
            }
        } catch (Exception e) {
            logging.logToError("发送请求到扩展 " + extensionName + " 时出错: " + e.getMessage());
        }
    }

    // 查找扩展的主要组件
    private Component findExtensionComponent(Component parent, String extensionName) {
        if (parent == null) return null;

        // 检查当前组件是否属于目标扩展
        if (isExtensionComponent(parent, extensionName)) {
            return parent;
        }

        // 递归搜索子组件
        if (parent instanceof Container) {
            Container container = (Container) parent;
            for (Component child : container.getComponents()) {
                Component found = findExtensionComponent(child, extensionName);
                if (found != null) {
                    return found;
                }
            }
        }

        return null;
    }

    // 检查组件是否属于特定扩展
    private boolean isExtensionComponent(Component component, String extensionName) {
        // 检查组件名称
        String componentName = component.getName();
        if (componentName != null && componentName.contains(extensionName)) {
            return true;
        }

        // 检查组件类名
        String className = component.getClass().getName();
        return className != null && (
            className.contains(extensionName.toLowerCase()) ||
            className.contains(extensionName.replace(" ", ""))
        );
    }

    // 查找请求处理组件
    private Component findRequestHandler(Component extensionComponent) {
        if (extensionComponent == null) return null;

        // 查找可能的请求处理组件（按钮、菜单项等）
        if (isRequestHandler(extensionComponent)) {
            return extensionComponent;
        }

        // 递归搜索子组件
        if (extensionComponent instanceof Container) {
            Container container = (Container) extensionComponent;
            for (Component child : container.getComponents()) {
                Component handler = findRequestHandler(child);
                if (handler != null) {
                    return handler;
                }
            }
        }

        return null;
    }

    // 检查组件是否是请求处理组件
    private boolean isRequestHandler(Component component) {
        // 检查组件名称和类型
        String name = component.getName();
        if (name != null) {
            String nameLower = name.toLowerCase();
            // 从配置中获取关键字列表
            String[] keywords = getRequestHandlerKeywords();
            for (String keyword : keywords) {
                if (nameLower.contains(keyword.toLowerCase())) {
                    return true;
                }
            }
        }

        // 检查是否是按钮或菜单项
        if (component instanceof AbstractButton || component instanceof JMenuItem) {
            String text = (component instanceof AbstractButton) ?
                         ((AbstractButton) component).getText() :
                         ((JMenuItem) component).getText();
            if (text != null) {
                String textLower = text.toLowerCase();
                String[] keywords = getRequestHandlerKeywords();
                for (String keyword : keywords) {
                    if (textLower.contains(keyword.toLowerCase())) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    // 获取请求处理组件的关键字列表
    private String[] getRequestHandlerKeywords() {
        String configKeywords = loadConfigurationValue("requestHandlerKeywords");
        if (configKeywords != null && !configKeywords.isEmpty()) {
            return configKeywords.split(",");
        }
        return REQUEST_HANDLER_KEYWORDS.split(",");
    }

    // 检查组件是否是请求编辑器
    private boolean isRequestEditor(Component component) {
        if (component instanceof JTextComponent) {
            return true;
        }
        String className = component.getClass().getName();
        if (className != null) {
            String[] keywords = getRequestEditorKeywords();
            for (String keyword : keywords) {
                if (className.contains(keyword)) {
                    return true;
                }
            }
        }
        return false;
    }

    // 获取请求编辑器的关键字列表
    private String[] getRequestEditorKeywords() {
        String configKeywords = loadConfigurationValue("requestEditorKeywords");
        if (configKeywords != null && !configKeywords.isEmpty()) {
            return configKeywords.split(",");
        }
        return REQUEST_EDITOR_KEYWORDS.split(",");
    }

    // 触发请求处理组件
    private void triggerRequestHandler(Component handler, HttpRequestResponse requestResponse) {
        if (handler instanceof AbstractButton) {
            // 如果是按钮，模拟点击
            AbstractButton button = (AbstractButton) handler;
            button.doClick();
        } else if (handler instanceof JMenuItem) {
            // 如果是菜单项，触发动作
            JMenuItem menuItem = (JMenuItem) handler;
            for (ActionListener listener : menuItem.getActionListeners()) {
                listener.actionPerformed(new ActionEvent(menuItem, ActionEvent.ACTION_PERFORMED, ""));
            }
        }
    }

    // 通用请求处理方法
    private void handleRequestGeneric(Component extensionComponent, HttpRequestResponse requestResponse) {
        // 1. 尝试查找文本区域或编辑器组件
        Component editor = findRequestEditor(extensionComponent);
        if (editor != null) {
            // 如果找到编辑器，设置请求内容
            setRequestToEditor(editor, requestResponse);
        }

        // 2. 尝试启动扫描（如果扩展支持）
        try {
            AuditConfiguration auditConfig = AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
            Audit audit = api.scanner().startAudit(auditConfig);
            audit.addRequest(requestResponse.request());
            logging.logToOutput("请求已添加到扫描队列");
        } catch (Exception e) {
            logging.logToError("无法将请求添加到扫描队列: " + e.getMessage());
        }
    }

    // 查找请求编辑器组件
    private Component findRequestEditor(Component parent) {
        if (parent == null) return null;

        // 检查是否是编辑器组件
        if (isRequestEditor(parent)) {
            return parent;
        }

        // 递归搜索子组件
        if (parent instanceof Container) {
            Container container = (Container) parent;
            for (Component child : container.getComponents()) {
                Component editor = findRequestEditor(child);
                if (editor != null) {
                    return editor;
                }
            }
        }

        return null;
    }

    // 设置请求到编辑器
    private void setRequestToEditor(Component editor, HttpRequestResponse requestResponse) {
        if (editor instanceof JTextComponent) {
            JTextComponent textComponent = (JTextComponent) editor;
            textComponent.setText(requestResponse.request().toString());
        }
    }

    private void switchToExtensionTab(String extensionName) {
        try {
            Frame mainFrame = api.userInterface().swingUtils().suiteFrame();
            JTabbedPane extensionTab = findExtensionTab(mainFrame, extensionName);
            if (extensionTab != null) {
                int index = findTabIndex(extensionTab, extensionName);
                if (index != -1) {
                    extensionTab.setSelectedIndex(index);
                }
            }
        } catch (Exception e) {
            logging.logToError("切换到扩展标签页时出错: " + e.getMessage());
        }
    }

    // 获取已加载的扩展列表
    private List<String> getLoadedExtensions() {
        List<String> extensions = new ArrayList<>();
        try {
            // 获取 Burp 的主窗口
            Frame mainFrame = api.userInterface().swingUtils().suiteFrame();

            // 遍历主窗口中的所有组件
            findExtensionTabs(mainFrame, extensions);

            logging.logToOutput("动态获取到 " + extensions.size() + " 个扩展");

            // 打印找到的扩展名称，用于调试
            for (String ext : extensions) {
                logging.logToOutput("找到扩展: " + ext);
            }
        } catch (Exception e) {
            logging.logToError("获取已加载扩展列表时出错: " + e.getMessage());
            e.printStackTrace(logging.error());
        }
        return extensions;
    }

    // 递归查找扩展标签页
    private void findExtensionTabs(Component component, List<String> extensions) {
        if (component == null) return;

        // 检查是否是主标签页面板
        if (component instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) component;

            // 检查是否是扩展面板
            if ("Extensions".equals(tabbedPane.getName()) || hasExtensionsTab(tabbedPane)) {
                logging.logToOutput("找到扩展面板");

                // 获取扩展面板
                Component extensionsTab = findExtensionsTab(tabbedPane);
                if (extensionsTab instanceof JTabbedPane) {
                    JTabbedPane extensionsTabbedPane = (JTabbedPane) extensionsTab;
                    // 查找 "Installed" 标签
                    for (int i = 0; i < extensionsTabbedPane.getTabCount(); i++) {
                        String title = extensionsTabbedPane.getTitleAt(i);
                        logging.logToOutput("检查标签: " + title);
                        if ("Installed".equals(title)) {
                            Component installedPanel = extensionsTabbedPane.getComponentAt(i);
                            if (installedPanel instanceof Container) {
                                // 在已安装扩展面板中查找扩展列表
                                findInstalledExtensions((Container) installedPanel, extensions);
                            }
                            break;
                        }
                    }
                }
                return; // 找到扩展面板后就不需要继续搜索
            }
        }

        // 如果是容器，递归查找其子组件
        if (component instanceof Container) {
            Container container = (Container) component;
            for (Component child : container.getComponents()) {
                findExtensionTabs(child, extensions);
            }
        }
    }

    // 检查是否包含扩展标签
    private boolean hasExtensionsTab(JTabbedPane tabbedPane) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if ("Extensions".equals(tabbedPane.getTitleAt(i))) {
                return true;
            }
        }
        return false;
    }

    // 查找扩展面板
    private Component findExtensionsTab(JTabbedPane tabbedPane) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            String title = tabbedPane.getTitleAt(i);
            logging.logToOutput("检查标签页: " + title);
            if ("Extensions".equals(title)) {
                return tabbedPane.getComponentAt(i);
            }
        }
        return null;
    }

    // 在已安装扩展面板中查找实际的扩展
    private void findInstalledExtensions(Container container, List<String> extensions) {
        logging.logToOutput("开始搜索已安装扩展面板中的扩展...");

        for (Component comp : container.getComponents()) {
            String componentClass = comp.getClass().getName();
            logging.logToOutput("检查组件类型: " + componentClass);

            if (comp instanceof JTable) {
                JTable extensionTable = (JTable) comp;
                javax.swing.table.TableModel model = extensionTable.getModel();

                logging.logToOutput("找到扩展表格:");
                logging.logToOutput("- 行数: " + model.getRowCount());
                logging.logToOutput("- 列数: " + model.getColumnCount());

                // 打印表格结构
                StringBuilder tableStructure = new StringBuilder("表格结构:\n");
                for (int col = 0; col < model.getColumnCount(); col++) {
                    tableStructure.append(String.format("列 %d: %s\n", col, model.getColumnName(col)));
                }
                logging.logToOutput(tableStructure.toString());

                // 打印表格内容
                StringBuilder tableContent = new StringBuilder("表格内容:\n");
                for (int row = 0; row < Math.min(model.getRowCount(), 10); row++) {
                    tableContent.append(String.format("行 %d:", row));
                    for (int col = 0; col < model.getColumnCount(); col++) {
                        Object value = model.getValueAt(row, col);
                        tableContent.append(String.format(" [%s]", value));
                    }
                    tableContent.append("\n");
                }
                logging.logToOutput(tableContent.toString());

                // 尝试识别扩展名称列
                int nameColumn = findExtensionNameColumn(model);
                if (nameColumn != -1) {
                    logging.logToOutput("找到扩展名称列: " + nameColumn);
                    processExtensionTable(model, nameColumn, extensions);
                } else {
                    logging.logToOutput("警告：未找到扩展名称列");
                }

                return;
            }

            if (comp instanceof Container) {
                findInstalledExtensions((Container) comp, extensions);
            }
        }
    }

    // 查找扩展名称列
    private int findExtensionNameColumn(javax.swing.table.TableModel model) {
        // 可能的扩展名称列标题
        String[] possibleNameHeaders = {"Name", "Extension Name", "Extension", "名称", "扩展名称"};

        for (int col = 0; col < model.getColumnCount(); col++) {
            String columnName = model.getColumnName(col);
            if (columnName != null) {
                // 检查是否匹配任何可能的列标题
                for (String header : possibleNameHeaders) {
                    if (columnName.equalsIgnoreCase(header)) {
                        return col;
                    }
                }
            }
        }

        // 如果没有找到明确的名称列，尝试查找第一个非空列
        for (int col = 0; col < model.getColumnCount(); col++) {
            boolean hasValidData = false;
            for (int row = 0; row < Math.min(model.getRowCount(), 3); row++) {
                Object value = model.getValueAt(row, col);
                if (value != null && !value.toString().trim().isEmpty() &&
                    !isCommonHeader(value.toString().trim())) {
                    hasValidData = true;
                    break;
                }
            }
            if (hasValidData) {
                return col;
            }
        }

        return -1;
    }

    // 处理扩展表格
    private void processExtensionTable(javax.swing.table.TableModel model, int nameColumn, List<String> extensions) {
        Set<String> processedNames = new HashSet<>();

        for (int row = 0; row < model.getRowCount(); row++) {
            Object value = model.getValueAt(row, nameColumn);
            if (value != null) {
                String extensionName = value.toString().trim();

                // 检查是否是有效的扩展名
                if (isValidExtensionName(extensionName) && !processedNames.contains(extensionName)) {
                    logging.logToOutput(String.format("处理扩展: [%s] (行 %d)", extensionName, row));
                    extensions.add(extensionName);
                    processedNames.add(extensionName);
                }
            }
        }
    }

    // 检查是否是有效的扩展名
    private boolean isValidExtensionName(String name) {
        if (name == null || name.trim().isEmpty() || name.equals("QaFuzz")) {
            return false;
        }

        // 检查是否是常见的列标题或系统文本
        if (isCommonHeader(name)) {
            return false;
        }

        // 检查是否包含无效字符或模式
        if (name.contains("...") || name.contains("===") ||
            name.matches(".*[<>\\[\\]\\{\\}\\|\\\\]+.*")) {
            return false;
        }

        return true;
    }

    // 检查是否是常见的列标题或系统文本
    private boolean isCommonHeader(String text) {
        String[] commonHeaders = {
            "Name", "Type", "Loaded", "Extension type", "Filename",
            "Extension state listeners", "Context menu providers", "Suite tabs",
            "HTTP listeners", "Proxy listeners", "Scanner insertionpoints",
            "Intruder payloads", "true", "false", "null", "undefined",
            "Extension Name", "Status", "Version", "Author"
        };

        String normalizedText = text.trim().toLowerCase();
        for (String header : commonHeaders) {
            if (normalizedText.equalsIgnoreCase(header)) {
                return true;
            }
        }

        // 检查是否是常见的系统文本模式
        return normalizedText.matches(".*(type|name|loaded|status|version|author|listener|provider|tab).*");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        
        logging.logToOutput("Context menu event received. Invocation type: " + event.invocationType());

        boolean containsHttpMessage = event.invocationType() != null &&
            (event.invocationType().containsHttpMessage() || event.invocationType().containsHttpRequestResponses());
        logging.logToOutput("Contains HTTP message: " + containsHttpMessage);

        List<HttpRequestResponse> selectedItems = new ArrayList<>();

        event.messageEditorRequestResponse().ifPresent(editor -> {
            HttpRequestResponse reqRes = editor.requestResponse();
            if (reqRes != null && reqRes.request() != null) {
                selectedItems.add(reqRes);
            }
        });

        selectedItems.addAll(event.selectedRequestResponses());

        logging.logToOutput("Total selected items count: " + selectedItems.size());

        if (containsHttpMessage || !selectedItems.isEmpty()) {
        JMenuItem qaFuzzItem = new JMenuItem("Send to QaFuzz");
        qaFuzzItem.addActionListener(e -> {
                if (!selectedItems.isEmpty()) {
                    logging.logToOutput("QaFuzz 右键菜单项被点击，选中了 " + selectedItems.size() + " 个 HTTP 请求/响应项。");
                for (HttpRequestResponse item : selectedItems) {
                        if (item != null) {
                            logging.logToOutput("Processing item - Request null: " + (item.request() == null) + ", Response null: " + (item.response() == null));
                            if (item.request() != null && item.response() != null) {
                        processHttpRequestResponse(item.request(), item.response());
                    } else {
                                logging.logToOutput("Skipping item - Request or response is null");
                            }
                        } else {
                            logging.logToOutput("Skipping null item");
                        }
                }
            } else {
                logging.logToOutput("没有选中任何 HTTP 请求/响应项。");
            }
        });
        
        menuItems.add(qaFuzzItem);
        }

        return menuItems;
    }

    private boolean isListEmpty(String[] list) {
        if (list == null || list.length == 0) {
            return true;
        }
        // 检查是否所有元素都是空字符串
        for (String item : list) {
            if (item != null && !item.trim().isEmpty()) {
                return false;
            }
        }
        return true;
    }

    // Calculate similarity between two responses using Jaccard similarity
    private double calculateResponseSimilarity(HttpResponse response1, HttpResponse response2) {
        if (response1 == null || response2 == null) {
            return 0.0;
        }

        // Get response bodies as strings
        String body1 = new String(response1.body().getBytes(), StandardCharsets.UTF_8);
        String body2 = new String(response2.body().getBytes(), StandardCharsets.UTF_8);

        // Split into words and create sets
        Set<String> words1 = new HashSet<>(Arrays.asList(body1.split("\\s+")));
        Set<String> words2 = new HashSet<>(Arrays.asList(body2.split("\\s+")));

        // Calculate Jaccard similarity
        Set<String> intersection = new HashSet<>(words1);
        intersection.retainAll(words2);
        
        Set<String> union = new HashSet<>(words1);
        union.addAll(words2);
        
        if (union.isEmpty()) {
            return 0.0;
        }
        
        return (double) intersection.size() / union.size();
    }

    private void processHttpRequestResponse(HttpRequest originalRequest, HttpResponse originalResponse) {
        // Submit a task to the thread pool to process this history item
        requestExecutor.submit(() -> {
            try {
                if (originalRequest == null || originalResponse == null) {
                    logging.logToOutput("Skipping selected item without request or response.");
                    return null;
                }

                String urlAsync = originalRequest.url();
                String methodAsync = originalRequest.method();
                int responseBodySizeAsync = (originalResponse.body() != null) ? originalResponse.body().length() : 0;

                 String hostnameAsync = "N/A";
                 HttpService originalService = originalRequest.httpService();
                 if (originalService != null) {
                     hostnameAsync = originalService.host();
                 }

                 if ("N/A".equals(hostnameAsync)) {
                     logging.logToOutput("Skipping selected item with no hostname.");
                    return null;
                 }

                 // Re-apply blacklist and whitelist checks
                 String[] blacklist = mainPanel.getHostnameBlacklist();
                 String[] whitelist = mainPanel.getHostnameWhitelist();

                // 检查黑名单是否为空（包括只包含空字符串的情况）
                if (!isListEmpty(blacklist)) {
                     for (String blEntry : blacklist) {
                        if (blEntry != null && !blEntry.trim().isEmpty() && hostnameAsync.equalsIgnoreCase(blEntry.trim())) {
                             logging.logToOutput("Skipping blacklisted hostname from right-click: " + hostnameAsync);
                            return null; // Skip if blacklisted
                        }
                    }
                }

                // 检查白名单是否为空（包括只包含空字符串的情况）
                if (!isListEmpty(whitelist)) {
                     boolean inWhitelist = false;
                     for (String wlEntry : whitelist) {
                        if (wlEntry != null && !wlEntry.trim().isEmpty() && hostnameAsync.equalsIgnoreCase(wlEntry.trim())) {
                              inWhitelist = true;
                              break;
                          }
                     }
                     if (!inWhitelist) {
                          logging.logToOutput("Skipping hostname not in whitelist from right-click: " + hostnameAsync);
                        return null; // Skip if not in whitelist
                    }
                } else {
                    logging.logToOutput("Whitelist is empty, allowing hostname: " + hostnameAsync);
                 }

                 String[] keywords = mainPanel.getKeywords();
                if (keywords == null || keywords.length == 0) {
                    logging.logToOutput("No keywords configured, skipping request.");
                    return null;
                }

                 // Extract hostname and second-level directory for de-duplication
                 String secondLevelDirectory = extractSecondLevelDirectory(urlAsync);

                 // Create a unique resource key for de-duplication
                 String resourceKey = hostnameAsync + (secondLevelDirectory != null ? secondLevelDirectory : "");

                 // Check if a vulnerability has already been found for this resource (using the existing set)
                 if (processedVulnerableResources.contains(resourceKey)) {
                     logging.logToOutput("Skipping already processed vulnerable resource from right-click: " + resourceKey);
                    return null; // Skip if already processed
                 }

                     for (String keyword : keywords) {
                    if (Thread.currentThread().isInterrupted()) {
                        return null;
                    }

                         String trimmedKeyword = keyword.trim();
                    if (trimmedKeyword.isEmpty()) {
                        continue;
                    }

                         String modifiedHostname = insertKeywordIntoHostname(hostnameAsync, trimmedKeyword);

                    if (originalService == null) {
                              logging.logToError("Could not get original HttpService for " + urlAsync + " in async task during right-click processing.");
                              continue;
                         }

                         // Determine the protocol based on whether the service is secure
                         String protocol = originalService.secure() ? "https" : "http";

                         // Construct the modified URL using the protocol, modified hostname, and original path/query
                         String modifiedUrl = protocol + "://" + modifiedHostname + originalRequest.path();
                         String originalQuery = originalRequest.query();
                         if (originalQuery != null && !originalQuery.isEmpty()) {
                             modifiedUrl += "?" + originalQuery;
                         }
                         logging.logToOutput("Async task (right-click): Testing modified URL: " + modifiedUrl);

                         // Create a new HttpService with the modified hostname and original port/security
                         HttpService modifiedService = HttpService.httpService(modifiedHostname, originalService.port(), originalService.secure());

                         // Create a new HttpRequest by updating the service and host header of the original request
                         HttpRequest modifiedRequest = originalRequest.withService(modifiedService).withUpdatedHeader("Host", modifiedHostname);

                    HttpResponse receivedResponse = null;
                    try {
                        HttpRequestResponse requestResponse = api.http().sendRequest(modifiedRequest);
                        receivedResponse = requestResponse.response();
                        if (receivedResponse == null) {
                            logging.logToOutput("Received null response for modified URL: " + modifiedUrl);
                            continue;
                        }
                    } catch (Exception e) {
                        logging.logToError("Error sending modified request: " + e.getMessage());
                        continue;
                    }

                    // 检查状态码是否一致
                    boolean statusCodeMatch = originalResponse.statusCode() == receivedResponse.statusCode();
                    
                    // 计算响应相似度
                    double similarity = calculateResponseSimilarity(originalResponse, receivedResponse);
                    logging.logToOutput(String.format("Response comparison for %s: Status Code Match: %b, Original: %d, Modified: %d, Similarity: %.2f",
                        modifiedUrl,
                        statusCodeMatch,
                        originalResponse.statusCode(),
                        receivedResponse.statusCode(),
                        similarity
                    ));

                    // 判断是否存在漏洞：状态码小于500且不等于403
                    if (receivedResponse.statusCode() != 403) {
                        logging.logToOutput("Async task (right-click): Potential vulnerability found for keyword '"+ trimmedKeyword +"' on URL: "+ urlAsync +
                                         ", Original Status Code: "+ originalResponse.statusCode() +
                                         ", Modified Status Code: "+ receivedResponse.statusCode());

                        final String finalUrlAsync = urlAsync;
                        final String finalMethodAsync = methodAsync;
                        final String finalModifiedUrl = modifiedUrl;
                        final int finalResponseBodySizeAsync = responseBodySizeAsync;
                        final HttpRequest finalModifiedRequest = modifiedRequest;
                        final HttpResponse finalReceivedResponse = receivedResponse;

                        SwingUtilities.invokeLater(() -> {
                            try {
                                String externalIp = "N/A";
                                if (originalService != null) {
                                    externalIp = originalService.ipAddress();
                                }

                                Object[] rowData = {
                                    null,
                                    finalMethodAsync,
                                    finalUrlAsync,
                                    finalModifiedUrl,
                                    finalResponseBodySizeAsync,
                                    externalIp
                                };

                                VulnerabilityEntry vulnerabilityEntry = new VulnerabilityEntry(
                                    originalRequest,
                                    originalResponse,
                                    finalModifiedRequest,
                                    finalReceivedResponse
                                );

                                mainPanel.addVulnRowWithDeduplication(rowData, vulnerabilityEntry);
                                logging.logToOutput("Successfully added vulnerability to table for URL: " + finalUrlAsync);
                            } catch (Exception e) {
                                logging.logToError("Error adding vulnerability to table: " + e.getMessage());
                                e.printStackTrace(logging.error());
                            }
                        });

                        processedVulnerableResources.add(resourceKey);
                        logging.logToOutput("Async task (right-click): Added vulnerable resource to set: " + resourceKey);
                    } else {
                        logging.logToOutput("Async task (right-click): No vulnerability found for keyword '"+ trimmedKeyword +"' on URL: "+ urlAsync +
                                         ": Status Code: "+ originalResponse.statusCode() +"->"+ receivedResponse.statusCode() +
                                         ", Similarity: " + similarity);
                    }
                }
                return null;
            } catch (Exception ex) {
                 logging.logToError("Async task error processing right-click item: " + ex.getMessage());
                 ex.printStackTrace(logging.error());
                return null;
             }
        });
    }

    private String insertKeywordIntoHostname(String hostname, String keyword) {
        if (hostname == null || hostname.isEmpty()) {
            return hostname;
        }
        if (hostname.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return keyword + "." + hostname;
        }

        int firstDotIndex = hostname.indexOf('.');
        if (firstDotIndex != -1) {
            return hostname.substring(0, firstDotIndex) + "." + keyword + hostname.substring(firstDotIndex);
        } else {
            return keyword + "." + hostname;
        }
    }

    // Helper method to extract the second-level directory from a URL path
    private String extractSecondLevelDirectory(String urlString) {
        try {
            URL url = new URL(urlString);
            String path = url.getPath();
            if (path == null || path.isEmpty() || path.equals("/")) {
                return "/"; // Root path
            }
            // Remove leading slash and split by slash
            String[] segments = path.substring(1).split("/");
            if (segments.length > 1) {
                return "/" + segments[0] + "/" + segments[1];
            } else if (segments.length == 1) {
                 return "/" + segments[0];
            }
            return "/"; // Default to root if no segments
        } catch (MalformedURLException e) {
             logging.logToError("Malformed URL when extracting second-level directory: " + urlString + ", error: " + e.getMessage());
            return null; // Return null in case of error
        }
    }

    // 查找特定扩展的标签页
    private JTabbedPane findExtensionTab(Component component, String extensionName) {
        if (component == null) return null;

        if (component instanceof JTabbedPane) {
            JTabbedPane tabbedPane = (JTabbedPane) component;
            String name = tabbedPane.getName();

            // 只在扩展面板中查找
            if ("burp.extensions".equals(name)) {
                for (int i = 0; i < tabbedPane.getTabCount(); i++) {
                    if (tabbedPane.getTitleAt(i).equals(extensionName)) {
                        return tabbedPane;
                    }
                }
            }
        }

        if (component instanceof Container) {
            Container container = (Container) component;
            for (Component child : container.getComponents()) {
                JTabbedPane result = findExtensionTab(child, extensionName);
                if (result != null) {
                    return result;
                }
            }
        }

        return null;
    }

    // 查找标签页索引
    private int findTabIndex(JTabbedPane tabbedPane, String title) {
        for (int i = 0; i < tabbedPane.getTabCount(); i++) {
            if (tabbedPane.getTitleAt(i).equals(title)) {
                return i;
            }
        }
        return -1;
    }

    // 处理请求超时
    private void handleRequestTimeout(ExecutorService executor) {
        int timeoutSeconds = getTimeoutSeconds();
        try {
            if (!executor.awaitTermination(timeoutSeconds, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                if (!executor.awaitTermination(timeoutSeconds, TimeUnit.SECONDS)) {
                    logging.logToError("请求执行器线程池未能完全关闭！");
                }
            }
        } catch (InterruptedException e) {
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    // 获取超时时间
    private int getTimeoutSeconds() {
        String configTimeout = loadConfigurationValue("timeoutSeconds");
        if (configTimeout != null) {
            try {
                return Integer.parseInt(configTimeout);
            } catch (NumberFormatException e) {
                logging.logToError("配置的超时时间无效: " + configTimeout);
            }
        }
        return DEFAULT_TIMEOUT_SECONDS;
    }

    // 更新 initialize 方法中的线程池初始化
    private ExecutorService initializeThreadPool() {
        int threadPoolSize = getThreadPoolSize();
        return Executors.newFixedThreadPool(threadPoolSize);
    }
} 