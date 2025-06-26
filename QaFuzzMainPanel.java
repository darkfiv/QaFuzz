package burp;

// import burp.api.montoya.http.message.HttpRequestResponse; // 不再直接存储 HttpRequestResponse
// import burp.api.montoya.http.message.requests.HttpRequest; // 不再直接存储 HttpRequest
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.proxy.ProxyHttpRequestResponse; // 导入 ProxyHttpRequestResponse
import burp.api.montoya.http.HttpService; // 导入 HttpService 用于获取 IP
import burp.api.montoya.http.message.requests.HttpRequest; // 导入 HttpRequest for display
import burp.api.montoya.http.message.responses.HttpResponse; // 导入 HttpResponse for display
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList; // 导入 ArrayList
import java.util.List; // 导入 List
import java.util.regex.Pattern; // 导入 Pattern
import java.util.Arrays; // 导入 Arrays
import javax.swing.BoxLayout; // 导入 BoxLayout
import javax.swing.border.EmptyBorder; // 导入 EmptyBorder
import java.util.HashSet; // Import HashSet for the new set
import java.net.URL; // Import URL for extracting path
import java.net.URI; // Import URI for opening GitHub link
import java.net.MalformedURLException; // Import MalformedURLException
import javax.swing.table.TableRowSorter;
import javax.swing.table.TableColumnModel;
import java.util.HashMap;
import java.util.concurrent.locks.ReentrantLock;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import java.awt.Desktop; // Import Desktop for opening GitHub link

// Assuming VulnerabilityEntry is a public static inner class in QaFuzzExtension
import static burp.QaFuzzExtension.VulnerabilityEntry;

public class QaFuzzMainPanel extends JPanel {
    // 表格操作监听接口
    public interface TableActionListener {
        // Methods to send specific HttpRequest objects (original or modified)
        void sendRequestToRepeater(HttpRequest request);
        void sendRequestToIntruder(HttpRequest request);
        void sendRequestToScanner(HttpRequest request);
        void sendRequestToDecoder(HttpRequest request);
        void sendRequestToComparer(HttpRequest request);
        void sendRequestToExtension(HttpRequest request, String extensionName);
    }
    
    // 表格相关
    private JTable vulnTable;
    private DefaultTableModel tableModel;
    
    // 修改：使用 JTabbedPane 替换 JTextArea
    private JTabbedPane packetDisplayPane; // 数据包展示面板
    private JTextArea originalRequestArea; // 原始请求展示区
    private JTextArea originalResponseArea; // 原始响应展示区
    private JTextArea vulnerableRequestArea; // 漏洞请求展示区
    private JTextArea vulnerableResponseArea; // 漏洞响应展示区

    private JTextField keywordField;

    private JLabel statusLabel; // 状态标签

    // 修改：存储 ProxyHttpRequestResponse 对象列表
    private List<VulnerabilityEntry> historyItemList = new ArrayList<>(); // 列表类型改为 VulnerabilityEntry

    // Set to track unique hostname + second-level directory for display de-duplication
    private HashSet<String> displayedVulnerableResources = new HashSet<>();

    private TableActionListener tableActionListener;

    public void setTableActionListener(TableActionListener listener) {
        this.tableActionListener = listener;
    }
    
    // 配置面板相关组件
    private JPanel configPanel;
    private JButton saveConfigButton;
    // 新增：Hostname 黑白名单文本区域变量声明
    private JTextArea hostnameBlacklistArea;
    private JTextArea hostnameWhitelistArea;

    // 主界面的 JTabbedPane
    private JTabbedPane mainTabbedPane;

    private Logging logging;

    public void setLogging(Logging logging) {
        this.logging = logging;
    }

    // Configuration options
    private String[] keywords = new String[]{"qa", "t"};
    private String[] hostnameBlacklist = new String[]{};
    private String[] hostnameWhitelist = new String[]{};

    // Declare vulnEntries and vulnEntriesLock
    private HashMap<String, VulnerabilityEntry> vulnEntries;
    private ReentrantLock vulnEntriesLock;

    private JMenu extensionsMenu; // Add this field to the class

    // 数据包展示组件
    private JSplitPane requestResponsePane;
    private JTabbedPane detailsPane;
    private JSplitPane originalPane;
    private JSplitPane vulnerablePane;
    private HttpRequestEditor originalRequestEditor;
    private HttpResponseEditor originalResponseEditor;
    private HttpRequestEditor vulnerableRequestEditor;
    private HttpResponseEditor vulnerableResponseEditor;

    public QaFuzzMainPanel() {
        // Initialize the map and lock
        this.vulnEntries = new HashMap<>();
        this.vulnEntriesLock = new ReentrantLock();
        
        // Initialize keywords with default values
        keywordField = new JTextField("qa,t", 15);

        // Initialize text areas
        hostnameBlacklistArea = new JTextArea(4, 20);
        hostnameWhitelistArea = new JTextArea(4, 20);

        // Main panel will use BorderLayout
        setLayout(new BorderLayout());

        // Create a JSplitPane for left (results) and right (settings)
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplitPane.setResizeWeight(0.8); // Give more space to the results panel (80%)
        mainSplitPane.setContinuousLayout(true); // Enable continuous layout while dragging

        // --- Left Panel (Results Display: Table + Packet Details) ---
        JPanel resultDisplayPanel = new JPanel(new BorderLayout());
        resultDisplayPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // 1. 漏洞展示表格 (Table Panel)
        String[] columnNames = {"Seq #", "Method", "URL", "Modified URL", "Original Body Size", "IP Address"};
        tableModel = new DefaultTableModel(columnNames, 0);
        vulnTable = new JTable(tableModel);
        vulnTable.setFillsViewportHeight(true);
        vulnTable.setRowSorter(new TableRowSorter<>(tableModel));

        JScrollPane tableScroll = new JScrollPane(vulnTable);
        tableScroll.setBorder(new TitledBorder("漏洞信息展示"));
        resultDisplayPanel.add(tableScroll, BorderLayout.CENTER);

        // 2. 数据包展示区
        detailsPane = new JTabbedPane();
        detailsPane.setBorder(new TitledBorder("数据包详情"));

        originalPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        originalPane.setResizeWeight(0.5);

        vulnerablePane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        vulnerablePane.setResizeWeight(0.5);

        detailsPane.addTab("Original Request/Response", originalPane);
        detailsPane.addTab("Vulnerable Request/Response", vulnerablePane);

        // Use preferred size for details pane
        detailsPane.setPreferredSize(new Dimension(getWidth(), 250));
        resultDisplayPanel.add(detailsPane, BorderLayout.SOUTH);

        mainSplitPane.setLeftComponent(resultDisplayPanel);

        // --- Right Panel (Settings) ---
        JPanel settingsPanel = buildSettingsPanel();
        mainSplitPane.setRightComponent(settingsPanel);

        // Add the split pane to the main panel
        add(mainSplitPane, BorderLayout.CENTER);

        // --- Bottom Status Panel ---
        JPanel statusPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        statusPanel.setBorder(new EmptyBorder(5, 10, 5, 10));
        statusLabel = new JLabel("状态: 停止");
        statusPanel.add(statusLabel);
        add(statusPanel, BorderLayout.SOUTH);

        // Set up table selection listener and context menu
        vulnTable.getSelectionModel().addListSelectionListener(new VulnerabilitiesTableSelectionListener());
        setupContextMenu();

        // Add component listener to handle resize events
        addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                // Update divider location when the window is resized
                mainSplitPane.setDividerLocation(0.8);
                
                // Update details pane height
                int detailsHeight = (int)(getHeight() * 0.3); // 30% of total height
                detailsPane.setPreferredSize(new Dimension(getWidth(), detailsHeight));
                
                // Revalidate and repaint
                revalidate();
                repaint();
            }
        });
    }

    // 设置 HTTP 消息编辑器
    public void setRequestResponseEditors(
            HttpRequestEditor originalRequestEditor,
            HttpResponseEditor originalResponseEditor,
            HttpRequestEditor vulnerableRequestEditor,
            HttpResponseEditor vulnerableResponseEditor) {
        this.originalRequestEditor = originalRequestEditor;
        this.originalResponseEditor = originalResponseEditor;
        this.vulnerableRequestEditor = vulnerableRequestEditor;
        this.vulnerableResponseEditor = vulnerableResponseEditor;

        // 设置编辑器到分割面板
        originalPane.setLeftComponent(originalRequestEditor.uiComponent());
        originalPane.setRightComponent(originalResponseEditor.uiComponent());
        vulnerablePane.setLeftComponent(vulnerableRequestEditor.uiComponent());
        vulnerablePane.setRightComponent(vulnerableResponseEditor.uiComponent());
    }

    // 更新选中行的请求和响应显示
    private void updateRequestResponseEditors(int selectedRow) {
        if (selectedRow >= 0 && selectedRow < historyItemList.size()) {
            VulnerabilityEntry entry = historyItemList.get(selectedRow);
            
            // 更新原始数据包
            if (entry.originalRequest != null) {
                originalRequestEditor.setRequest(entry.originalRequest);
            }
            if (entry.originalResponse != null) {
                originalResponseEditor.setResponse(entry.originalResponse);
            }
            
            // 更新漏洞数据包
            if (entry.modifiedRequest != null) {
                vulnerableRequestEditor.setRequest(entry.modifiedRequest);
            }
            if (entry.receivedResponse != null) {
                vulnerableResponseEditor.setResponse(entry.receivedResponse);
            }
        }
    }

    // 设置右键菜单
    private void setupContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();
        
        // Send to submenu
        JMenu sendToMenu = new JMenu("Send to");
        
        // Repeater
        JMenuItem sendToRepeaterItem = new JMenuItem("Repeater");
        sendToRepeaterItem.addActionListener(e -> sendSelectedRequestToTool("repeater"));
        sendToMenu.add(sendToRepeaterItem);
        
        // Intruder
        JMenuItem sendToIntruderItem = new JMenuItem("Intruder");
        sendToIntruderItem.addActionListener(e -> sendSelectedRequestToTool("intruder"));
        sendToMenu.add(sendToIntruderItem);
        
        // Scanner
        JMenuItem sendToScannerItem = new JMenuItem("Scanner");
        sendToScannerItem.addActionListener(e -> sendSelectedRequestToTool("scanner"));
        sendToMenu.add(sendToScannerItem);
        
        // Decoder
        JMenuItem sendToDecoderItem = new JMenuItem("Decoder");
        sendToDecoderItem.addActionListener(e -> sendSelectedRequestToTool("decoder"));
        sendToMenu.add(sendToDecoderItem);
        
        // Comparer
        JMenuItem sendToComparerItem = new JMenuItem("Comparer");
        sendToComparerItem.addActionListener(e -> sendSelectedRequestToTool("comparer"));
        sendToMenu.add(sendToComparerItem);
        
        popupMenu.add(sendToMenu);
        popupMenu.addSeparator();
        
        // Delete and Clear options
        JMenuItem deleteRowItem = new JMenuItem("Delete Item");
        deleteRowItem.addActionListener(e -> deleteSelectedRow());
        JMenuItem clearTableItem = new JMenuItem("Clear All");
        clearTableItem.addActionListener(e -> clearTable());
        
        popupMenu.add(deleteRowItem);
        popupMenu.add(clearTableItem);

        vulnTable.setComponentPopupMenu(popupMenu);
    }

    // --- Right Panel (Settings) ---
    private JPanel buildSettingsPanel() {
        // Create main container panel with BorderLayout
        JPanel settingsPanel = new JPanel(new BorderLayout());
        settingsPanel.setBorder(new EmptyBorder(10, 10, 10, 10));

        // Create a container panel for both sections using BoxLayout
        JPanel containerPanel = new JPanel();
        containerPanel.setLayout(new BoxLayout(containerPanel, BoxLayout.Y_AXIS));
        containerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // Author Info Section with fixed preferred width
        JPanel authorPanel = new JPanel();
        authorPanel.setLayout(new BoxLayout(authorPanel, BoxLayout.Y_AXIS));
        authorPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "About"
        ));
        authorPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Set minimum and preferred width for author panel
        authorPanel.setMinimumSize(new Dimension(250, authorPanel.getMinimumSize().height));
        authorPanel.setPreferredSize(new Dimension(250, authorPanel.getPreferredSize().height));

        // Tool and Author Information
        JLabel titleLabel = new JLabel("Version: QaFuzz v1.0.0");
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 14));
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel authorLabel = new JLabel("Author: DarkFi5");
        authorLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel githubLabel = new JLabel("Github: https://github.com/darkfiv/QaFuzz");
        githubLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        githubLabel.setCursor(new Cursor(Cursor.HAND_CURSOR));
        githubLabel.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                try {
                    Desktop.getDesktop().browse(new URI("https://github.com/darkfiv/QaFuzz"));
                } catch (Exception ex) {
                    if (logging != null) {
                        logging.logToError("Error opening GitHub link: " + ex.getMessage());
                    }
                }
            }
        });

        // Add components to author panel with proper spacing
        authorPanel.add(Box.createVerticalStrut(10));
        authorPanel.add(titleLabel);
        authorPanel.add(Box.createVerticalStrut(10));
        authorPanel.add(authorLabel);
        authorPanel.add(Box.createVerticalStrut(10));
        authorPanel.add(githubLabel);
        authorPanel.add(Box.createVerticalStrut(10));

        // Configuration Section
        JPanel configPanel = new JPanel();
        configPanel.setLayout(new BoxLayout(configPanel, BoxLayout.Y_AXIS));
        configPanel.setBorder(BorderFactory.createTitledBorder(
            BorderFactory.createEtchedBorder(), "Configuration"
        ));
        configPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        // Set minimum and preferred width for config panel
        configPanel.setMinimumSize(new Dimension(250, configPanel.getMinimumSize().height));
        configPanel.setPreferredSize(new Dimension(250, configPanel.getPreferredSize().height));

        // Keywords section with proper sizing
        JPanel keywordPanel = new JPanel();
        keywordPanel.setLayout(new BoxLayout(keywordPanel, BoxLayout.Y_AXIS));
        keywordPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        JLabel keywordLabel = new JLabel("Keywords (comma-separated):");
        keywordLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        keywordField.setMaximumSize(new Dimension(Integer.MAX_VALUE, keywordField.getPreferredSize().height));
        keywordField.setAlignmentX(Component.LEFT_ALIGNMENT);

        keywordPanel.add(keywordLabel);
        keywordPanel.add(Box.createVerticalStrut(5));
        keywordPanel.add(keywordField);

        // Hostname Blacklist section
        JPanel blacklistPanel = new JPanel();
        blacklistPanel.setLayout(new BoxLayout(blacklistPanel, BoxLayout.Y_AXIS));
        blacklistPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel blacklistLabel = new JLabel("Hostname Blacklist:");
        blacklistLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        hostnameBlacklistArea.setLineWrap(true);
        hostnameBlacklistArea.setWrapStyleWord(true);
        JScrollPane blacklistScrollPane = new JScrollPane(hostnameBlacklistArea);
        blacklistScrollPane.setPreferredSize(new Dimension(0, 80));
        blacklistScrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
        blacklistScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);

        blacklistPanel.add(blacklistLabel);
        blacklistPanel.add(Box.createVerticalStrut(5));
        blacklistPanel.add(blacklistScrollPane);

        // Hostname Whitelist section
        JPanel whitelistPanel = new JPanel();
        whitelistPanel.setLayout(new BoxLayout(whitelistPanel, BoxLayout.Y_AXIS));
        whitelistPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel whitelistLabel = new JLabel("Hostname Whitelist:");
        whitelistLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        hostnameWhitelistArea.setLineWrap(true);
        hostnameWhitelistArea.setWrapStyleWord(true);
        JScrollPane whitelistScrollPane = new JScrollPane(hostnameWhitelistArea);
        whitelistScrollPane.setPreferredSize(new Dimension(0, 80));
        whitelistScrollPane.setMaximumSize(new Dimension(Integer.MAX_VALUE, 80));
        whitelistScrollPane.setAlignmentX(Component.LEFT_ALIGNMENT);

        whitelistPanel.add(whitelistLabel);
        whitelistPanel.add(Box.createVerticalStrut(5));
        whitelistPanel.add(whitelistScrollPane);

        // Apply Button with proper sizing
        JButton applyButton = new JButton("Apply Changes");
        applyButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        applyButton.setMaximumSize(new Dimension(Integer.MAX_VALUE, applyButton.getPreferredSize().height));
        applyButton.addActionListener(e -> applyConfigurationChanges());

        // Add components to config panel with proper spacing
        configPanel.add(Box.createVerticalStrut(10));
        configPanel.add(keywordPanel);
        configPanel.add(Box.createVerticalStrut(15));
        configPanel.add(blacklistPanel);
        configPanel.add(Box.createVerticalStrut(15));
        configPanel.add(whitelistPanel);
        configPanel.add(Box.createVerticalStrut(15));
        configPanel.add(applyButton);
        configPanel.add(Box.createVerticalStrut(10));

        // Add panels to container with proper spacing
        containerPanel.add(authorPanel);
        containerPanel.add(Box.createVerticalStrut(15));
        containerPanel.add(configPanel);
        containerPanel.add(Box.createVerticalStrut(10));

        // Create scroll pane for the container with proper settings
        JScrollPane scrollPane = new JScrollPane(containerPanel);
        scrollPane.setBorder(null);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        // Add scroll pane to settings panel
        settingsPanel.add(scrollPane, BorderLayout.CENTER);

        return settingsPanel;
    }

    private JPanel createConfigSection(String label, Component component) {
        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel titleLabel = new JLabel(label);
        titleLabel.setAlignmentX(Component.LEFT_ALIGNMENT);

        component.setMaximumSize(new Dimension(Integer.MAX_VALUE, component instanceof JScrollPane ? 80 : component.getPreferredSize().height));

        panel.add(titleLabel);
        panel.add(Box.createVerticalStrut(3));
        panel.add(component);

        return panel;
    }

    // Method to handle configuration changes
    private void applyConfigurationChanges() {
        if (logging != null) {
            logging.logToOutput("Applying configuration changes...");
        }

        // Get and trim the current values
        String[] newKeywords = Arrays.stream(keywordField.getText().split(","))
                                   .map(String::trim)
                                   .filter(s -> !s.isEmpty())
                                   .toArray(String[]::new);

        String[] newBlacklist = Arrays.stream(hostnameBlacklistArea.getText().split("\n"))
                                    .map(String::trim)
                                    .filter(s -> !s.isEmpty())
                                    .toArray(String[]::new);

        String[] newWhitelist = Arrays.stream(hostnameWhitelistArea.getText().split("\n"))
                                    .map(String::trim)
                                    .filter(s -> !s.isEmpty())
                                    .toArray(String[]::new);

        // Log the changes if logging is available
        if (logging != null) {
            logging.logToOutput("New keywords: " + String.join(", ", newKeywords));
            logging.logToOutput("New blacklist entries: " + String.join(", ", newBlacklist));
            logging.logToOutput("New whitelist entries: " + String.join(", ", newWhitelist));
        }

        // Clear the processed resources set to allow re-checking with new configuration
        displayedVulnerableResources.clear();

        // Update the configuration in memory
        keywords = newKeywords;
        hostnameBlacklist = newBlacklist;
        hostnameWhitelist = newWhitelist;

        // Show confirmation message
        if (logging != null) {
            logging.logToOutput("Configuration updated successfully!");
        }
    }

    private void addPacketAreaPopupMenu() {
        // 移除数据包展示区域的右键菜单，只在表格中显示
        originalRequestArea.setComponentPopupMenu(null);
        originalResponseArea.setComponentPopupMenu(null);
        vulnerableRequestArea.setComponentPopupMenu(null);
        vulnerableResponseArea.setComponentPopupMenu(null);
    }
    
    private void sendSelectedRequestToTool(String tool) {
        int selectedRow = vulnTable.getSelectedRow();
        if (selectedRow != -1 && selectedRow < historyItemList.size() && tableActionListener != null) {
            VulnerabilityEntry selectedEntry = historyItemList.get(selectedRow);
            HttpRequest requestToSend = selectedEntry.modifiedRequest; // 使用漏洞域名的请求
            
            if (requestToSend != null) {
                switch (tool.toLowerCase()) {
                    case "repeater":
                        tableActionListener.sendRequestToRepeater(requestToSend);
                        break;
                    case "intruder":
                        tableActionListener.sendRequestToIntruder(requestToSend);
                        break;
                    case "scanner":
                        tableActionListener.sendRequestToScanner(requestToSend);
                        break;
                    case "decoder":
                        tableActionListener.sendRequestToDecoder(requestToSend);
                        break;
                    case "comparer":
                        tableActionListener.sendRequestToComparer(requestToSend);
                        break;
                    default:
                        if (tool.startsWith("extension:")) {
                            String extensionName = tool.substring("extension:".length());
                            tableActionListener.sendRequestToExtension(requestToSend, extensionName);
                        } else {
                            if (logging != null) logging.logToOutput("未知的工具类型: " + tool);
                        }
                        break;
                }
            } else if (logging != null) {
                logging.logToError("Could not determine which request to send or request is null");
            }
        } else if (logging != null) {
            logging.logToOutput("右键菜单: 发送到 " + tool + " 未执行，选中行: " + selectedRow + 
                              ", historyItemList 大小: " + historyItemList.size() + 
                              ", tableActionListener 是否为 null: " + (tableActionListener == null));
        }
    }
    
    public void updateExtensionsMenu(JMenu extensionsMenu, List<String> extensions) {
        extensionsMenu.removeAll();
        for (String extension : extensions) {
            JMenuItem item = new JMenuItem(extension);
            item.addActionListener(e -> sendSelectedRequestToTool("extension:" + extension));
            extensionsMenu.add(item);
        }
        if (extensions.isEmpty()) {
            JMenuItem noExtensionsItem = new JMenuItem("No extensions available");
            noExtensionsItem.setEnabled(false);
            extensionsMenu.add(noExtensionsItem);
        }
    }
    
    private void copySelectedContent(String type) {
        JTextArea sourceArea = type.equals("request") ? 
            (vulnerableRequestArea.isFocusOwner() ? vulnerableRequestArea : originalRequestArea) :
            (vulnerableRequestArea.isFocusOwner() ? vulnerableRequestArea : originalRequestArea);
            
        String selectedText = sourceArea.getSelectedText();
        if (selectedText != null && !selectedText.isEmpty()) {
            StringSelection selection = new StringSelection(selectedText);
            Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, selection);
            if (logging != null) logging.logToOutput("已复制选中的" + (type.equals("request") ? "请求" : "响应") + "内容");
        } else {
            if (logging != null) logging.logToOutput("没有选中任何内容");
        }
    }

    // 修改：供后续功能调用的方法，接收 ProxyHttpRequestResponse，并更新表格列
    // rowData 数组需要包含：Method, 原始URL, 漏洞URL, Body Size, 外网IP (不包含序号，序号在此方法内部生成)
    public void addVulnRow(Object[] rowData, VulnerabilityEntry vulnerabilityEntry) {
        if (logging != null) {
            logging.logToOutput("Attempting to add row to vulnerability table with data: " + Arrays.toString(rowData));
        }
        SwingUtilities.invokeLater(() -> {
            // Get the current row count to use as the sequence number (starting from 1)
            int sequenceNumber = tableModel.getRowCount() + 1;
            rowData[0] = sequenceNumber; // Set the sequence number in the first column

            tableModel.addRow(rowData);
            historyItemList.add(vulnerabilityEntry);
        });
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
             // Log error if logging is available, but don't throw exception
             if (logging != null) {
                 logging.logToError("Malformed URL when extracting second-level directory for display de-duplication: " + urlString + ", error: " + e.getMessage());
             }
            return null; // Return null in case of error
        }
    }

    // Modified addVulnRow with de-duplication logic
    public void addVulnRowWithDeduplication(Object[] rowData, VulnerabilityEntry vulnerabilityEntry) {
         if (logging != null) {
             logging.logToOutput("Attempting to add row with de-duplication to vulnerability table with data: " + Arrays.toString(rowData));
         }

        // Extract hostname and second-level directory for de-duplication key from the new VulnerabilityEntry structure
        String hostname = "N/A";
        String secondLevelDirectory = null;
        if (vulnerabilityEntry != null && vulnerabilityEntry.originalRequest != null && vulnerabilityEntry.originalRequest.httpService() != null) {
            hostname = vulnerabilityEntry.originalRequest.httpService().host();
            secondLevelDirectory = extractSecondLevelDirectory(vulnerabilityEntry.originalRequest.url());
        }

        String resourceKey = hostname + (secondLevelDirectory != null ? secondLevelDirectory : "");

        // Check if this resource key has already been displayed
        if (displayedVulnerableResources.contains(resourceKey)) {
            if (logging != null) {
                logging.logToOutput("Skipping display of already displayed vulnerable resource: " + resourceKey);
            }
            return; // Skip adding if already displayed
        }

        // If not displayed, add to the set and proceed to add the row
        displayedVulnerableResources.add(resourceKey);
        if (logging != null) {
            logging.logToOutput("Adding new vulnerable resource to display: " + resourceKey);
        }

         // Check if response body size is less than 1, skip if true
         if (rowData.length > 4 && rowData[4] instanceof Integer && (Integer)rowData[4] < 1) {
             if (logging != null) {
                 logging.logToOutput("Skipping display of result with response body size < 1: " + rowData[4]);
             }
             return; // Skip adding if body size is less than 1
         }

         SwingUtilities.invokeLater(() -> {
             // Get the current row count to use as the sequence number (starting from 1)
             int sequenceNumber = tableModel.getRowCount() + 1;
             rowData[0] = sequenceNumber; // Set the sequence number in the first column

        tableModel.addRow(rowData);
             historyItemList.add(vulnerabilityEntry);
         });
    }

    public String[] getKeywords() {
        String text = keywordField.getText();
        if (text == null || text.trim().isEmpty()) {
            return new String[]{};
        }
        return text.split(",");
    }

    // 获取表格当前行数 (不变)
    public int getRowCount() {
        return tableModel.getRowCount();
    }

    // TODO: 实现保存配置文件的逻辑
    private void saveConfig() {
        // 获取黑白名单列表
        String[] blacklist = getHostnameBlacklist();
        String[] whitelist = getHostnameWhitelist();
        // TODO: 保存到文件或内存中
        System.out.println("保存 Hostname 黑名单: " + Arrays.toString(blacklist));
        System.out.println("保存 Hostname 白名单: " + Arrays.toString(whitelist));
    }

    // 获取 Hostname 黑名单列表
    public String[] getHostnameBlacklist() {
        String text = hostnameBlacklistArea.getText();
        if (text == null) {
            return new String[]{};
        }
        return text.split("\n");
    }

    // 获取 Hostname 白名单列表
    public String[] getHostnameWhitelist() {
        String text = hostnameWhitelistArea.getText();
        if (text == null) {
            return new String[]{};
        }
        return text.split("\n");
    }

    // Inner class to listen for row selection changes in the table
    private class VulnerabilitiesTableSelectionListener implements ListSelectionListener {
        @Override
        public void valueChanged(ListSelectionEvent e) {
            // Ensure the event is not a synthetic event from a table change
            if (!e.getValueIsAdjusting()) {
                int selectedRow = vulnTable.getSelectedRow();
                updateRequestResponseEditors(selectedRow);
            }
        }
    }

    private void deleteSelectedRow() {
        int selectedRow = vulnTable.getSelectedRow();
        if (selectedRow != -1) {
            tableModel.removeRow(selectedRow);
            historyItemList.remove(selectedRow);
            // Clear editors when row is deleted
            updateRequestResponseEditors(-1);
        }
    }

    private void clearTable() {
        tableModel.setRowCount(0);
        historyItemList.clear();
        // Clear editors when table is cleared
        updateRequestResponseEditors(-1);
    }

    public JMenu getExtensionsMenu() {
        return extensionsMenu;
    }
} 