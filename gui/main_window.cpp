#include "main_window.hpp"

#include "wirescope/common.hpp"
#include "wirescope/decoder.hpp"
#include "tcp_stream_dialog.hpp"
#include "statistics_widget.hpp"

#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFontDatabase>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QStatusBar>
#include <QStyle>
#include <QTabWidget>
#include <QTableView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QAbstractItemView>
#include <QItemSelectionModel>
#include <QStringList>
#include <QTimer>
#include <QToolBar>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTextCursor>
#include <QPlainTextEdit>
#include <QKeySequence>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QWidget>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <variant>
#include <utility>

namespace {


QString qstr(const std::string& value) {
    return QString::fromStdString(value);
}

QTreeWidgetItem* add_detail(QTreeWidget* tree, const QString& label, const QString& value,
                            QTreeWidgetItem* parent = nullptr) {
    auto* item = parent == nullptr
        ? new QTreeWidgetItem(tree, QStringList{label, value})
        : new QTreeWidgetItem(parent, QStringList{label, value});
    return item;
}

QTableWidgetItem* cell(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}

QString time_text(std::uint64_t timestamp_us) {
    const auto milliseconds = static_cast<qint64>(timestamp_us / 1000U);
    const auto remainder = static_cast<unsigned int>(timestamp_us % 1000U);
    return QDateTime::fromMSecsSinceEpoch(milliseconds, Qt::UTC)
        .toString("yyyy-MM-dd HH:mm:ss.zzz") +
        QString("%1").arg(remainder, 3, 10, QLatin1Char('0'));
}


QString hex_dump(const std::vector<std::uint8_t>& bytes) {
    constexpr std::size_t bytes_per_line = 16U;
    constexpr char digits[] = "0123456789ABCDEF";
    QString output;
    output.reserve(static_cast<qsizetype>(bytes.size() * 4U));

    for (std::size_t offset = 0U; offset < bytes.size(); offset += bytes_per_line) {
        std::ostringstream line;
        line << std::uppercase << std::hex << std::setfill('0')
             << std::setw(8) << offset << "  ";
        QString ascii;
        for (std::size_t index = 0U; index < bytes_per_line; ++index) {
            const std::size_t position = offset + index;
            if (position < bytes.size()) {
                const std::uint8_t value = bytes[position];
                line << digits[(value >> 4U) & 0x0FU] << digits[value & 0x0FU] << ' ';
                ascii += (value >= 0x20U && value <= 0x7EU)
                    ? QChar(static_cast<ushort>(value)) : QLatin1Char('.');
            } else {
                line << "   ";
                ascii += QLatin1Char(' ');
            }
            if (index == 7U) line << ' ';
        }
        output += QString::fromStdString(line.str()) + " |" + ascii + "|\n";
    }
    return output;
}

QString join_strings(const std::vector<std::string>& values) {
    QStringList list;
    for (const auto& value : values) list.push_back(qstr(value));
    return list.join(", ");
}

void configure_table(QTableWidget* table, const QStringList& headers) {
    table->setColumnCount(static_cast<int>(headers.size()));
    table->setHorizontalHeaderLabels(headers);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->verticalHeader()->setVisible(false);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setAlternatingRowColors(true);
}

} // namespace

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent), engine_(), packet_model_(new PacketTableModel(engine_, this)) {
    setWindowTitle(QStringLiteral("WireScope — Network Analyzer"));
    resize(1440, 900);
    setMinimumSize(1050, 680);

    setStyleSheet(R"(
        QMainWindow, QWidget { background: #111827; color: #e5e7eb; }
        QToolBar { background: #172033; border: 0; spacing: 8px; padding: 8px; }
        QToolButton, QPushButton { background: #263449; color: #e5e7eb; border: 1px solid #34445d; border-radius: 6px; padding: 7px 12px; }
        QToolButton:hover, QPushButton:hover { background: #334761; }
        QToolButton:disabled, QPushButton:disabled { color: #64748b; background: #1b2535; }
        QLineEdit, QComboBox { background: #0b1220; border: 1px solid #34445d; border-radius: 5px; padding: 7px; selection-background-color: #2563eb; }
        QTableView, QTableWidget, QTreeWidget, QPlainTextEdit { background: #0b1220; alternate-background-color: #111c2d; border: 1px solid #263449; gridline-color: #263449; selection-background-color: #1d4ed8; selection-color: white; }
        QHeaderView::section { background: #1c2a3e; color: #9fb3cc; padding: 8px; border: 0; border-right: 1px solid #2b3b52; border-bottom: 1px solid #2b3b52; font-weight: 600; }
        QTabWidget::pane { border: 1px solid #263449; border-radius: 5px; }
        QTabBar::tab { background: #182438; color: #9fb3cc; padding: 9px 18px; border: 1px solid #263449; }
        QTabBar::tab:selected { background: #263b58; color: #ffffff; }
        QStatusBar { background: #172033; color: #9fb3cc; }
        QCheckBox { spacing: 6px; }
        QSplitter::handle { background: #263449; }
    )");

    open_action_ = new QAction(style()->standardIcon(QStyle::SP_DialogOpenButton), tr("Open PCAP"), this);
    open_action_->setShortcut(QKeySequence::Open);
    connect(open_action_, &QAction::triggered, this, [this] { openCapture(); });

    auto* refresh_action = new QAction(style()->standardIcon(QStyle::SP_BrowserReload), tr("Refresh interfaces"), this);
    connect(refresh_action, &QAction::triggered, this, [this] { refreshInterfaces(); });

    start_action_ = new QAction(style()->standardIcon(QStyle::SP_MediaPlay), tr("Start live"), this);
    connect(start_action_, &QAction::triggered, this, [this] { startLiveCapture(); });

    stop_action_ = new QAction(style()->standardIcon(QStyle::SP_MediaStop), tr("Stop"), this);
    connect(stop_action_, &QAction::triggered, this, [this] { stopCapture(); });

    auto* file_menu = menuBar()->addMenu(tr("&File"));
    file_menu->addAction(open_action_);
    file_menu->addSeparator();
    file_menu->addAction(tr("E&xit"), this, &QWidget::close, QKeySequence::Quit);

    auto* toolbar = addToolBar(tr("Capture"));
    toolbar->setMovable(false);
    toolbar->addAction(open_action_);
    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(tr("Interface"), toolbar));
    interface_combo_ = new QComboBox(toolbar);
    interface_combo_->setMinimumWidth(170);
    toolbar->addWidget(interface_combo_);
    toolbar->addAction(refresh_action);
    promiscuous_check_ = new QCheckBox(tr("Promiscuous"), toolbar);
    toolbar->addWidget(promiscuous_check_);
    toolbar->addSeparator();
    toolbar->addAction(start_action_);
    toolbar->addAction(stop_action_);
    toolbar->addSeparator();
    toolbar->addWidget(new QLabel(tr("Display filter"), toolbar));
    filter_edit_ = new QLineEdit(toolbar);
    filter_edit_->setPlaceholderText(tr("tcp, udp, port 443, host 192.168.1.1…"));
    filter_edit_->setMinimumWidth(270);
    toolbar->addWidget(filter_edit_);
    auto* apply_button = new QPushButton(tr("Apply"), toolbar);
    toolbar->addWidget(apply_button);
    connect(apply_button, &QPushButton::clicked, this, [this] { applyDisplayFilter(); });
    connect(filter_edit_, &QLineEdit::returnPressed, this, [this] { applyDisplayFilter(); });

    tabs_ = new QTabWidget(this);
    setCentralWidget(tabs_);

    auto* packet_page = new QWidget(tabs_);
    auto* packet_layout = new QVBoxLayout(packet_page);
    packet_layout->setContentsMargins(8, 8, 8, 8);

    auto* summary_row = new QHBoxLayout();
    packet_count_label_ = new QLabel(tr("0 packets"), packet_page);
    byte_count_label_ = new QLabel(tr("0 bytes"), packet_page);
    connection_count_label_ = new QLabel(tr("0 TCP connections"), packet_page);
    dns_count_label_ = new QLabel(tr("0 DNS messages"), packet_page);
    for (QLabel* label : {packet_count_label_, byte_count_label_, connection_count_label_, dns_count_label_}) {
        label->setStyleSheet("background:#1a2940; color:#c4d6ed; border:1px solid #2d4260; border-radius:6px; padding:7px 12px; font-weight:600;");
        summary_row->addWidget(label);
    }
    summary_row->addStretch(1);
    packet_layout->addLayout(summary_row);

    packet_table_ = new QTableView(packet_page);
    packet_table_->setModel(packet_model_);
    packet_table_->setAlternatingRowColors(true);
    packet_table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    packet_table_->setSelectionMode(QAbstractItemView::SingleSelection);
    packet_table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    packet_table_->verticalHeader()->setVisible(false);
    packet_table_->horizontalHeader()->setStretchLastSection(true);
    packet_table_->setSortingEnabled(false);
    packet_table_->setColumnWidth(0, 75);
    packet_table_->setColumnWidth(1, 165);
    packet_table_->setColumnWidth(2, 190);
    packet_table_->setColumnWidth(3, 190);
    packet_table_->setColumnWidth(4, 90);
    packet_table_->setColumnWidth(5, 85);

    packet_details_ = new QTreeWidget(packet_page);
    packet_details_->setColumnCount(2);
    packet_details_->setHeaderLabels({tr("Protocol layer / field"), tr("Value")});
    packet_details_->header()->setStretchLastSection(true);
    packet_details_->setColumnWidth(0, 270);
    hex_view_ = new QPlainTextEdit(packet_page);
    hex_view_->setReadOnly(true);
    hex_view_->setLineWrapMode(QPlainTextEdit::NoWrap);
    hex_view_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    hex_view_->setPlaceholderText(tr("Select a packet to inspect its raw bytes."));

    auto* lower_splitter = new QSplitter(Qt::Horizontal, packet_page);
    lower_splitter->addWidget(packet_details_);
    lower_splitter->addWidget(hex_view_);
    lower_splitter->setStretchFactor(0, 1);
    lower_splitter->setStretchFactor(1, 1);

    auto* packet_splitter = new QSplitter(Qt::Vertical, packet_page);
    packet_splitter->addWidget(packet_table_);
    packet_splitter->addWidget(lower_splitter);
    packet_splitter->setStretchFactor(0, 3);
    packet_splitter->setStretchFactor(1, 2);
    packet_layout->addWidget(packet_splitter, 1);
    tabs_->addTab(packet_page, tr("Packets"));

    connections_table_ = new QTableWidget(tabs_);
    configure_table(connections_table_, {tr("ID"), tr("Endpoint A"), tr("Endpoint B"), tr("State A"), tr("State B"), tr("Packets"), tr("Bytes"), tr("Duration")});
    connections_table_->setToolTip(tr("Double-click a TCP connection to follow its reassembled streams in each direction."));
    tabs_->addTab(connections_table_, tr("TCP Connections"));

    dns_table_ = new QTableWidget(tabs_);
    configure_table(dns_table_, {tr("ID / Packet"), tr("Direction"), tr("Name"), tr("Type"), tr("Response"), tr("Answers")});
    dns_table_->setToolTip(tr("Double-click a DNS message to inspect its questions and all resource-record sections."));
    tabs_->addTab(dns_table_, tr("DNS"));

    application_table_ = new QTableWidget(tabs_);
    configure_table(application_table_, {tr("Stream"), tr("Protocol"), tr("Direction"), tr("Summary"), tr("Metadata")});
    application_table_->setToolTip(tr("Double-click a row to inspect HTTP headers or TLS ClientHello details."));
    tabs_->addTab(application_table_, tr("HTTP / TLS"));

    statistics_widget_ = new StatisticsWidget(tabs_);
    tabs_->addTab(statistics_widget_, tr("Statistics"));

    refresh_timer_ = new QTimer(this);
    refresh_timer_->setInterval(750);
    connect(refresh_timer_, &QTimer::timeout, this, [this] { refreshAnalysisViews(); });
    refresh_timer_->start();

    connect(packet_table_->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, [this](const QModelIndex& current, const QModelIndex&) { showPacket(current.row()); });
    packet_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(packet_table_, &QWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        const QModelIndex index = packet_table_->indexAt(position);
        if (!index.isValid()) return;
        packet_table_->selectRow(index.row());
        QMenu menu(this);
        QAction* follow = menu.addAction(tr("Follow TCP stream"));
        follow->setEnabled(packet_model_->packetAt(index.row()) != nullptr &&
                           packet_model_->packetAt(index.row())->protocol == "TCP");
        if (menu.exec(packet_table_->viewport()->mapToGlobal(position)) == follow)
            openTcpStreamForPacket(index.row());
    });
    connect(connections_table_, &QTableWidget::cellDoubleClicked, this,
            [this](int row, int) { openTcpStreamForConnection(row); });
    connections_table_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(connections_table_, &QWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        const QModelIndex index = connections_table_->indexAt(position);
        if (!index.isValid()) return;
        connections_table_->selectRow(index.row());
        QMenu menu(this);
        QAction* follow = menu.addAction(tr("Follow TCP stream"));
        if (menu.exec(connections_table_->viewport()->mapToGlobal(position)) == follow)
            openTcpStreamForConnection(index.row());
    });
    connect(dns_table_, &QTableWidget::cellDoubleClicked, this,
            [this](int row, int) { showDnsDetails(row); });
    connect(application_table_, &QTableWidget::cellDoubleClicked, this,
            [this](int row, int) { showApplicationDetails(row); });

    refreshInterfaces();
    setCaptureRunning(false);
    statusBar()->showMessage(tr("Ready — open a PCAP file or start a live capture."));
}

MainWindow::~MainWindow() {
    if (worker_ != nullptr && worker_->isRunning()) {
        worker_->requestStop();
        worker_->wait(1500);
    }
}

void MainWindow::closeEvent(QCloseEvent* event) {
    if (worker_ != nullptr && worker_->isRunning()) {
        worker_->requestStop();
        worker_->wait(1500);
    }
    event->accept();
}

void MainWindow::openCapture() {
    if (capture_running_) return;
    const QString path = QFileDialog::getOpenFileName(
        this, tr("Open packet capture"), QString{},
        tr("Packet captures (*.pcap *.cap);;All files (*)")
    );
    if (path.isEmpty()) return;

    engine_.clear();
    packet_model_->resetModel();
    packet_details_->clear();
    hex_view_->clear();
    refreshAnalysisViews();
    worker_ = new CaptureWorker(CaptureWorker::Mode::OfflineFile, path.toStdString(), false, this);
    connect(worker_, &CaptureWorker::packetCaptured, this, [this](const QByteArray& bytes, quint64 timestamp, quint32 wireLength, quint32 linkTypeValue, quint8 linkTypeNamespace, quint16 linuxPacketProtocol) {
        handlePacket(bytes, timestamp, wireLength, linkTypeValue, linkTypeNamespace, linuxPacketProtocol);
    });
    connect(worker_, &CaptureWorker::captureCompleted, this, [this](const QString& error) {
        handleCaptureFinished(error);
    });
    connect(worker_, &QThread::finished, this, [this] { handleWorkerStopped(); });
    setCaptureRunning(true);
    statusBar()->showMessage(tr("Reading %1…").arg(path));
    worker_->start();
}

void MainWindow::startLiveCapture() {
    if (capture_running_) return;
    const QString interface_name = interface_combo_->currentText();
    if (interface_name.isEmpty()) {
        QMessageBox::warning(this, tr("No interface"), tr("No network interface is available."));
        return;
    }

    engine_.clear();
    packet_model_->resetModel();
    packet_details_->clear();
    hex_view_->clear();
    refreshAnalysisViews();
    worker_ = new CaptureWorker(CaptureWorker::Mode::LiveInterface,
                                interface_name.toStdString(), promiscuous_check_->isChecked(), this);
    connect(worker_, &CaptureWorker::packetCaptured, this, [this](const QByteArray& bytes, quint64 timestamp, quint32 wireLength, quint32 linkTypeValue, quint8 linkTypeNamespace, quint16 linuxPacketProtocol) {
        handlePacket(bytes, timestamp, wireLength, linkTypeValue, linkTypeNamespace, linuxPacketProtocol);
    });
    connect(worker_, &CaptureWorker::captureCompleted, this, [this](const QString& error) {
        handleCaptureFinished(error);
    });
    connect(worker_, &QThread::finished, this, [this] { handleWorkerStopped(); });
    setCaptureRunning(true);
    statusBar()->showMessage(tr("Capturing on %1…").arg(interface_name));
    worker_->start();
}

void MainWindow::stopCapture() {
    if (worker_ == nullptr || !worker_->isRunning()) return;
    worker_->requestStop();
    statusBar()->showMessage(tr("Stopping capture…"));
}

void MainWindow::refreshInterfaces() {
    const QString previous = interface_combo_->currentText();
    interface_combo_->clear();
    for (const auto& interface_name : wirescope::list_interfaces()) {
        interface_combo_->addItem(qstr(interface_name));
    }
    const int previous_index = interface_combo_->findText(previous);
    if (previous_index >= 0) interface_combo_->setCurrentIndex(previous_index);
}

void MainWindow::applyDisplayFilter() {
    std::string error;
    const std::string filter = filter_edit_->text().trimmed().toStdString();
    if (!packet_model_->setDisplayFilter(filter, error)) {
        QMessageBox::warning(this, tr("Invalid display filter"), qstr(error));
        return;
    }
    statusBar()->showMessage(filter.empty()
        ? tr("Display filter cleared — showing all packets.")
        : tr("Display filter applied: %1").arg(filter_edit_->text()));
    if (packet_model_->rowCount() > 0) packet_table_->selectRow(0);
    else { packet_details_->clear(); hex_view_->clear(); }
}

void MainWindow::handlePacket(const QByteArray& bytes, quint64 timestampUs, quint32 wireLength,
                              quint32 linkTypeValue, quint8 linkTypeNamespace,
                              quint16 linuxPacketProtocol) {
    wirescope::CapturedPacket packet;
    packet.timestamp_us = static_cast<std::uint64_t>(timestampUs);
    packet.wire_length = static_cast<std::uint32_t>(wireLength);
    if (linkTypeNamespace == 0U) {
        packet.link_type = wirescope::pcap_link_type(linkTypeValue);
    } else if (linkTypeNamespace == 1U && linkTypeValue <= UINT16_MAX) {
        packet.link_type = wirescope::linux_link_type(static_cast<std::uint16_t>(linkTypeValue),
                                                      linuxPacketProtocol);
    } else {
        packet.link_type = wirescope::pcap_link_type(UINT32_MAX);
    }
    const auto* begin = reinterpret_cast<const std::uint8_t*>(bytes.constData());
    packet.bytes.assign(begin, begin + bytes.size());
    const std::size_t packet_index = engine_.packets().size();
    if (!engine_.ingest(std::move(packet))) {
        statusBar()->showMessage(tr("Warning: packet could not be retained in memory."));
        return;
    }
    packet_model_->appendPacket(packet_index);
    packet_count_label_->setText(tr("%1 packets").arg(static_cast<qulonglong>(engine_.packets().size())));
    byte_count_label_->setText(tr("%1 bytes").arg(static_cast<qulonglong>(engine_.total_wire_bytes())));
}

void MainWindow::handleCaptureFinished(const QString& errorMessage) {
    if (!errorMessage.isEmpty()) {
        statusBar()->showMessage(tr("Capture error: %1").arg(errorMessage));
    } else {
        statusBar()->showMessage(tr("Capture complete — %1 packets analyzed.").arg(static_cast<qulonglong>(engine_.packets().size())));
    }
    refreshAnalysisViews();
}

void MainWindow::handleWorkerStopped() {
    setCaptureRunning(false);
    if (worker_ != nullptr) {
        worker_->deleteLater();
        worker_ = nullptr;
    }
    refreshAnalysisViews();
}

void MainWindow::showPacket(int row) {
    const auto* record = packet_model_->packetAt(row);
    if (record == nullptr) return;
    populatePacketDetails(*record);
    populateHexView(*record);
}

void MainWindow::populatePacketDetails(const wirescope::PacketRecord& record) {
    packet_details_->clear();
    auto* frame = add_detail(packet_details_, tr("Frame %1").arg(static_cast<qulonglong>(record.number)), QString{});
    add_detail(packet_details_, tr("Arrival time"), time_text(record.captured.timestamp_us), frame);
    add_detail(packet_details_, tr("Captured length"), tr("%1 bytes").arg(static_cast<qulonglong>(record.captured.bytes.size())), frame);
    add_detail(packet_details_, tr("Original length"), tr("%1 bytes").arg(static_cast<qulonglong>(record.captured.wire_length)), frame);

    const auto& packet = record.decoded;
    auto* ethernet = add_detail(packet_details_, tr("Ethernet II"), QString{});
    add_detail(packet_details_, tr("Source MAC"), qstr(packet.source_mac), ethernet);
    add_detail(packet_details_, tr("Destination MAC"), qstr(packet.destination_mac), ethernet);
    add_detail(packet_details_, tr("EtherType"), QStringLiteral("0x%1").arg(static_cast<unsigned int>(packet.ether_type), 4, 16, QLatin1Char('0')), ethernet);

    for (std::size_t index = 0U; index < packet.vlan_tags.size(); ++index) {
        const auto& vlan = packet.vlan_tags[index];
        auto* tag = add_detail(packet_details_, tr("VLAN tag %1").arg(static_cast<qulonglong>(index + 1U)), QString{});
        add_detail(packet_details_, tr("Tag protocol ID"), QStringLiteral("0x%1").arg(vlan.tag_protocol_id, 4, 16, QLatin1Char('0')), tag);
        add_detail(packet_details_, tr("VLAN ID"), QString::number(vlan.vlan_id), tag);
        add_detail(packet_details_, tr("Priority (PCP)"), QString::number(vlan.priority), tag);
        add_detail(packet_details_, tr("Drop eligible (DEI)"), vlan.drop_eligible ? tr("Yes") : tr("No"), tag);
        add_detail(packet_details_, tr("Encapsulated EtherType"), QStringLiteral("0x%1").arg(vlan.encapsulated_ether_type, 4, 16, QLatin1Char('0')), tag);
    }

    if (packet.ipv4) {
        const auto& ip = *packet.ipv4;
        auto* node = add_detail(packet_details_, tr("Internet Protocol Version 4"), QString{});
        add_detail(packet_details_, tr("Version"), QStringLiteral("4"), node);
        add_detail(packet_details_, tr("Source address"), qstr(ip.source_address), node);
        add_detail(packet_details_, tr("Destination address"), qstr(ip.destination_address), node);
        add_detail(packet_details_, tr("Header length"), tr("%1 bytes").arg(static_cast<qulonglong>(ip.header_length)), node);
        add_detail(packet_details_, tr("Total length"), tr("%1 bytes").arg(static_cast<unsigned int>(ip.total_length)), node);
        add_detail(packet_details_, tr("TTL"), QString::number(ip.ttl), node);
        add_detail(packet_details_, tr("Protocol"), tr("%1 (%2)").arg(ip.protocol).arg(ip.protocol == 6U ? QStringLiteral("TCP") : ip.protocol == 17U ? QStringLiteral("UDP") : QStringLiteral("other")), node);
        add_detail(packet_details_, tr("Identification"), QStringLiteral("0x%1").arg(ip.identification, 4, 16, QLatin1Char('0')), node);
        add_detail(packet_details_, tr("Fragment offset"), QString::number(ip.fragment_offset), node);
        add_detail(packet_details_, tr("More fragments"), ip.more_fragments ? tr("Yes") : tr("No"), node);
    }

    if (packet.ipv6) {
        const auto& ip = *packet.ipv6;
        auto* node = add_detail(packet_details_, tr("Internet Protocol Version 6"), QString{});
        add_detail(packet_details_, tr("Source address"), qstr(ip.source_address), node);
        add_detail(packet_details_, tr("Destination address"), qstr(ip.destination_address), node);
        add_detail(packet_details_, tr("Version"), QStringLiteral("6"), node);
        add_detail(packet_details_, tr("Payload length"), tr("%1 bytes").arg(static_cast<unsigned int>(ip.payload_length)), node);
        add_detail(packet_details_, tr("Hop limit"), QString::number(ip.hop_limit), node);
        add_detail(packet_details_, tr("Base next-header"), QString::number(ip.next_header), node);
        add_detail(packet_details_, tr("Traffic class"), QStringLiteral("0x%1").arg(static_cast<unsigned int>(ip.traffic_class), 2, 16, QLatin1Char('0')), node);
        add_detail(packet_details_, tr("Flow label"), QStringLiteral("0x%1").arg(static_cast<qulonglong>(ip.flow_label), 5, 16, QLatin1Char('0')), node);
        add_detail(packet_details_, tr("Upper-layer protocol"), QString::number(ip.upper_layer_protocol), node);
        for (std::size_t index = 0U; index < ip.extension_headers.size(); ++index) {
            const auto& extension = ip.extension_headers[index];
            QString extension_name;
            switch (extension.type) {
                case 0U: extension_name = tr("Hop-by-Hop Options"); break;
                case 43U: extension_name = tr("Routing"); break;
                case 44U: extension_name = tr("Fragment"); break;
                case 50U: extension_name = tr("Encapsulating Security Payload"); break;
                case 51U: extension_name = tr("Authentication Header"); break;
                case 60U: extension_name = tr("Destination Options"); break;
                case 135U: extension_name = tr("Mobility"); break;
                default: extension_name = tr("Unknown extension"); break;
            }
            auto* extension_node = add_detail(packet_details_, tr("Extension header %1 — %2")
                .arg(static_cast<qulonglong>(index + 1U)).arg(extension_name), QString{}, node);
            add_detail(packet_details_, tr("Header type"), QString::number(extension.type), extension_node);
            add_detail(packet_details_, tr("Next header"), QString::number(extension.next_header), extension_node);
            add_detail(packet_details_, tr("Header length"), tr("%1 bytes").arg(static_cast<qulonglong>(extension.header_length)), extension_node);
        }
        if (ip.fragment) {
            add_detail(packet_details_, tr("Fragment"), tr("Offset %1, more: %2, ID: %3")
                .arg(static_cast<unsigned int>(ip.fragment->offset)).arg(ip.fragment->more_fragments ? tr("yes") : tr("no"))
                .arg(static_cast<qulonglong>(ip.fragment->identification)), node);
        }
    }

    const wirescope::TransportInfo* transport = nullptr;
    if (packet.ipv4 && packet.ipv4->transport) transport = &*packet.ipv4->transport;
    if (packet.ipv6 && packet.ipv6->transport) transport = &*packet.ipv6->transport;
    if (transport != nullptr) {
        if (const auto* tcp = std::get_if<wirescope::TcpInfo>(transport)) {
            auto* node = add_detail(packet_details_, tr("Transmission Control Protocol"), QString{});
            add_detail(packet_details_, tr("Source port"), QString::number(tcp->source_port), node);
            add_detail(packet_details_, tr("Destination port"), QString::number(tcp->destination_port), node);
            add_detail(packet_details_, tr("Sequence number"), QString::number(tcp->sequence_number), node);
            add_detail(packet_details_, tr("Acknowledgment number"), QString::number(tcp->acknowledgement_number), node);
            add_detail(packet_details_, tr("Flags"), qstr(wirescope::format_tcp_flags(tcp->flags)), node);
            add_detail(packet_details_, tr("Window size"), QString::number(tcp->window_size), node);
            add_detail(packet_details_, tr("Header length"), tr("%1 bytes").arg(static_cast<qulonglong>(tcp->header_length)), node);
            static const std::array<std::pair<std::uint8_t, const char*>, 8> flag_names{{
                {0x01U, "FIN"}, {0x02U, "SYN"}, {0x04U, "RST"}, {0x08U, "PSH"},
                {0x10U, "ACK"}, {0x20U, "URG"}, {0x40U, "ECE"}, {0x80U, "CWR"}
            }};
            auto* flags_node = add_detail(packet_details_, tr("Individual flags"), QString{}, node);
            for (const auto& [mask, name] : flag_names)
                add_detail(packet_details_, QString::fromLatin1(name),
                    (tcp->flags & mask) != 0U ? tr("Set") : tr("Not set"), flags_node);
        } else if (const auto* udp = std::get_if<wirescope::UdpInfo>(transport)) {
            auto* node = add_detail(packet_details_, tr("User Datagram Protocol"), QString{});
            add_detail(packet_details_, tr("Source port"), QString::number(udp->source_port), node);
            add_detail(packet_details_, tr("Destination port"), QString::number(udp->destination_port), node);
            add_detail(packet_details_, tr("Length"), tr("%1 bytes").arg(static_cast<unsigned int>(udp->length)), node);
            add_detail(packet_details_, tr("Payload length"), tr("%1 bytes").arg(udp->length >= 8U ? static_cast<unsigned int>(udp->length - 8U) : 0U), node);
        }
    }

    if (!packet.parse_error.empty()) {
        add_detail(packet_details_, tr("Decoder warning"), qstr(packet.parse_error));
    }
    addApplicationProtocolDetails(record);
    packet_details_->expandToDepth(2);
}


void MainWindow::addApplicationProtocolDetails(const wirescope::PacketRecord& record) {
    for (const auto& observation : engine_.dns_messages()) {
        if (observation.packet_number != record.number) continue;
        const auto& dns = observation.message;
        auto* root = add_detail(packet_details_, tr("Domain Name System (DNS)"), QString{});
        add_detail(packet_details_, tr("Transaction ID"), QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(dns.id), 4, 16, QLatin1Char('0')), root);
        add_detail(packet_details_, tr("Message type"), dns.response ? tr("Response") : tr("Query"), root);
        add_detail(packet_details_, tr("Response code"), qstr(wirescope::dns_rcode_name(dns.rcode)), root);
        add_detail(packet_details_, tr("Opcode"), QString::number(dns.opcode), root);
        add_detail(packet_details_, tr("Authoritative"), dns.authoritative ? tr("Yes") : tr("No"), root);
        add_detail(packet_details_, tr("Truncated"), dns.truncated ? tr("Yes") : tr("No"), root);
        add_detail(packet_details_, tr("Recursion desired"), dns.recursion_desired ? tr("Yes") : tr("No"), root);
        add_detail(packet_details_, tr("Recursion available"), dns.recursion_available ? tr("Yes") : tr("No"), root);
        auto* questions = add_detail(packet_details_, tr("Questions (%1)").arg(static_cast<qulonglong>(dns.questions.size())), QString{}, root);
        for (const auto& question : dns.questions) {
            add_detail(packet_details_, qstr(question.name),
                qstr(wirescope::dns_type_name(question.type)) + QStringLiteral(" / class %1").arg(question.class_code), questions);
        }
        const auto add_records = [&](const QString& title, const std::vector<wirescope::DnsRecord>& records) {
            auto* section = add_detail(packet_details_, title + QStringLiteral(" (%1)").arg(static_cast<qulonglong>(records.size())), QString{}, root);
            for (const auto& resource : records) {
                auto* item = add_detail(packet_details_, qstr(resource.name), qstr(wirescope::dns_type_name(resource.type)), section);
                add_detail(packet_details_, tr("Value"), qstr(resource.value), item);
                add_detail(packet_details_, tr("TTL"), tr("%1 seconds").arg(resource.ttl), item);
                add_detail(packet_details_, tr("Class"), QString::number(resource.class_code), item);
            }
        };
        add_records(tr("Answers"), dns.answers);
        add_records(tr("Authority"), dns.authorities);
        add_records(tr("Additional records"), dns.additional);
    }

    if (record.protocol != "TCP") return;
    const auto analyses = engine_.application_streams();
    for (const auto& analysis : analyses) {
        const bool same_direction = analysis.source == record.source && analysis.destination == record.destination;
        const bool reverse_direction = analysis.source == record.destination && analysis.destination == record.source;
        if (!same_direction && !reverse_direction) continue;

        if (!analysis.http_messages.empty()) {
            auto* root = add_detail(packet_details_, tr("Hypertext Transfer Protocol (HTTP) — stream %1")
                .arg(static_cast<qulonglong>(analysis.index)), QString{});
            for (std::size_t i = 0U; i < analysis.http_messages.size(); ++i) {
                const auto& message = analysis.http_messages[i];
                const QString summary = message.request
                    ? qstr(message.method) + QLatin1Char(' ') + qstr(message.target)
                    : tr("Response %1 %2").arg(message.status).arg(qstr(message.reason));
                auto* item = add_detail(packet_details_, tr("Message %1").arg(static_cast<qulonglong>(i + 1U)), summary, root);
                add_detail(packet_details_, tr("HTTP version"), qstr(message.version), item);
                add_detail(packet_details_, tr("Body bytes"), QString::number(static_cast<qulonglong>(message.body_bytes)), item);
                add_detail(packet_details_, tr("Framing"), message.chunked ? tr("Chunked") :
                    (message.close_delimited ? tr("Connection close") : tr("Content-Length / no body")), item);
                add_detail(packet_details_, tr("Complete"), message.complete ? tr("Yes") : tr("No"), item);
                add_detail(packet_details_, tr("Malformed"), message.malformed ? tr("Yes") : tr("No"), item);
                auto* headers = add_detail(packet_details_, tr("Headers (%1)").arg(static_cast<qulonglong>(message.headers.size())), QString{}, item);
                for (const auto& header : message.headers)
                    add_detail(packet_details_, qstr(header.first), qstr(header.second), headers);
            }
        }

        if (analysis.tls_client_hello) {
            const auto& tls = *analysis.tls_client_hello;
            auto* root = add_detail(packet_details_, tr("Transport Layer Security — ClientHello, stream %1")
                .arg(static_cast<qulonglong>(analysis.index)), QString{});
            add_detail(packet_details_, tr("Legacy version"), qstr(tls.legacy_version), root);
            add_detail(packet_details_, tr("Server Name Indication"), tls.server_name.empty() ? tr("Not provided") : qstr(tls.server_name), root);
            add_detail(packet_details_, tr("Supported versions"), join_strings(tls.supported_versions), root);
            add_detail(packet_details_, tr("ALPN protocols"), join_strings(tls.alpn_protocols), root);
            auto* ciphers = add_detail(packet_details_, tr("Cipher suites (%1)").arg(static_cast<qulonglong>(tls.cipher_suites.size())), QString{}, root);
            for (const auto cipher : tls.cipher_suites)
                add_detail(packet_details_, QStringLiteral("0x%1").arg(cipher, 4, 16, QLatin1Char('0')),
                    qstr(wirescope::tls_cipher_name(cipher)), ciphers);
        }
    }
}

void MainWindow::openTcpStreamForConnection(int row) {
    const auto& connections = engine_.tcp_connections().connections();
    if (row < 0 || static_cast<std::size_t>(row) >= connections.size()) return;
    TcpStreamDialog dialog(connections[static_cast<std::size_t>(row)], engine_.tcp_streams().streams(), this);
    dialog.exec();
}

void MainWindow::openTcpStreamForPacket(int row) {
    const auto* packet = packet_model_->packetAt(row);
    if (packet == nullptr || packet->protocol != "TCP") return;
    const auto& connections = engine_.tcp_connections().connections();
    const auto found = std::find_if(connections.rbegin(), connections.rend(), [&](const auto& connection) {
        return (connection.a == packet->source && connection.b == packet->destination) ||
               (connection.b == packet->source && connection.a == packet->destination);
    });
    if (found == connections.rend()) {
        QMessageBox::information(this, tr("TCP stream unavailable"),
            tr("No tracked TCP connection was found for this packet."));
        return;
    }
    TcpStreamDialog dialog(*found, engine_.tcp_streams().streams(), this);
    dialog.exec();
}

void MainWindow::showDnsDetails(int row) {
    const auto& messages = engine_.dns_messages();
    if (row < 0 || static_cast<std::size_t>(row) >= messages.size()) return;
    const auto& observation = messages[static_cast<std::size_t>(row)];
    const auto& dns = observation.message;
    QString details = tr("Packet: %1\nTransaction ID: 0x%2\nDirection: %3 → %4\nType: %5\nRCODE: %6\n\nQuestions:\n")
        .arg(static_cast<qulonglong>(observation.packet_number))
        .arg(dns.id, 4, 16, QLatin1Char('0'))
        .arg(qstr(wirescope::endpoint_string(observation.source)))
        .arg(qstr(wirescope::endpoint_string(observation.destination)))
        .arg(dns.response ? tr("Response") : tr("Query"))
        .arg(qstr(wirescope::dns_rcode_name(dns.rcode)));
    for (const auto& question : dns.questions)
        details += QStringLiteral("  %1  %2\n").arg(qstr(question.name), qstr(wirescope::dns_type_name(question.type)));
    const auto append_records = [&](const QString& title, const std::vector<wirescope::DnsRecord>& records) {
        details += QStringLiteral("\n%1:\n").arg(title);
        for (const auto& item : records)
            details += QStringLiteral("  %1  %2  TTL %3  %4\n")
                .arg(qstr(item.name), qstr(wirescope::dns_type_name(item.type)))
                .arg(item.ttl).arg(qstr(item.value));
    };
    append_records(tr("Answers"), dns.answers);
    append_records(tr("Authority"), dns.authorities);
    append_records(tr("Additional"), dns.additional);
    QMessageBox box(this);
    box.setWindowTitle(tr("DNS message details"));
    box.setText(details);
    box.setTextInteractionFlags(Qt::TextSelectableByMouse);
    box.exec();
}

void MainWindow::showApplicationDetails(int row) {
    if (row < 0) return;
    const auto analyses = engine_.application_streams();
    int current = 0;
    for (const auto& analysis : analyses) {
        const QString direction = qstr(wirescope::endpoint_string(analysis.source)) + QStringLiteral(" → ") +
                                  qstr(wirescope::endpoint_string(analysis.destination));
        for (const auto& message : analysis.http_messages) {
            if (current++ != row) continue;
            QString details = tr("Stream: %1\nDirection: %2\n\n")
                .arg(static_cast<qulonglong>(analysis.index)).arg(direction);
            details += message.request
                ? QStringLiteral("%1 %2 %3\n").arg(qstr(message.method), qstr(message.target), qstr(message.version))
                : QStringLiteral("%1 %2 %3\n").arg(qstr(message.version)).arg(message.status).arg(qstr(message.reason));
            details += tr("Body: %1 bytes\nComplete: %2\nMalformed: %3\n\nHeaders:\n")
                .arg(static_cast<qulonglong>(message.body_bytes))
                .arg(message.complete ? tr("yes") : tr("no"))
                .arg(message.malformed ? tr("yes") : tr("no"));
            for (const auto& header : message.headers)
                details += qstr(header.first) + QStringLiteral(": ") + qstr(header.second) + QLatin1Char('\n');
            QMessageBox box(this);
            box.setWindowTitle(tr("HTTP message details"));
            box.setText(details);
            box.setTextInteractionFlags(Qt::TextSelectableByMouse);
            box.exec();
            return;
        }
        if (analysis.tls_client_hello) {
            if (current++ != row) continue;
            const auto& tls = *analysis.tls_client_hello;
            QString details = tr("TLS ClientHello\nStream: %1\nDirection: %2\nLegacy version: %3\nSNI: %4\nSupported versions: %5\nALPN: %6\n\nCipher suites:\n")
                .arg(static_cast<qulonglong>(analysis.index)).arg(direction).arg(qstr(tls.legacy_version))
                .arg(tls.server_name.empty() ? tr("not provided") : qstr(tls.server_name))
                .arg(join_strings(tls.supported_versions)).arg(join_strings(tls.alpn_protocols));
            for (const auto cipher : tls.cipher_suites)
                details += QStringLiteral("  0x%1  %2\n").arg(cipher, 4, 16, QLatin1Char('0')).arg(qstr(wirescope::tls_cipher_name(cipher)));
            QMessageBox box(this);
            box.setWindowTitle(tr("TLS ClientHello details"));
            box.setText(details);
            box.setTextInteractionFlags(Qt::TextSelectableByMouse);
            box.exec();
            return;
        }
    }
}

void MainWindow::populateHexView(const wirescope::PacketRecord& record) {
    hex_view_->setPlainText(hex_dump(record.captured.bytes));
    hex_view_->moveCursor(QTextCursor::Start);
}

void MainWindow::refreshAnalysisViews() {
    connection_count_label_->setText(tr("%1 TCP connections").arg(static_cast<qulonglong>(engine_.tcp_connections().size())));
    dns_count_label_->setText(tr("%1 DNS messages").arg(static_cast<qulonglong>(engine_.dns_messages().size())));

    const auto& connections = engine_.tcp_connections().connections();
    connections_table_->setRowCount(static_cast<int>(connections.size()));
    for (std::size_t index = 0U; index < connections.size(); ++index) {
        const auto& connection = connections[index];
        const auto duration = connection.last_seen_us >= connection.first_seen_us
            ? connection.last_seen_us - connection.first_seen_us : 0U;
        const std::array<QString, 8> values{
            QString::number(static_cast<qulonglong>(connection.id)), qstr(wirescope::endpoint_string(connection.a)),
            qstr(wirescope::endpoint_string(connection.b)), qstr(wirescope::tcp_state_name(connection.state_a)),
            qstr(wirescope::tcp_state_name(connection.state_b)), QString::number(static_cast<qulonglong>(connection.packets)),
            QString::number(static_cast<qulonglong>(connection.bytes)), tr("%1 ms").arg(static_cast<double>(duration) / 1000.0, 0, 'f', 3)
        };
        for (int column = 0; column < static_cast<int>(values.size()); ++column)
            connections_table_->setItem(static_cast<int>(index), column, cell(values[static_cast<std::size_t>(column)]));
    }

    const auto& dns_messages = engine_.dns_messages();
    dns_table_->setRowCount(static_cast<int>(dns_messages.size()));
    for (std::size_t index = 0U; index < dns_messages.size(); ++index) {
        const auto& dns = dns_messages[index];
        QStringList questions;
        for (const auto& question : dns.message.questions)
            questions.push_back(qstr(question.name) + " " + qstr(wirescope::dns_type_name(question.type)));
        QStringList answers;
        for (const auto& answer : dns.message.answers)
            answers.push_back(qstr(answer.name) + " → " + qstr(answer.value));
        const QString direction = qstr(wirescope::endpoint_string(dns.source)) + " → " +
                                  qstr(wirescope::endpoint_string(dns.destination));
        const std::array<QString, 6> values{
            QStringLiteral("0x%1 / #%2").arg(dns.message.id, 4, 16, QLatin1Char('0')).arg(static_cast<qulonglong>(dns.packet_number)), direction,
            questions.join("; "),
            questions.isEmpty() ? QStringLiteral("—") : questions.front().section(QLatin1Char(' '), -1),
            dns.message.response ? qstr(wirescope::dns_rcode_name(dns.message.rcode)) : tr("Query"),
            answers.join("; ")
        };
        for (int column = 0; column < static_cast<int>(values.size()); ++column)
            dns_table_->setItem(static_cast<int>(index), column, cell(values[static_cast<std::size_t>(column)]));
    }

    const auto analyses = engine_.application_streams();
    int row_count = 0;
    for (const auto& analysis : analyses)
        row_count += static_cast<int>(analysis.http_messages.size()) + (analysis.tls_client_hello ? 1 : 0);
    application_table_->setRowCount(row_count);
    int row = 0;
    for (const auto& analysis : analyses) {
        const QString direction = qstr(wirescope::endpoint_string(analysis.source)) + " → " +
                                  qstr(wirescope::endpoint_string(analysis.destination));
        for (const auto& message : analysis.http_messages) {
            const QString summary = message.request
                ? qstr(message.method) + " " + qstr(message.target)
                : tr("HTTP %1 %2").arg(static_cast<unsigned int>(message.status)).arg(qstr(message.reason));
            const std::array<QString, 5> values{
                QString::number(analysis.index), QStringLiteral("HTTP/1.x"), direction, summary,
                tr("%1 body bytes · %2")
                    .arg(static_cast<qulonglong>(message.body_bytes))
                    .arg(message.complete ? tr("complete") : tr("incomplete"))
            };
            for (int column = 0; column < static_cast<int>(values.size()); ++column)
                application_table_->setItem(row, column, cell(values[static_cast<std::size_t>(column)]));
            ++row;
        }
        if (analysis.tls_client_hello) {
            const auto& tls = *analysis.tls_client_hello;
            const std::array<QString, 5> values{
                QString::number(analysis.index), QStringLiteral("TLS ClientHello"), direction,
                tls.server_name.empty() ? tr("ClientHello without SNI") : qstr(tls.server_name),
                tr("Versions: %1 · ALPN: %2 · Ciphers: %3")
                    .arg(join_strings(tls.supported_versions), join_strings(tls.alpn_protocols))
                    .arg(static_cast<qulonglong>(tls.cipher_suites.size()))
            };
            for (int column = 0; column < static_cast<int>(values.size()); ++column)
                application_table_->setItem(row, column, cell(values[static_cast<std::size_t>(column)]));
            ++row;
        }
    }
    statistics_widget_->setEngine(engine_);
}

void MainWindow::setCaptureRunning(bool running) {
    capture_running_ = running;
    if (open_action_ != nullptr) open_action_->setEnabled(!running);
    if (start_action_ != nullptr) start_action_->setEnabled(!running);
    if (stop_action_ != nullptr) stop_action_->setEnabled(running);
    if (interface_combo_ != nullptr) interface_combo_->setEnabled(!running);
    if (promiscuous_check_ != nullptr) promiscuous_check_->setEnabled(!running);
    if (packet_table_ != nullptr) packet_table_->setEnabled(true);
}
