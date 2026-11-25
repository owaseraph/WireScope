#pragma once

#include "capture_worker.hpp"
#include "packet_table_model.hpp"
#include "wirescope/analysis_engine.hpp"

#include <QMainWindow>

#include <QString>
#include <string>

class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QAction;
class QPlainTextEdit;
class QTableView;
class QTableWidget;
class QTabWidget;
class QTreeWidget;
class QCloseEvent;
class QTimer;
class StatisticsWidget;

class MainWindow final : public QMainWindow {
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* event) override;

private:
    void openCapture();
    void startLiveCapture();
    void stopCapture();
    void refreshInterfaces();
    void applyDisplayFilter();
    void handlePacket(const QByteArray& bytes, quint64 timestampUs, quint32 wireLength);
    void handleCaptureFinished(const QString& errorMessage);
    void handleWorkerStopped();
    void showPacket(int row);
    void openTcpStreamForConnection(int row);
    void openTcpStreamForPacket(int row);
    void showDnsDetails(int row);
    void showApplicationDetails(int row);
    void refreshAnalysisViews();
    void populatePacketDetails(const wirescope::PacketRecord& record);
    void addApplicationProtocolDetails(const wirescope::PacketRecord& record);
    void populateHexView(const wirescope::PacketRecord& record);
    void setCaptureRunning(bool running);

    wirescope::AnalysisEngine engine_;
    PacketTableModel* packet_model_{};
    CaptureWorker* worker_{};
    QAction* open_action_{};
    QAction* start_action_{};
    QAction* stop_action_{};

    QComboBox* interface_combo_{};
    QCheckBox* promiscuous_check_{};
    QLineEdit* filter_edit_{};
    QTableView* packet_table_{};
    QTreeWidget* packet_details_{};
    QPlainTextEdit* hex_view_{};
    QTableWidget* connections_table_{};
    QTableWidget* dns_table_{};
    QTableWidget* application_table_{};
    StatisticsWidget* statistics_widget_{};
    QLabel* packet_count_label_{};
    QLabel* byte_count_label_{};
    QLabel* connection_count_label_{};
    QLabel* dns_count_label_{};
    QTabWidget* tabs_{};
    QTimer* refresh_timer_{};
    bool capture_running_{};
};
