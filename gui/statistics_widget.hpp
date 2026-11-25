#pragma once

#include "wirescope/analysis_engine.hpp"

#include <QWidget>

class QLabel;
class QTableWidget;
class TrafficChartWidget;

class StatisticsWidget final : public QWidget {
public:
    explicit StatisticsWidget(QWidget* parent = nullptr);
    void setEngine(const wirescope::AnalysisEngine& engine);

private:
    QLabel* packet_value_{};
    QLabel* byte_value_{};
    QLabel* duration_value_{};
    QLabel* packet_rate_value_{};
    QLabel* throughput_value_{};
    QTableWidget* protocol_table_{};
    QTableWidget* conversation_table_{};
    TrafficChartWidget* chart_{};
};
