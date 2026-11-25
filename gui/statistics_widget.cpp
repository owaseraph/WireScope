#include "statistics_widget.hpp"

#include "wirescope/common.hpp"

#include <QHeaderView>
#include <QAbstractItemView>
#include <QColor>
#include <QPaintEvent>
#include <QPen>
#include <QSizePolicy>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QWidget>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <map>
#include <numeric>
#include <vector>
#include <utility>

namespace {

QTableWidgetItem* readonly_cell(const QString& value) {
    auto* item = new QTableWidgetItem(value);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}

QString format_bytes(std::uint64_t bytes) {
    constexpr std::array<const char*, 4> units{"B", "KiB", "MiB", "GiB"};
    double amount = static_cast<double>(bytes);
    std::size_t unit = 0U;
    while (amount >= 1024.0 && unit + 1U < units.size()) {
        amount /= 1024.0;
        ++unit;
    }
    return QStringLiteral("%1 %2").arg(amount, 0, 'f', unit == 0U ? 0 : 2).arg(QString::fromLatin1(units[unit]));
}

class MetricCard final : public QGroupBox {
public:
    MetricCard(const QString& title, QLabel*& value, QWidget* parent = nullptr)
        : QGroupBox(title, parent) {
        auto* layout = new QVBoxLayout(this);
        value = new QLabel(QStringLiteral("—"), this);
        QFont font = value->font();
        font.setPointSize(font.pointSize() + 4);
        font.setBold(true);
        value->setFont(font);
        layout->addWidget(value);
    }
};

} // namespace

class TrafficChartWidget final : public QWidget {
public:
    explicit TrafficChartWidget(QWidget* parent = nullptr) : QWidget(parent) {
        setMinimumHeight(230);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }

    void setSamples(std::vector<double> packets, std::vector<double> bytes) {
        packet_samples_ = std::move(packets);
        byte_samples_ = std::move(bytes);
        update();
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.fillRect(rect(), QColor("#0b1220"));

        const QRectF plot(58.0, 38.0, std::max(10, width() - 82), std::max(10, height() - 78));
        painter.setPen(QColor("#dbeafe"));
        painter.drawText(QRectF(12.0, 8.0, width() - 24.0, 22.0), Qt::AlignLeft | Qt::AlignVCenter,
                         tr("Traffic over capture time"));
        painter.setPen(QPen(QColor("#263449"), 1.0));
        for (int i = 0; i <= 4; ++i) {
            const qreal y = plot.top() + plot.height() * static_cast<qreal>(i) / 4.0;
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y));
        }
        painter.drawRect(plot);

        if (packet_samples_.empty() || byte_samples_.empty()) {
            painter.setPen(QColor("#94a3b8"));
            painter.drawText(plot, Qt::AlignCenter, tr("Capture traffic to populate the timeline."));
            return;
        }

        const auto make_path = [&](const std::vector<double>& values) {
            const double maximum = std::max(1.0, *std::max_element(values.begin(), values.end()));
            QPainterPath path;
            for (std::size_t i = 0U; i < values.size(); ++i) {
                const qreal x = plot.left() + (values.size() <= 1U ? 0.0 :
                    plot.width() * static_cast<qreal>(i) / static_cast<qreal>(values.size() - 1U));
                const qreal y = plot.bottom() - plot.height() *
                    static_cast<qreal>(values[i] / maximum);
                if (i == 0U) path.moveTo(x, y); else path.lineTo(x, y);
            }
            return path;
        };

        painter.setClipRect(plot.adjusted(-1.0, -1.0, 1.0, 1.0));
        painter.setPen(QPen(QColor("#60a5fa"), 2.2));
        painter.drawPath(make_path(packet_samples_));
        painter.setPen(QPen(QColor("#34d399"), 2.2));
        painter.drawPath(make_path(byte_samples_));
        painter.setClipping(false);

        painter.setPen(QColor("#93c5fd"));
        painter.drawText(QRectF(plot.left(), height() - 30.0, 160.0, 20.0), Qt::AlignLeft, tr("Packets / second"));
        painter.setPen(QColor("#6ee7b7"));
        painter.drawText(QRectF(plot.left() + 165.0, height() - 30.0, 160.0, 20.0), Qt::AlignLeft, tr("Bytes / second (scaled)"));
    }

private:
    std::vector<double> packet_samples_;
    std::vector<double> byte_samples_;
};

StatisticsWidget::StatisticsWidget(QWidget* parent) : QWidget(parent) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(10, 10, 10, 10);

    auto* metrics = new QGridLayout();
    metrics->addWidget(new MetricCard(tr("Packets"), packet_value_, this), 0, 0);
    metrics->addWidget(new MetricCard(tr("Captured bytes"), byte_value_, this), 0, 1);
    metrics->addWidget(new MetricCard(tr("Capture duration"), duration_value_, this), 0, 2);
    metrics->addWidget(new MetricCard(tr("Average packets/s"), packet_rate_value_, this), 0, 3);
    metrics->addWidget(new MetricCard(tr("Average throughput"), throughput_value_, this), 0, 4);
    layout->addLayout(metrics);

    chart_ = new TrafficChartWidget(this);
    layout->addWidget(chart_, 2);

    auto* tables = new QHBoxLayout();
    protocol_table_ = new QTableWidget(this);
    protocol_table_->setColumnCount(4);
    protocol_table_->setHorizontalHeaderLabels({tr("Protocol"), tr("Packets"), tr("Bytes"), tr("Share")});
    conversation_table_ = new QTableWidget(this);
    conversation_table_->setColumnCount(5);
    conversation_table_->setHorizontalHeaderLabels({tr("Endpoint A"), tr("Endpoint B"), tr("Packets"), tr("Bytes"), tr("State")});
    for (auto* table : {protocol_table_, conversation_table_}) {
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setStretchLastSection(true);
    }
    tables->addWidget(protocol_table_, 1);
    tables->addWidget(conversation_table_, 2);
    layout->addLayout(tables, 2);
}

void StatisticsWidget::setEngine(const wirescope::AnalysisEngine& engine) {
    const auto& packets = engine.packets();
    const std::uint64_t total_packets = static_cast<std::uint64_t>(packets.size());
    const std::uint64_t total_bytes = engine.total_wire_bytes();

    std::uint64_t first_timestamp = 0U;
    std::uint64_t last_timestamp = 0U;
    if (!packets.empty()) {
        first_timestamp = packets.front().captured.timestamp_us;
        last_timestamp = first_timestamp;
        for (const auto& packet : packets) {
            first_timestamp = std::min(first_timestamp, packet.captured.timestamp_us);
            last_timestamp = std::max(last_timestamp, packet.captured.timestamp_us);
        }
    }
    const double duration_seconds = packets.empty() ? 0.0 :
        std::max(0.001, static_cast<double>(last_timestamp - first_timestamp) / 1'000'000.0);

    packet_value_->setText(QString::number(static_cast<qulonglong>(total_packets)));
    byte_value_->setText(format_bytes(total_bytes));
    duration_value_->setText(QStringLiteral("%1 s").arg(duration_seconds, 0, 'f', 3));
    const double packets_per_second = duration_seconds > 0.0
        ? static_cast<double>(total_packets) / duration_seconds : 0.0;
    const double megabits_per_second = duration_seconds > 0.0
        ? static_cast<double>(total_bytes) * 8.0 / duration_seconds / 1'000'000.0 : 0.0;
    packet_rate_value_->setText(QStringLiteral("%1").arg(packets_per_second, 0, 'f', 2));
    throughput_value_->setText(QStringLiteral("%1 Mbit/s").arg(megabits_per_second, 0, 'f', 3));

    std::map<QString, std::uint64_t> protocol_counts;
    std::map<QString, std::uint64_t> protocol_bytes;
    for (const auto& packet : packets) {
        const QString protocol = QString::fromStdString(packet.protocol);
        ++protocol_counts[protocol];
        protocol_bytes[protocol] += packet.captured.wire_length;
    }
    protocol_table_->setRowCount(static_cast<int>(protocol_counts.size()));
    int row = 0;
    for (const auto& [protocol, count] : protocol_counts) {
        protocol_table_->setItem(row, 0, readonly_cell(protocol));
        protocol_table_->setItem(row, 1, readonly_cell(QString::number(static_cast<qulonglong>(count))));
        protocol_table_->setItem(row, 2, readonly_cell(format_bytes(protocol_bytes[protocol])));
        const double share = total_packets == 0U ? 0.0 : static_cast<double>(count) * 100.0 / static_cast<double>(total_packets);
        protocol_table_->setItem(row, 3, readonly_cell(QStringLiteral("%1%").arg(share, 0, 'f', 1)));
        ++row;
    }

    std::vector<const wirescope::TcpConnection*> conversations;
    conversations.reserve(engine.tcp_connections().connections().size());
    for (const auto& connection : engine.tcp_connections().connections()) conversations.push_back(&connection);
    std::stable_sort(conversations.begin(), conversations.end(), [](const auto* a, const auto* b) {
        return a->bytes > b->bytes;
    });
    const std::size_t shown = std::min<std::size_t>(conversations.size(), 12U);
    conversation_table_->setRowCount(static_cast<int>(shown));
    for (std::size_t i = 0U; i < shown; ++i) {
        const auto& connection = *conversations[i];
        const std::array<QString, 5> values{
            QString::fromStdString(wirescope::endpoint_string(connection.a)),
            QString::fromStdString(wirescope::endpoint_string(connection.b)),
            QString::number(static_cast<qulonglong>(connection.packets)),
            format_bytes(connection.bytes),
            QStringLiteral("%1 / %2")
                .arg(QString::fromLatin1(wirescope::tcp_state_name(connection.state_a)))
                .arg(QString::fromLatin1(wirescope::tcp_state_name(connection.state_b)))
        };
        for (int column = 0; column < static_cast<int>(values.size()); ++column)
            conversation_table_->setItem(static_cast<int>(i), column, readonly_cell(values[static_cast<std::size_t>(column)]));
    }

    constexpr std::size_t bucket_count = 60U;
    std::vector<double> packets_per_bucket(bucket_count, 0.0);
    std::vector<double> bytes_per_bucket(bucket_count, 0.0);
    if (!packets.empty()) {
        const std::uint64_t span_us = std::max<std::uint64_t>(1U, last_timestamp - first_timestamp + 1U);
        for (const auto& packet : packets) {
            const std::uint64_t elapsed = packet.captured.timestamp_us - first_timestamp;
            const long double position = static_cast<long double>(elapsed) *
                static_cast<long double>(bucket_count) / static_cast<long double>(span_us);
            const std::size_t bucket = std::min<std::size_t>(bucket_count - 1U,
                static_cast<std::size_t>(position));
            packets_per_bucket[bucket] += 1.0;
            bytes_per_bucket[bucket] += static_cast<double>(packet.captured.wire_length);
        }
        const double bucket_seconds = std::max(0.001, duration_seconds / static_cast<double>(bucket_count));
        for (std::size_t i = 0U; i < bucket_count; ++i) {
            packets_per_bucket[i] /= bucket_seconds;
            bytes_per_bucket[i] /= bucket_seconds;
        }
    }
    chart_->setSamples(std::move(packets_per_bucket), std::move(bytes_per_bucket));
}
