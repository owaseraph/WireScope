#include "packet_table_model.hpp"

#include "wirescope/common.hpp"

#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QFont>
#include <QString>
#include <QStringList>

#include <array>

PacketTableModel::PacketTableModel(const wirescope::AnalysisEngine& engine, QObject* parent)
    : QAbstractTableModel(parent), engine_(engine) {}

int PacketTableModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(visible_indices_.size());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : 7;
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) return {};
    const auto* record = packetAt(index.row());
    if (record == nullptr) return {};

    if (role == Qt::ForegroundRole && index.column() == 4) {
        if (record->protocol == "TCP") return QBrush(QColor("#65b8f2"));
        if (record->protocol == "UDP") return QBrush(QColor("#65d6bd"));
        if (record->protocol == "ICMP" || record->protocol == "ICMPv6") return QBrush(QColor("#e6b96b"));
    }
    if (role == Qt::ToolTipRole) {
        return QString::fromStdString(record->info);
    }
    if (role == Qt::TextAlignmentRole && (index.column() == 0 || index.column() == 6)) {
        return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
    }
    if (role != Qt::DisplayRole) return {};

    const QString source = record->source.address.empty()
        ? QStringLiteral("—")
        : QString::fromStdString(wirescope::endpoint_string(record->source));
    const QString destination = record->destination.address.empty()
        ? QStringLiteral("—")
        : QString::fromStdString(wirescope::endpoint_string(record->destination));

    const auto timestamp_ms = static_cast<qint64>(record->captured.timestamp_us / 1000U);
    const auto remaining_us = record->captured.timestamp_us % 1000U;
    const QString timestamp = QDateTime::fromMSecsSinceEpoch(timestamp_ms, Qt::UTC)
        .toString(QStringLiteral("HH:mm:ss.zzz")) +
        QStringLiteral("%1").arg(static_cast<unsigned int>(remaining_us), 3, 10, QLatin1Char('0'));

    switch (index.column()) {
        case 0: return QVariant::fromValue<qulonglong>(record->number);
        case 1: return timestamp;
        case 2: return source;
        case 3: return destination;
        case 4: return QString::fromStdString(record->protocol);
        case 5: return QStringLiteral("%1 B").arg(static_cast<qulonglong>(record->captured.bytes.size()));
        case 6: return QString::fromStdString(record->info);
        default: return {};
    }
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (role != Qt::DisplayRole || orientation != Qt::Horizontal) return {};
    static constexpr std::array<const char*, 7> headers{
        "No.", "Time (UTC)", "Source", "Destination", "Protocol", "Length", "Info"
    };
    if (section < 0 || static_cast<std::size_t>(section) >= headers.size()) return {};
    return QString::fromLatin1(headers[static_cast<std::size_t>(section)]);
}

void PacketTableModel::appendPacket(std::size_t packet_index) {
    const auto& packets = engine_.packets();
    if (packet_index >= packets.size()) return;
    std::string error;
    if (!packet_matches_filter(packets[packet_index], filter_, error)) return;
    const int row = rowCount();
    beginInsertRows(QModelIndex(), row, row);
    visible_indices_.push_back(packet_index);
    endInsertRows();
}

void PacketTableModel::resetModel() {
    beginResetModel();
    visible_indices_.clear();
    endResetModel();
}

bool PacketTableModel::setDisplayFilter(const std::string& expression, std::string& error) {
    wirescope::PacketRecord sample;
    static_cast<void>(packet_matches_filter(sample, expression, error));
    if (!error.empty()) return false;

    beginResetModel();
    filter_ = expression;
    visible_indices_.clear();
    const auto& packets = engine_.packets();
    visible_indices_.reserve(packets.size());
    for (std::size_t index = 0U; index < packets.size(); ++index) {
        std::string ignored;
        if (packet_matches_filter(packets[index], filter_, ignored)) {
            visible_indices_.push_back(index);
        }
    }
    endResetModel();
    return true;
}

const wirescope::PacketRecord* PacketTableModel::packetAt(int row) const noexcept {
    if (row < 0 || static_cast<std::size_t>(row) >= visible_indices_.size()) return nullptr;
    const std::size_t index = visible_indices_[static_cast<std::size_t>(row)];
    const auto& packets = engine_.packets();
    return index < packets.size() ? &packets[index] : nullptr;
}

const std::vector<std::size_t>& PacketTableModel::visiblePacketIndices() const noexcept {
    return visible_indices_;
}
