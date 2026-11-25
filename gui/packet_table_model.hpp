#pragma once

#include "wirescope/analysis_engine.hpp"

#include <QAbstractTableModel>

#include <cstddef>
#include <string>
#include <vector>

class PacketTableModel final : public QAbstractTableModel {
public:
    explicit PacketTableModel(const wirescope::AnalysisEngine& engine, QObject* parent = nullptr);

    [[nodiscard]] int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = QModelIndex()) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation,
                                      int role = Qt::DisplayRole) const override;

    void appendPacket(std::size_t packet_index);
    void resetModel();
    [[nodiscard]] bool setDisplayFilter(const std::string& expression, std::string& error);
    [[nodiscard]] const wirescope::PacketRecord* packetAt(int row) const noexcept;
    [[nodiscard]] const std::vector<std::size_t>& visiblePacketIndices() const noexcept;

private:
    const wirescope::AnalysisEngine& engine_;
    std::string filter_;
    std::vector<std::size_t> visible_indices_;
};
