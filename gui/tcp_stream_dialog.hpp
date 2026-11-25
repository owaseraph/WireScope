#pragma once

#include "wirescope/tcp_reassembler.hpp"
#include "wirescope/tcp_tracker.hpp"

#include <QDialog>

#include <vector>

class QTabWidget;

class TcpStreamDialog final : public QDialog {
public:
    TcpStreamDialog(const wirescope::TcpConnection& connection,
                    const std::vector<wirescope::TcpStream>& streams,
                    QWidget* parent = nullptr);

private:
    QTabWidget* tabs_{};
};
