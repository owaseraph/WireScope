#include "tcp_stream_dialog.hpp"

#include "wirescope/common.hpp"

#include <QFontDatabase>
#include <QLabel>
#include <QFont>
#include <QString>
#include <QPlainTextEdit>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QWidget>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

namespace {

constexpr std::size_t display_limit = 2U * 1024U * 1024U;

QString ascii_view(const std::vector<std::uint8_t>& bytes) {
    const std::size_t count = std::min(bytes.size(), display_limit);
    QString text;
    text.reserve(static_cast<qsizetype>(count + 96U));
    for (std::size_t i = 0U; i < count; ++i) {
        const std::uint8_t byte = bytes[i];
        if (byte == '\n' || byte == '\r' || byte == '\t' || (byte >= 0x20U && byte <= 0x7EU)) {
            text.append(QChar(static_cast<ushort>(byte)));
        } else {
            text.append(QLatin1Char('.'));
        }
    }
    if (count < bytes.size()) {
        text += QStringLiteral("\n\n[Display limited to first %1 of %2 bytes]")
            .arg(static_cast<qulonglong>(count))
            .arg(static_cast<qulonglong>(bytes.size()));
    }
    return text;
}

QString hex_view(const std::vector<std::uint8_t>& bytes) {
    constexpr char digits[] = "0123456789ABCDEF";
    constexpr std::size_t per_line = 16U;
    const std::size_t count = std::min(bytes.size(), display_limit);
    QString text;
    text.reserve(static_cast<qsizetype>(count * 3U + (count / per_line) * 16U + 128U));
    for (std::size_t offset = 0U; offset < count; offset += per_line) {
        std::ostringstream line;
        line << std::uppercase << std::hex << std::setfill('0') << std::setw(8) << offset << "  ";
        QString ascii;
        for (std::size_t i = 0U; i < per_line; ++i) {
            const std::size_t pos = offset + i;
            if (pos < count) {
                const auto b = bytes[pos];
                line << digits[(b >> 4U) & 0x0FU] << digits[b & 0x0FU] << ' ';
                ascii.append(b >= 0x20U && b <= 0x7EU ? QChar(static_cast<ushort>(b)) : QLatin1Char('.'));
            } else {
                line << "   ";
                ascii.append(QLatin1Char(' '));
            }
            if (i == 7U) line << ' ';
        }
        text += QString::fromStdString(line.str()) + QStringLiteral("|") + ascii + QStringLiteral("|\n");
    }
    if (count < bytes.size()) {
        text += QStringLiteral("\n[Hex display limited to first %1 of %2 bytes]")
            .arg(static_cast<qulonglong>(count))
            .arg(static_cast<qulonglong>(bytes.size()));
    }
    return text;
}

void add_stream_page(QTabWidget* parent, const wirescope::TcpStream& stream,
                     const QString& direction, std::size_t generation) {
    auto* page = new QWidget(parent);
    auto* layout = new QVBoxLayout(page);
    auto* summary = new QLabel(
        QStringLiteral("%1    ·    %2 bytes    ·    %3 segments    ·    %4 out of order    ·    %5 duplicate bytes    ·    %6 pending    ·    %7 dropped")
            .arg(direction)
            .arg(static_cast<qulonglong>(stream.payload.size()))
            .arg(static_cast<qulonglong>(stream.segments))
            .arg(static_cast<qulonglong>(stream.out_of_order_segments))
            .arg(static_cast<qulonglong>(stream.retransmitted_bytes))
            .arg(static_cast<qulonglong>(stream.pending_bytes))
            .arg(static_cast<qulonglong>(stream.dropped_bytes)), page);
    summary->setWordWrap(true);
    layout->addWidget(summary);

    auto* views = new QTabWidget(page);
    auto* ascii = new QPlainTextEdit(views);
    ascii->setReadOnly(true);
    ascii->setLineWrapMode(QPlainTextEdit::NoWrap);
    ascii->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    ascii->setPlainText(ascii_view(stream.payload));
    views->addTab(ascii, QObject::tr("Payload (ASCII)"));

    auto* hex = new QPlainTextEdit(views);
    hex->setReadOnly(true);
    hex->setLineWrapMode(QPlainTextEdit::NoWrap);
    hex->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    hex->setPlainText(hex_view(stream.payload));
    views->addTab(hex, QObject::tr("Hex"));

    layout->addWidget(views, 1);
    parent->addTab(page, QStringLiteral("%1 · generation %2").arg(direction).arg(static_cast<qulonglong>(generation)));
}

} // namespace

TcpStreamDialog::TcpStreamDialog(const wirescope::TcpConnection& connection,
                                 const std::vector<wirescope::TcpStream>& streams,
                                 QWidget* parent)
    : QDialog(parent) {
    setWindowTitle(tr("Follow TCP stream — %1 ↔ %2")
        .arg(QString::fromStdString(wirescope::endpoint_string(connection.a)))
        .arg(QString::fromStdString(wirescope::endpoint_string(connection.b))));
    resize(1050, 720);

    auto* layout = new QVBoxLayout(this);
    auto* info = new QLabel(
        tr("Connection #%1  ·  %2 packets  ·  %3 bytes  ·  states %4 / %5")
            .arg(static_cast<qulonglong>(connection.id))
            .arg(static_cast<qulonglong>(connection.packets))
            .arg(static_cast<qulonglong>(connection.bytes))
            .arg(QString::fromLatin1(wirescope::tcp_state_name(connection.state_a)))
            .arg(QString::fromLatin1(wirescope::tcp_state_name(connection.state_b))), this);
    info->setWordWrap(true);
    layout->addWidget(info);

    tabs_ = new QTabWidget(this);
    layout->addWidget(tabs_, 1);

    std::size_t a_to_b = 0U;
    std::size_t b_to_a = 0U;
    for (const auto& stream : streams) {
        const bool overlaps_connection = !stream.has_timestamps ||
            (stream.last_seen_us >= connection.first_seen_us &&
             stream.first_seen_us <= connection.last_seen_us);
        if (!overlaps_connection) continue;
        if (stream.source == connection.a && stream.destination == connection.b) {
            ++a_to_b;
            add_stream_page(tabs_, stream,
                QString::fromStdString(wirescope::endpoint_string(connection.a) + " → " +
                                       wirescope::endpoint_string(connection.b)), a_to_b);
        } else if (stream.source == connection.b && stream.destination == connection.a) {
            ++b_to_a;
            add_stream_page(tabs_, stream,
                QString::fromStdString(wirescope::endpoint_string(connection.b) + " → " +
                                       wirescope::endpoint_string(connection.a)), b_to_a);
        }
    }

    if (tabs_->count() == 0) {
        auto* empty = new QLabel(tr("No reassembled payload is available for this connection.\n\nThe capture may contain only handshake/control packets, or the payload may have been lost before capture began."), this);
        empty->setAlignment(Qt::AlignCenter);
        empty->setWordWrap(true);
        tabs_->addTab(empty, tr("No payload"));
    }
}
