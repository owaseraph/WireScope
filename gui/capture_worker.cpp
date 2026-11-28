#include "capture_worker.hpp"

#include "wirescope/pcap_io.hpp"

#include <QString>

#include <utility>

CaptureWorker::CaptureWorker(Mode mode, std::string source, bool promiscuous, QObject* parent)
    : QThread(parent), mode_(mode), source_(std::move(source)), promiscuous_(promiscuous) {}

void CaptureWorker::requestStop() noexcept {
    stop_requested_.store(true, std::memory_order_relaxed);
}

void CaptureWorker::run() {
    std::string error;
    const auto handler = [this](const wirescope::CapturedPacket& packet) {
        if (stop_requested_.load(std::memory_order_relaxed)) return false;
        const auto size = static_cast<qsizetype>(packet.bytes.size());
        const QByteArray bytes(
            reinterpret_cast<const char*>(packet.bytes.data()),
            size
        );
        emit packetCaptured(bytes, static_cast<quint64>(packet.timestamp_us),
                            static_cast<quint32>(packet.wire_length),
                            std::holds_alternative<wirescope::PcapLinkType>(packet.link_type.framing)
                                ? std::get<wirescope::PcapLinkType>(packet.link_type.framing).value
                                : std::get<wirescope::LinuxHardwareType>(packet.link_type.framing).value,
                            static_cast<quint8>(std::holds_alternative<wirescope::PcapLinkType>(packet.link_type.framing)
                                ? 0U : 1U), packet.link_type.linux_protocol.value);
        return !stop_requested_.load(std::memory_order_relaxed);
    };

    bool success = false;
    if (mode_ == Mode::OfflineFile) {
        success = wirescope::read_pcap_file(source_, handler, error);
    } else {
        success = wirescope::capture_live(
            source_, promiscuous_, handler,
            [this] { return stop_requested_.load(std::memory_order_relaxed); },
            error
        );
    }

    emit captureCompleted(success ? QString{} : QString::fromStdString(error));
}
