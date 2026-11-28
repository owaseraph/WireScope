#pragma once

#include <QByteArray>
#include <QThread>
#include <QString>

#include <atomic>
#include <cstdint>
#include <string>

class CaptureWorker final : public QThread {
    Q_OBJECT
public:
    enum class Mode { OfflineFile, LiveInterface };

    CaptureWorker(Mode mode, std::string source, bool promiscuous, QObject* parent = nullptr);
    void requestStop() noexcept;

signals:
    void packetCaptured(QByteArray bytes, quint64 timestampUs, quint32 wireLength,
                        quint32 linkTypeValue, quint8 linkTypeNamespace,
                        quint16 linuxPacketProtocol);
    void captureCompleted(QString errorMessage);

protected:
    void run() override;

private:
    Mode mode_;
    std::string source_;
    bool promiscuous_{};
    std::atomic_bool stop_requested_{false};
};
