#ifndef AUTOSERVERCONTROLLER_H
#define AUTOSERVERCONTROLLER_H

#include <functional>

#include <QElapsedTimer>
#include <QList>
#include <QObject>
#include <QPointer>
#include <QTimer>
#include <QVector>

#include "core/protocols/vpnProtocol.h"
#include "core/utils/errorCodes.h"

class ServersController;
class SecureServersRepository;
class SecureAppSettingsRepository;
class ConnectionController;
class SubscriptionController;
class QNetworkReply;

using namespace amnezia;

// "Auto best server" mode.
//
// On connect it ranks every configured server (self-hosted ones and the current location of each
// Amnezia Premium subscription) by TCP connect latency, then tries them one by one through the
// regular connect path: the candidate becomes the default server and the usual
// prepareConfig -> validate -> openConnection flow runs. A candidate that does not reach Connected
// (a real WireGuard/AWG handshake on every platform) within the timeout is disconnected and the
// next one is tried. The server that works stays the default one.
//
// Other Premium locations are a second tier, tried only when nothing else works: switching a
// location reissues the device key through the gateway, which is slow and rate limited.
class AutoServerController : public QObject
{
    Q_OBJECT

public:
    AutoServerController(ServersController *serversController, SecureServersRepository *serversRepository,
                         SecureAppSettingsRepository *appSettingsRepository, ConnectionController *connectionController,
                         SubscriptionController *subscriptionController, QObject *parent = nullptr);

    bool isEnabled() const;
    bool isRunning() const;

public slots:
    void start();
    void cancel();
    void onConnectionStateChanged(Vpn::ConnectionState state);

signals:
    // asks ConnectionUiController to run the regular connect flow for the current default server
    void connectRequested();
    // emitted once when a run ends; on failure lastError is the error of the last attempt
    void finished(bool success, ErrorCode lastError);

private:
    struct Candidate
    {
        QString serverId;
        QString host;
        QVector<int> ports;
        QString countryCode;  // Premium location to switch to before connecting; empty = keep current
        QString statsCountry; // Premium location the stats belong to (current or target one)
        double rttMs = -1;    // median TCP connect time, -1 = no answer
    };

    enum class Phase { Idle, Closing, Probing, Attempting, WaitingDisconnect, Verifying };

    void beginProbing();
    QList<Candidate> buildCandidates() const;
    QList<Candidate> buildPremiumLocationCandidates() const;
    void probe(QList<Candidate> candidates, int rounds, std::function<void(QList<Candidate>)> done);
    void sortCandidates(QList<Candidate> &candidates) const;

    void attemptNext();
    void onAttemptSucceeded();
    void onAttemptFailed(bool alreadyDisconnected, ErrorCode error);
    void verifyTunnel();
    void finish(bool success, ErrorCode lastError);

    void recordSuccess(const Candidate &candidate, qint64 handshakeMs);
    void recordFailure(const Candidate &candidate);
    void recordAttempt(const Candidate &candidate);
    // in-tunnel latency of the server we just connected to: the main ranking signal for next time,
    // since most AWG servers answer neither TCP nor ICMP before the tunnel is up
    void measureTunnelLatency(const Candidate &candidate);

    ServersController *m_serversController;
    SecureServersRepository *m_serversRepository;
    SecureAppSettingsRepository *m_appSettingsRepository;
    ConnectionController *m_connectionController;
    SubscriptionController *m_subscriptionController;

    Phase m_phase = Phase::Idle;
    QList<Candidate> m_queue;
    QList<Candidate> m_premiumLocations;
    bool m_premiumTierQueued = false;
    int m_countrySwitches = 0;
    Candidate m_current;
    // set once this attempt reached Preparing/Connecting: a late Disconnected left over from closing
    // the previous candidate must not count as a failure of the current one
    bool m_attemptInProgress = false;
    QString m_originalDefaultServerId;
    ErrorCode m_lastError = ErrorCode::NoError;

    QTimer m_handshakeTimer;   // started on Connecting: no handshake in time -> next candidate
    QTimer m_attemptTimer;     // whole attempt incl. config validation (Premium may hit the gateway)
    QTimer m_disconnectTimer;  // fallback if Disconnected never arrives after closeConnection()
    QElapsedTimer m_connectingClock;
    QPointer<QNetworkReply> m_verifyReply;
};

#endif // AUTOSERVERCONTROLLER_H
