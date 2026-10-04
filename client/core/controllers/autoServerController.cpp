#include "autoServerController.h"

#include <QDateTime>
#include <QDebug>
#include <QJsonArray>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QSharedPointer>
#include <QTcpSocket>
#include <algorithm>
#include <limits>

#include "amneziaApplication.h"
#include "core/controllers/api/subscriptionController.h"
#include "core/controllers/connectionController.h"
#include "core/controllers/serversController.h"
#include "core/repositories/secureAppSettingsRepository.h"
#include "core/repositories/secureServersRepository.h"
#include "core/utils/containerEnum.h"
#include "core/utils/serverConfigUtils.h"

namespace
{
    constexpr int kProbeTimeoutMs = 1500;
    constexpr int kProbeRounds = 2;
    // WireGuard/AWG report Connected only after a real handshake; it normally takes well under a second
    constexpr int kHandshakeTimeoutMs = 10000;
    // config validation for a Premium server may go through the gateway and its proxy fallbacks
    constexpr int kAttemptTimeoutMs = 45000;
    constexpr int kDisconnectTimeoutMs = 8000;
    constexpr int kVerifyTimeoutMs = 6000;
    // switching a Premium location reissues the device key: keep it rare
    constexpr qint64 kCountrySwitchCooldownMs = 30 * 60 * 1000;
    constexpr int kMaxCountrySwitchesPerRun = 3;
    // a server that failed recently goes behind everything that may still work
    constexpr qint64 kRecentFailureMs = 10 * 60 * 1000;
    const char *kVerifyUrl = "https://www.gstatic.com/generate_204";

    namespace statKey
    {
        const char *okMs = "okMs";
        const char *okAt = "okAt";
        const char *failAt = "failAt";
        const char *fails = "fails";
        const char *triedAt = "triedAt";
        const char *tunnelMs = "tunnelMs";
    }

    constexpr int kTunnelSamples = 3;
    // a server never measured through the tunnel is tried first once a day to learn its latency
    constexpr qint64 kExploreIntervalMs = 24 * 60 * 60 * 1000;

    double median(QVector<double> values)
    {
        if (values.isEmpty()) {
            return -1;
        }
        std::sort(values.begin(), values.end());
        const int mid = values.size() / 2;
        return values.size() % 2 ? values.at(mid) : (values.at(mid - 1) + values.at(mid)) / 2;
    }

    QString statsKey(const QString &serverId, const QString &countryCode)
    {
        return countryCode.isEmpty() ? serverId : serverId + "#" + countryCode;
    }
}

AutoServerController::AutoServerController(ServersController *serversController, SecureServersRepository *serversRepository,
                                           SecureAppSettingsRepository *appSettingsRepository,
                                           ConnectionController *connectionController,
                                           SubscriptionController *subscriptionController, QObject *parent)
    : QObject(parent),
      m_serversController(serversController),
      m_serversRepository(serversRepository),
      m_appSettingsRepository(appSettingsRepository),
      m_connectionController(connectionController),
      m_subscriptionController(subscriptionController)
{
    m_handshakeTimer.setSingleShot(true);
    m_attemptTimer.setSingleShot(true);
    m_disconnectTimer.setSingleShot(true);

    connect(&m_handshakeTimer, &QTimer::timeout, this, [this]() {
        qInfo() << "auto server: no handshake within" << kHandshakeTimeoutMs << "ms on" << m_current.serverId
                << m_current.countryCode;
        onAttemptFailed(false, ErrorCode::NoError);
    });
    connect(&m_attemptTimer, &QTimer::timeout, this, [this]() {
        qInfo() << "auto server: attempt timed out on" << m_current.serverId << m_current.countryCode;
        onAttemptFailed(false, ErrorCode::NoError);
    });
    connect(&m_disconnectTimer, &QTimer::timeout, this, [this]() {
        if (m_phase == Phase::WaitingDisconnect) {
            attemptNext();
        } else if (m_phase == Phase::Closing) {
            beginProbing();
        }
    });

    connect(m_connectionController, &ConnectionController::connectionStateChanged, this,
            &AutoServerController::onConnectionStateChanged);
}

bool AutoServerController::isEnabled() const
{
    return m_appSettingsRepository->isAutoBestServer();
}

bool AutoServerController::isRunning() const
{
    return m_phase != Phase::Idle;
}

void AutoServerController::start()
{
    if (isRunning()) {
        return;
    }

    m_originalDefaultServerId = m_serversController->getDefaultServerId();
    m_lastError = ErrorCode::NoError;
    m_premiumTierQueued = false;
    m_countrySwitches = 0;
    m_queue.clear();
    m_premiumLocations.clear();

    if (buildCandidates().isEmpty()) {
        finish(false, ErrorCode::NoError);
        return;
    }

    // probes through a still running tunnel would measure the wrong path
    if (m_connectionController->isConnected()) {
        m_phase = Phase::Closing;
        m_disconnectTimer.start(kDisconnectTimeoutMs);
        m_connectionController->closeConnection();
        return;
    }
    beginProbing();
}

void AutoServerController::beginProbing()
{
    QList<Candidate> candidates = buildCandidates();
    if (candidates.isEmpty()) {
        finish(false, ErrorCode::NoError);
        return;
    }

    m_phase = Phase::Probing;
    m_connectionController->setConnectionState(Vpn::ConnectionState::Preparing);

    // Premium locations with a host learned on an earlier switch are probed now too, to order the second tier
    QList<Candidate> premium = buildPremiumLocationCandidates();
    const int tierOneCount = candidates.size();
    candidates.append(premium);

    probe(candidates, kProbeRounds, [this, tierOneCount](QList<Candidate> probed) {
        if (m_phase != Phase::Probing) {
            return; // cancelled meanwhile
        }
        QList<Candidate> tierOne = probed.mid(0, tierOneCount);
        m_premiumLocations = probed.mid(tierOneCount);
        sortCandidates(tierOne);
        sortCandidates(m_premiumLocations);
        m_queue = tierOne;

        for (const auto &c : std::as_const(m_queue)) {
            const QJsonObject s = m_appSettingsRepository->autoBestServerStats().value(statsKey(c.serverId, c.statsCountry)).toObject();
            qInfo() << "auto server: candidate" << c.serverId << c.statsCountry << c.host << "tcp" << c.rttMs << "tunnel"
                    << s.value(statKey::tunnelMs).toDouble(-1);
        }
        attemptNext();
    });
}

void AutoServerController::cancel()
{
    if (!isRunning()) {
        return;
    }
    qInfo() << "auto server: cancelled";
    m_handshakeTimer.stop();
    m_attemptTimer.stop();
    m_disconnectTimer.stop();
    if (m_verifyReply) {
        m_verifyReply->abort();
    }
    m_queue.clear();
    m_premiumLocations.clear();
    m_phase = Phase::Idle;
    m_connectionController->closeConnection();
}

QList<AutoServerController::Candidate> AutoServerController::buildCandidates() const
{
    QList<Candidate> candidates;
    for (const QString &serverId : m_serversRepository->orderedServerIds()) {
        if (m_connectionController->isConnectionSupported(serverId) != ErrorCode::NoError) {
            continue;
        }

        Candidate c;
        c.serverId = serverId;
        switch (m_serversRepository->serverKind(serverId)) {
        case serverConfigUtils::ConfigType::SelfHostedAdmin: {
            const auto config = m_serversRepository->selfHostedAdminConfig(serverId);
            if (!config) continue;
            c.host = config->hostName;
            c.ports = { config->credentials().port > 0 ? config->credentials().port : 22, 443 };
            break;
        }
        case serverConfigUtils::ConfigType::SelfHostedUser: {
            const auto config = m_serversRepository->selfHostedUserConfig(serverId);
            if (!config) continue;
            c.host = config->hostName;
            const auto credentials = config->credentials();
            c.ports = { credentials && credentials->port > 0 ? credentials->port : 22, 443 };
            break;
        }
        case serverConfigUtils::ConfigType::Native: {
            const auto config = m_serversRepository->nativeConfig(serverId);
            if (!config) continue;
            c.host = config->hostName;
            c.ports = { 22, 443 };
            break;
        }
        default: {
            const auto config = m_serversRepository->apiV2Config(serverId);
            if (!config) continue; // legacy API configs cannot connect anyway
            c.host = config->hostName; // empty until the first config is fetched; ranked by history then
            c.ports = { 443, 22 };
            c.statsCountry = config->apiConfig.serverCountryCode;
            break;
        }
        }
        candidates.append(c);
    }
    return candidates;
}

QList<AutoServerController::Candidate> AutoServerController::buildPremiumLocationCandidates() const
{
    QList<Candidate> candidates;
    const QJsonObject learnedHosts = m_appSettingsRepository->autoBestServerCountryHosts();

    for (const QString &serverId : m_serversRepository->orderedServerIds()) {
        if (!serverConfigUtils::isApiV2Subscription(m_serversRepository->serverKind(serverId))) {
            continue;
        }
        const auto config = m_serversRepository->apiV2Config(serverId);
        if (!config || !config->isPremium()) {
            continue;
        }

        const QJsonObject hosts = learnedHosts.value(serverId).toObject();
        for (const QJsonValue &value : config->apiConfig.availableCountries) {
            const QString code = value.toObject().value("server_country_code").toString();
            if (code.isEmpty() || code == config->apiConfig.serverCountryCode) {
                continue;
            }
            Candidate c;
            c.serverId = serverId;
            c.countryCode = code;
            c.statsCountry = code;
            c.host = hosts.value(code).toString();
            c.ports = { 443, 22 };
            candidates.append(c);
        }
    }
    return candidates;
}

void AutoServerController::probe(QList<Candidate> candidates, int rounds, std::function<void(QList<Candidate>)> done)
{
    // samples[i] collects one RTT per round for candidate i (min over its ports)
    auto samples = QSharedPointer<QVector<QVector<double>>>::create(candidates.size());
    auto shared = QSharedPointer<QList<Candidate>>::create(candidates);
    auto pending = QSharedPointer<int>::create(0);

    auto finishAll = [shared, samples, done]() {
        for (int i = 0; i < shared->size(); ++i) {
            (*shared)[i].rttMs = median(samples->at(i));
        }
        done(*shared);
    };

    // one round = every (candidate, port) pair in parallel
    // The round function refers to itself only weakly; the sockets of a running round keep it alive,
    // so it is freed as soon as the last round completes.
    auto runRound = QSharedPointer<std::function<void(int)>>::create();
    QWeakPointer<std::function<void(int)>> weakRun = runRound;
    *runRound = [this, shared, samples, pending, rounds, weakRun, finishAll](int round) {
        const auto runRound = weakRun.toStrongRef();
        if (round >= rounds) {
            finishAll();
            return;
        }
        auto best = QSharedPointer<QVector<double>>::create(shared->size(), -1);
        for (int i = 0; i < shared->size(); ++i) {
            const Candidate &c = shared->at(i);
            if (c.host.isEmpty()) {
                continue;
            }
            for (int port : c.ports) {
                ++*pending;
                auto *socket = new QTcpSocket(this);
                auto *clock = new QElapsedTimer();
                auto *timeout = new QTimer(socket);
                timeout->setSingleShot(true);

                auto complete = [=](bool answered) {
                    if (!socket->property("done").toBool()) {
                        socket->setProperty("done", true);
                        const double ms = clock->nsecsElapsed() / 1e6;
                        delete clock;
                        if (answered && ((*best)[i] < 0 || ms < (*best)[i])) {
                            (*best)[i] = ms;
                        }
                        socket->abort();
                        socket->deleteLater();
                        if (--*pending == 0) {
                            for (int j = 0; j < best->size(); ++j) {
                                if (best->at(j) >= 0) {
                                    (*samples)[j].append(best->at(j));
                                }
                            }
                            (*runRound)(round + 1);
                        }
                    }
                };

                // connected or actively refused: both are a full round trip to the host
                connect(socket, &QTcpSocket::connected, socket, [complete]() { complete(true); });
                connect(socket, &QTcpSocket::errorOccurred, socket, [complete](QAbstractSocket::SocketError error) {
                    complete(error == QAbstractSocket::ConnectionRefusedError);
                });
                connect(timeout, &QTimer::timeout, socket, [complete]() { complete(false); });

                clock->start();
                timeout->start(kProbeTimeoutMs);
                socket->connectToHost(c.host, port);
            }
        }
        if (*pending == 0) {
            finishAll(); // nothing to probe at all
        }
    };
    (*runRound)(0);
}

void AutoServerController::sortCandidates(QList<Candidate> &candidates) const
{
    const QJsonObject stats = m_appSettingsRepository->autoBestServerStats();
    const qint64 now = QDateTime::currentMSecsSinceEpoch();
    auto statsOf = [&](const Candidate &c) { return stats.value(statsKey(c.serverId, c.statsCountry)).toObject(); };
    auto msField = [](const QJsonObject &s, const char *key) { return s.value(key).toVariant().toLongLong(); };

    auto recentlyFailed = [&](const Candidate &c) {
        const QJsonObject s = statsOf(c);
        const qint64 failAt = msField(s, statKey::failAt);
        return failAt > msField(s, statKey::okAt) && now - failAt < kRecentFailureMs;
    };
    // never measured through the tunnel and not tried for a while: worth one attempt to learn it
    auto shouldExplore = [&](const Candidate &c) {
        const QJsonObject s = statsOf(c);
        return !s.contains(statKey::tunnelMs) && now - msField(s, statKey::triedAt) > kExploreIntervalMs;
    };
    // lower is better: measured in-tunnel latency, else a rough estimate from the TCP probe
    auto score = [&](const Candidate &c) {
        const QJsonObject s = statsOf(c);
        if (s.contains(statKey::tunnelMs)) {
            return s.value(statKey::tunnelMs).toDouble();
        }
        return c.rttMs >= 0 ? c.rttMs * 3 : std::numeric_limits<double>::infinity();
    };

    std::stable_sort(candidates.begin(), candidates.end(), [&](const Candidate &a, const Candidate &b) {
        const bool aFailed = recentlyFailed(a), bFailed = recentlyFailed(b);
        if (aFailed != bFailed) {
            return !aFailed;
        }
        const bool aExplore = shouldExplore(a), bExplore = shouldExplore(b);
        if (aExplore != bExplore) {
            return aExplore;
        }
        const double sa = score(a), sb = score(b);
        if (sa != sb) {
            return sa < sb;
        }
        // nothing measured at all: most recently working first, then fewest failures
        const QJsonObject ha = statsOf(a), hb = statsOf(b);
        if (msField(ha, statKey::okAt) != msField(hb, statKey::okAt)) {
            return msField(ha, statKey::okAt) > msField(hb, statKey::okAt);
        }
        return ha.value(statKey::fails).toInt() < hb.value(statKey::fails).toInt();
    });
}

void AutoServerController::attemptNext()
{
    m_handshakeTimer.stop();
    m_attemptTimer.stop();
    m_disconnectTimer.stop();

    if (m_queue.isEmpty() && !m_premiumTierQueued) {
        m_premiumTierQueued = true;
        const qint64 sinceSwitch = QDateTime::currentMSecsSinceEpoch() - m_appSettingsRepository->autoBestServerLastCountrySwitch();
        if (!m_premiumLocations.isEmpty() && sinceSwitch > kCountrySwitchCooldownMs) {
            qInfo() << "auto server: trying other Premium locations";
            m_queue = m_premiumLocations.mid(0, kMaxCountrySwitchesPerRun);
        }
    }

    if (m_queue.isEmpty()) {
        finish(false, m_lastError);
        return;
    }

    m_current = m_queue.takeFirst();
    m_phase = Phase::Attempting;
    m_attemptTimer.start(kAttemptTimeoutMs);

    if (!m_current.countryCode.isEmpty()) {
        ++m_countrySwitches;
        m_appSettingsRepository->setAutoBestServerLastCountrySwitch(QDateTime::currentMSecsSinceEpoch());
        // synchronous gateway call (nested event loop), the same one the location picker uses
        const ErrorCode error = m_subscriptionController->updateServiceFromGateway(m_current.serverId, m_current.countryCode, true);
        if (m_phase != Phase::Attempting) {
            return; // cancelled while waiting for the gateway
        }
        if (error != ErrorCode::NoError) {
            qInfo() << "auto server: switching location to" << m_current.countryCode << "failed:" << error;
            m_lastError = error;
            if (error == ErrorCode::ApiCaptchaRequiredError || error == ErrorCode::ApiRateLimitError
                || error == ErrorCode::ApiConfigLimitError || error == ErrorCode::ApiSubscriptionExpiredError) {
                m_queue.erase(std::remove_if(m_queue.begin(), m_queue.end(),
                                             [](const Candidate &c) { return !c.countryCode.isEmpty(); }),
                              m_queue.end());
            }
            recordFailure(m_current);
            attemptNext();
            return;
        }
    }

    qInfo() << "auto server: trying" << m_current.serverId << m_current.host << m_current.countryCode;
    m_attemptInProgress = false;
    recordAttempt(m_current);
    m_serversController->setDefaultServer(m_current.serverId);
    emit connectRequested();
}

void AutoServerController::onConnectionStateChanged(Vpn::ConnectionState state)
{
    switch (m_phase) {
    case Phase::Idle:
    case Phase::Probing:
        return;

    case Phase::Closing:
        if (state == Vpn::ConnectionState::Disconnected) {
            m_disconnectTimer.stop();
            QTimer::singleShot(300, this, [this]() {
                if (m_phase == Phase::Closing) {
                    beginProbing();
                }
            });
        }
        return;

    case Phase::WaitingDisconnect:
        if (state == Vpn::ConnectionState::Disconnected || state == Vpn::ConnectionState::Error
            || state == Vpn::ConnectionState::Unknown) {
            m_disconnectTimer.stop();
            // give the platform a moment to release the tunnel (tun2socks "resource busy", Android service)
            QTimer::singleShot(300, this, [this]() {
                if (m_phase == Phase::WaitingDisconnect) {
                    attemptNext();
                }
            });
        }
        return;

    case Phase::Verifying:
        if (state != Vpn::ConnectionState::Connected) {
            onAttemptFailed(state == Vpn::ConnectionState::Disconnected, ErrorCode::NoError);
        }
        return;

    case Phase::Attempting:
        break;
    }

    switch (state) {
    case Vpn::ConnectionState::Preparing:
        m_attemptInProgress = true;
        break;
    case Vpn::ConnectionState::Connecting:
        m_attemptInProgress = true;
        if (!m_handshakeTimer.isActive()) {
            m_connectingClock.start();
            m_handshakeTimer.start(kHandshakeTimeoutMs);
        }
        break;
    case Vpn::ConnectionState::Connected: {
        m_handshakeTimer.stop();
        m_attemptTimer.stop();
        const DockerContainer container = m_serversController->getDefaultContainer(m_current.serverId);
        if (container == DockerContainer::Xray || container == DockerContainer::SSXray) {
            verifyTunnel(); // Xray reports Connected once the local tunnel is up, not when the server answers
        } else {
            onAttemptSucceeded();
        }
        break;
    }
    case Vpn::ConnectionState::Error:
    case Vpn::ConnectionState::Unknown:
        onAttemptFailed(false, m_connectionController->lastConnectionError());
        break;
    case Vpn::ConnectionState::Disconnected:
        if (m_attemptInProgress) {
            onAttemptFailed(true, m_connectionController->lastConnectionError());
        }
        break;
    default:
        break;
    }
}

void AutoServerController::verifyTunnel()
{
    m_phase = Phase::Verifying;
    QNetworkRequest request { QUrl(kVerifyUrl) };
    request.setTransferTimeout(kVerifyTimeoutMs);
    m_verifyReply = amnApp->networkManager()->get(request);
    connect(m_verifyReply, &QNetworkReply::finished, this, [this, reply = m_verifyReply]() {
        if (!reply) {
            return;
        }
        const bool ok = reply->error() == QNetworkReply::NoError;
        reply->deleteLater();
        if (m_phase != Phase::Verifying) {
            return;
        }
        if (ok) {
            onAttemptSucceeded();
        } else {
            qInfo() << "auto server: tunnel check failed on" << m_current.serverId << reply->errorString();
            onAttemptFailed(false, ErrorCode::NoError);
        }
    });
}

void AutoServerController::onAttemptSucceeded()
{
    const qint64 handshakeMs = m_connectingClock.isValid() ? m_connectingClock.elapsed() : 0;
    qInfo() << "auto server: connected to" << m_current.serverId << m_current.countryCode << "in" << handshakeMs << "ms";
    recordSuccess(m_current, handshakeMs);
    const Candidate connected = m_current;
    finish(true, ErrorCode::NoError);
    measureTunnelLatency(connected);
}

void AutoServerController::onAttemptFailed(bool alreadyDisconnected, ErrorCode error)
{
    if (m_phase != Phase::Attempting && m_phase != Phase::Verifying) {
        return;
    }
    m_handshakeTimer.stop();
    m_attemptTimer.stop();
    if (m_verifyReply) {
        m_verifyReply->abort();
    }
    if (error != ErrorCode::NoError) {
        m_lastError = error;
    }
    recordFailure(m_current);

    m_phase = Phase::WaitingDisconnect;
    if (alreadyDisconnected) {
        QTimer::singleShot(300, this, [this]() {
            if (m_phase == Phase::WaitingDisconnect) {
                attemptNext();
            }
        });
        return;
    }
    // Android ignores a new connect while CONNECTING, so always wait for a full disconnect first
    m_disconnectTimer.start(kDisconnectTimeoutMs);
    m_connectionController->closeConnection();
}

void AutoServerController::finish(bool success, ErrorCode lastError)
{
    m_handshakeTimer.stop();
    m_attemptTimer.stop();
    m_disconnectTimer.stop();
    m_queue.clear();
    m_premiumLocations.clear();
    m_phase = Phase::Idle;

    if (!success) {
        qInfo() << "auto server: no working server found";
        if (!m_originalDefaultServerId.isEmpty() && m_serversController->indexOfServerId(m_originalDefaultServerId) >= 0) {
            m_serversController->setDefaultServer(m_originalDefaultServerId);
        }
        m_connectionController->setConnectionState(Vpn::ConnectionState::Disconnected);
    }
    emit finished(success, lastError);
}

void AutoServerController::recordSuccess(const Candidate &candidate, qint64 handshakeMs)
{
    QJsonObject stats = m_appSettingsRepository->autoBestServerStats();
    const QString key = statsKey(candidate.serverId, candidate.statsCountry);
    QJsonObject s = stats.value(key).toObject();
    s[statKey::okMs] = static_cast<double>(handshakeMs);
    s[statKey::okAt] = static_cast<double>(QDateTime::currentMSecsSinceEpoch());
    s[statKey::fails] = 0;
    stats[key] = s;
    m_appSettingsRepository->setAutoBestServerStats(stats);

    // remember which host this Premium location resolves to, so it can be probed next time
    if (const auto config = m_serversRepository->apiV2Config(candidate.serverId)) {
        const QString code = config->apiConfig.serverCountryCode;
        if (!code.isEmpty() && !config->hostName.isEmpty()) {
            QJsonObject hosts = m_appSettingsRepository->autoBestServerCountryHosts();
            QJsonObject serverHosts = hosts.value(candidate.serverId).toObject();
            serverHosts[code] = config->hostName;
            hosts[candidate.serverId] = serverHosts;
            m_appSettingsRepository->setAutoBestServerCountryHosts(hosts);
        }
    }
}

void AutoServerController::recordFailure(const Candidate &candidate)
{
    QJsonObject stats = m_appSettingsRepository->autoBestServerStats();
    const QString key = statsKey(candidate.serverId, candidate.statsCountry);
    QJsonObject s = stats.value(key).toObject();
    s[statKey::failAt] = static_cast<double>(QDateTime::currentMSecsSinceEpoch());
    s[statKey::fails] = s.value(statKey::fails).toInt() + 1;
    stats[key] = s;
    m_appSettingsRepository->setAutoBestServerStats(stats);
}

void AutoServerController::recordAttempt(const Candidate &candidate)
{
    QJsonObject stats = m_appSettingsRepository->autoBestServerStats();
    const QString key = statsKey(candidate.serverId, candidate.statsCountry);
    QJsonObject s = stats.value(key).toObject();
    s[statKey::triedAt] = static_cast<double>(QDateTime::currentMSecsSinceEpoch());
    stats[key] = s;
    m_appSettingsRepository->setAutoBestServerStats(stats);
}

void AutoServerController::measureTunnelLatency(const Candidate &candidate)
{
    // a few small HTTPS requests through the fresh tunnel; the median is stored as the server's latency
    auto samples = QSharedPointer<QVector<double>>::create();
    auto next = QSharedPointer<std::function<void()>>::create();
    QWeakPointer<std::function<void()>> weakNext = next;
    *next = [this, candidate, samples, weakNext]() {
        const auto self = weakNext.toStrongRef();
        if (samples->size() >= kTunnelSamples || !self) {
            if (samples->isEmpty()) {
                return;
            }
            const double ms = median(*samples);
            QJsonObject stats = m_appSettingsRepository->autoBestServerStats();
            const QString key = statsKey(candidate.serverId, candidate.statsCountry);
            QJsonObject s = stats.value(key).toObject();
            s[statKey::tunnelMs] = ms;
            stats[key] = s;
            m_appSettingsRepository->setAutoBestServerStats(stats);
            qInfo() << "auto server: tunnel latency via" << candidate.serverId << candidate.statsCountry << ms << "ms";
            return;
        }
        QNetworkRequest request { QUrl(kVerifyUrl) };
        request.setTransferTimeout(kVerifyTimeoutMs);
        auto clock = QSharedPointer<QElapsedTimer>::create();
        clock->start();
        QNetworkReply *reply = amnApp->networkManager()->get(request);
        connect(reply, &QNetworkReply::finished, this, [this, reply, clock, samples, self]() {
            reply->deleteLater();
            if (reply->error() != QNetworkReply::NoError || !m_connectionController->isConnected()) {
                return; // not connected any more or no internet: keep whatever was measured before
            }
            samples->append(clock->nsecsElapsed() / 1e6);
            (*self)();
        });
    };
    // let routes and DNS settle first
    QTimer::singleShot(1500, this, [next]() { (*next)(); });
}
