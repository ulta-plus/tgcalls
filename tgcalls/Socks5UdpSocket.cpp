#include "Socks5UdpSocket.h"

#include "Socks5UdpProtocol.h"

#include <algorithm>

#include "rtc_base/async_udp_socket.h"
#include "rtc_base/byte_order.h"
#include "rtc_base/ip_address.h"
#include "rtc_base/logging.h"
#include "rtc_base/thread.h"
#include "api/units/time_delta.h"

namespace rtc {

AsyncSocksProxyUdpSocket::AsyncSocksProxyUdpSocket(
    SocketFactory* socket_factory,
    const SocketAddress& local_bind,
    const SocketAddress& socks_server)
    : socks_server_(socks_server) {
  if (local_bind.family() != socks_server_.family()) {
    stage_ = Stage::Closed;
    error_ = EAFNOSUPPORT;
    return;
  }
  auto raw_udp = socket_factory->CreateSocket(local_bind.family(), SOCK_DGRAM);
  if (!raw_udp) {
    stage_ = Stage::Closed;
    error_ = EIO;
    return;
  }
  udp_.reset(AsyncUDPSocket::Create(raw_udp, SocketAddress(GetAnyIP(local_bind.family()), 0)));
  if (!udp_) {
    stage_ = Stage::Closed;
    error_ = EIO;
    return;
  }
  udp_->RegisterReceivedPacketCallback(
      [this](AsyncPacketSocket* socket, const ReceivedPacket& packet) {
        OnUdpPacket(socket, packet);
      });
  udp_->SignalSentPacket.connect(this, &AsyncSocksProxyUdpSocket::OnUdpSent);
  udp_->SignalReadyToSend.connect(this, &AsyncSocksProxyUdpSocket::OnUdpReady);
  udp_->SubscribeCloseEvent(this, [this](AsyncPacketSocket* socket, int error) {
    OnUdpClose(socket, error);
  });

  control_.reset(
      socket_factory->CreateSocket(socks_server_.family(), SOCK_STREAM));
  if (!control_) {
    stage_ = Stage::Closed;
    error_ = EIO;
    return;
  }
  control_->SignalConnectEvent.connect(
      this, &AsyncSocksProxyUdpSocket::OnControlConnect);
  control_->SignalReadEvent.connect(
      this, &AsyncSocksProxyUdpSocket::OnControlRead);
  control_->SignalWriteEvent.connect(
      this, &AsyncSocksProxyUdpSocket::OnControlWrite);
  control_->SignalCloseEvent.connect(
      this, &AsyncSocksProxyUdpSocket::OnControlClose);

  const auto result = control_->Connect(socks_server_);
  if (result < 0
      && control_->GetError() != EINPROGRESS
      && control_->GetError() != EWOULDBLOCK
      && control_->GetError() != 0) {
    error_ = control_->GetError();
    stage_ = Stage::Closed;
    return;
  }
  // Some socket implementations complete Connect synchronously and do not
  // emit SignalConnectEvent afterwards. Start the handshake in that case,
  // while keeping the guard re-entrancy-safe for implementations that do.
  if (result == 0 && stage_ == Stage::Connecting) {
    StartGreeting();
  }
  const auto thread = Thread::Current();
  if (!thread) {
    Fail(EINVAL);
    return;
  }
  thread->PostDelayedTask(
      webrtc::SafeTask(task_safety_.flag(), [this] {
        if (stage_ != Stage::Ready && stage_ != Stage::Closed) {
          Fail(ETIMEDOUT);
        }
      }),
      webrtc::TimeDelta::Seconds(10));
}

AsyncSocksProxyUdpSocket::~AsyncSocksProxyUdpSocket() {
  task_safety_.flag()->SetNotAlive();
  DisconnectSignals();
}

bool AsyncSocksProxyUdpSocket::IsBound() const {
  return udp_ && stage_ != Stage::Closed;
}

SocketAddress AsyncSocksProxyUdpSocket::GetLocalAddress() const {
  return udp_ ? udp_->GetLocalAddress() : SocketAddress();
}

SocketAddress AsyncSocksProxyUdpSocket::GetRemoteAddress() const {
  return SocketAddress();
}

int AsyncSocksProxyUdpSocket::Send(const void*, size_t, const PacketOptions&) {
  SetError(ENOTCONN);
  return -1;
}

int AsyncSocksProxyUdpSocket::SendTo(
    const void* data,
    size_t size,
    const SocketAddress& address,
    const PacketOptions& options) {
  if (stage_ != Stage::Ready || !udp_) {
    SetError(stage_ == Stage::Closed ? ENOTCONN : EWOULDBLOCK);
    return -1;
  }
  constexpr auto kHeaderMax = size_t(22);
  constexpr auto kMaxPayload = size_t(65507 - 22);
  if (size > kMaxPayload) {
    SetError(EMSGSIZE);
    return -1;
  }
  auto buffer = std::vector<uint8_t>(size + kHeaderMax);
  const auto header = tgcalls::socks5::WriteUdpHeader(address, buffer.data());
  if (!header) {
    SetError(EAFNOSUPPORT);
    return -1;
  }
  memcpy(buffer.data() + header, data, size);
  const auto sent = udp_->SendTo(
      buffer.data(), header + size, udp_relay_, options);
  if (sent < 0) {
    error_ = udp_->GetError();
    return sent;
  }
  return (sent >= static_cast<int>(header))
      ? (sent - static_cast<int>(header))
      : 0;
}

int AsyncSocksProxyUdpSocket::Close() {
  if (stage_ == Stage::Closed) {
    return 0;
  }
  stage_ = Stage::Closed;
  task_safety_.flag()->SetNotAlive();
  DisconnectSignals();
  if (control_) {
    control_->Close();
  }
  return udp_ ? udp_->Close() : 0;
}

AsyncPacketSocket::State AsyncSocksProxyUdpSocket::GetState() const {
  if (!udp_ || stage_ == Stage::Closed) {
    return STATE_CLOSED;
  }
  return stage_ == Stage::Ready ? STATE_BOUND : STATE_BINDING;
}

int AsyncSocksProxyUdpSocket::GetOption(Socket::Option option, int* value) {
  return udp_ ? udp_->GetOption(option, value) : -1;
}

int AsyncSocksProxyUdpSocket::SetOption(Socket::Option option, int value) {
  return udp_ ? udp_->SetOption(option, value) : -1;
}

int AsyncSocksProxyUdpSocket::GetError() const {
  return error_;
}

void AsyncSocksProxyUdpSocket::SetError(int error) {
  error_ = error;
  if (udp_) {
    udp_->SetError(error);
  }
}

void AsyncSocksProxyUdpSocket::OnControlConnect(Socket*) {
  if (stage_ == Stage::Connecting) {
    StartGreeting();
  }
}

void AsyncSocksProxyUdpSocket::OnControlWrite(Socket*) {
  FlushControlWrite();
}

void AsyncSocksProxyUdpSocket::StartGreeting() {
  stage_ = Stage::GreetingWrite;
  control_write_.Reset({ 0x05, 0x01, 0x00 });
  FlushControlWrite();
}

void AsyncSocksProxyUdpSocket::StartAssociate() {
  auto local = GetLocalAddress();
  if (!local.port()) {
    Fail(EADDRNOTAVAIL);
    return;
  }
  if (local.IsAnyIP()) {
    local.SetIP(socks_server_.ipaddr());
  }
  auto request = tgcalls::socks5::AssociateRequest(local, socks_server_);
  if (request.empty()) {
    Fail(EAFNOSUPPORT);
    return;
  }
  stage_ = Stage::AssociateWrite;
  control_write_.Reset(std::move(request));
  FlushControlWrite();
}

void AsyncSocksProxyUdpSocket::FlushControlWrite() {
  while (stage_ != Stage::Closed && !control_write_.done()) {
    const auto sent = control_->Send(
        control_write_.data(), control_write_.size());
    if (sent > 0) {
      control_write_.Advance(static_cast<size_t>(sent));
      continue;
    }
    const auto error = control_->GetError();
    if (sent < 0 && (error == EWOULDBLOCK || error == EINPROGRESS)) {
      return;
    }
    Fail(error);
    return;
  }
  if (stage_ == Stage::GreetingWrite) {
    stage_ = Stage::GreetingReply;
  } else if (stage_ == Stage::AssociateWrite) {
    stage_ = Stage::AssociateReply;
  }
  ParseControlRead();
}

void AsyncSocksProxyUdpSocket::OnControlRead(Socket*) {
  if (stage_ == Stage::Closed) {
    return;
  }
  while (control_read_size_ < control_read_.size()) {
    const auto received = control_->Recv(
        control_read_.data() + control_read_size_,
        control_read_.size() - control_read_size_,
        nullptr);
    if (received > 0) {
      control_read_size_ += static_cast<size_t>(received);
      continue;
    }
    const auto error = control_->GetError();
    if (received < 0 && error != EWOULDBLOCK) {
      Fail(error);
      return;
    }
    break;
  }
  if (control_read_size_ == control_read_.size()) {
    Fail(EOVERFLOW);
    return;
  }
  ParseControlRead();
}

void AsyncSocksProxyUdpSocket::ParseControlRead() {
  auto parsing = true;
  while (parsing) {
    if (stage_ == Stage::GreetingReply) {
      parsing = HandleHelloReply();
    } else if (stage_ == Stage::AssociateReply) {
      parsing = HandleAssociateReply();
    } else {
      parsing = false;
    }
  }
}

bool AsyncSocksProxyUdpSocket::HandleHelloReply() {
  if (control_read_size_ < 2) {
    return false;
  }
  if (control_read_[0] != 0x05 || control_read_[1] != 0x00) {
    Fail(EPROTO);
    return false;
  }
  control_read_size_ -= 2;
  if (control_read_size_) {
    memmove(control_read_.data(), control_read_.data() + 2, control_read_size_);
  }
  StartAssociate();
  return stage_ == Stage::AssociateReply && control_read_size_;
}

bool AsyncSocksProxyUdpSocket::HandleAssociateReply() {
  if (control_read_size_ < 5) return false;
  if (control_read_[0] != 0x05 || control_read_[2] != 0x00) {
    RTC_LOG(LS_WARNING) << "AsyncSocksProxyUdpSocket: malformed ASSOCIATE reply";
    Fail(EPROTO);
    return false;
  }
  if (control_read_[1] != 0x00) {
    RTC_LOG(LS_WARNING) << "AsyncSocksProxyUdpSocket: ASSOCIATE rejected, REP="
                        << static_cast<int>(control_read_[1]);
    Fail(EHOSTUNREACH);
    return false;
  }
  uint8_t atyp = control_read_[3];
  size_t addr_off = 4;
  size_t addr_len;
  IPAddress ip;
  switch (atyp) {
    case 0x01:
      addr_len = 4;
      if (control_read_size_ < addr_off + addr_len + 2) return false;
      {
        in_addr v4;
        memcpy(&v4.s_addr, control_read_.data() + addr_off, 4);
        ip = IPAddress(v4);
      }
      break;
    case 0x04:
      addr_len = 16;
      if (control_read_size_ < addr_off + addr_len + 2) return false;
      {
        in6_addr v6;
        memcpy(&v6.s6_addr, control_read_.data() + addr_off, 16);
        ip = IPAddress(v6);
      }
      break;
    default:
      RTC_LOG(LS_WARNING)
          << "AsyncSocksProxyUdpSocket: unexpected ATYP in ASSOCIATE reply: "
          << static_cast<int>(atyp);
      Fail(EPROTO);
      return false;
  }
  uint16_t port_be;
  memcpy(&port_be, control_read_.data() + addr_off + addr_len, 2);
  uint16_t port = NetworkToHost16(port_be);

  if (!tgcalls::socks5::ValidateRelay(
          ip, port, socks_server_, &udp_relay_)) {
    Fail(EPROTO);
    return false;
  }

  size_t consumed = addr_off + addr_len + 2;
  control_read_size_ -= consumed;
  if (control_read_size_) {
    memmove(
        control_read_.data(),
        control_read_.data() + consumed,
        control_read_size_);
  }

  // UDPPort prepares synchronously when GetState() reports STATE_BOUND.
  // Keep the socket binding until the queued notification is delivered,
  // otherwise PrepareAddress and SignalAddressReady both start STUN requests.
  // Closing while this task is pending must never publish a ready address.
  stage_ = Stage::PendingReady;
  RTC_LOG(LS_INFO) << "AsyncSocksProxyUdpSocket: relay ready at "
                   << udp_relay_.ToSensitiveString();
  const auto safety = task_safety_.flag();
  Thread::Current()->PostTask(
      webrtc::SafeTask(safety, [this, safety] {
        if (stage_ == Stage::PendingReady) {
          stage_ = Stage::Ready;
          SignalAddressReady(this, GetLocalAddress());
          if (safety->alive() && stage_ == Stage::Ready) {
            SignalReadyToSend(this);
          }
        }
      }));
  return false;
}

void AsyncSocksProxyUdpSocket::OnControlClose(Socket*, int error) {
  Fail(error ? error : ECONNRESET);
}

void AsyncSocksProxyUdpSocket::OnUdpPacket(
    AsyncPacketSocket*,
    const ReceivedPacket& packet) {
  if (stage_ != Stage::Ready
      || !tgcalls::socks5::IsLoopbackRelaySource(
          packet.source_address(), socks_server_)) {
    return;
  }
  auto source = SocketAddress();
  auto header = size_t(0);
  if (!tgcalls::socks5::ParseUdpHeader(
          packet.payload().data(), packet.payload().size(), &source, &header)) {
    Fail(EPROTO);
    return;
  }
  NotifyPacketReceived(ReceivedPacket(
      packet.payload().subview(header), source, packet.arrival_time()));
}

void AsyncSocksProxyUdpSocket::OnUdpSent(
    AsyncPacketSocket*,
    const SentPacket& packet) {
  if (stage_ == Stage::Ready) {
    SignalSentPacket(this, packet);
  }
}

void AsyncSocksProxyUdpSocket::OnUdpReady(AsyncPacketSocket*) {
  if (stage_ == Stage::Ready) {
    SignalReadyToSend(this);
  }
}

void AsyncSocksProxyUdpSocket::OnUdpClose(AsyncPacketSocket*, int error) {
  Fail(error ? error : ECONNRESET);
}

void AsyncSocksProxyUdpSocket::DisconnectSignals() {
  if (control_) {
    control_->SignalConnectEvent.disconnect(this);
    control_->SignalReadEvent.disconnect(this);
    control_->SignalWriteEvent.disconnect(this);
    control_->SignalCloseEvent.disconnect(this);
  }
  if (udp_) {
    udp_->DeregisterReceivedPacketCallback();
    udp_->SignalSentPacket.disconnect(this);
    udp_->SignalReadyToSend.disconnect(this);
    udp_->UnsubscribeCloseEvent(this);
  }
}

void AsyncSocksProxyUdpSocket::Fail(int error) {
  const auto actualError = error ? error : EPROTO;
  if (!terminal_.Close(actualError)) {
    return;
  }
  error_ = actualError;
  stage_ = Stage::Closed;
  task_safety_.flag()->SetNotAlive();
  DisconnectSignals();
  if (control_) {
    control_->Close();
  }
  if (udp_) {
    udp_->Close();
  }
  NotifyClosed(error_);
}

} // namespace rtc
