#include "Socks5UdpSocket.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <vector>

#include "rtc_base/ip_address.h"
#include "rtc_base/physical_socket_server.h"
#include "rtc_base/socket.h"
#include "rtc_base/socket_server.h"
#include "rtc_base/thread.h"

namespace {

rtc::SocketAddress LoopbackAddress(uint16_t port) {
  auto ip = rtc::IPAddress();
  if (!rtc::IPFromString("127.0.0.1", &ip)) {
    return rtc::SocketAddress();
  }
  return rtc::SocketAddress(ip, port);
}

class LoopbackSocksServer final : public sigslot::has_slots<> {
 public:
  explicit LoopbackSocksServer(rtc::SocketFactory* socket_factory) {
    listener_.reset(socket_factory->CreateSocket(AF_INET, SOCK_STREAM));
    if (!listener_
        || listener_->Bind(LoopbackAddress(0)) != 0
        || listener_->Listen(1) != 0) {
      return;
    }
    listener_->SignalReadEvent.connect(
        this, &LoopbackSocksServer::OnAccept);
    started_ = true;
  }

  bool started() const {
    return started_;
  }

  rtc::SocketAddress address() const {
    return listener_ ? listener_->GetLocalAddress() : rtc::SocketAddress();
  }

  bool associate_received() const {
    return associate_received_;
  }

  bool failed() const {
    return failed_;
  }

  void SendAssociateSuccess() {
    const auto port = address().port();
    Send({
        0x05,
        0x00,
        0x00,
        0x01,
        127,
        0,
        0,
        1,
        static_cast<uint8_t>(port >> 8),
        static_cast<uint8_t>(port),
    });
  }

  void SendAssociateRejection() {
    const auto port = address().port();
    Send({
        0x05,
        0x05,
        0x00,
        0x01,
        127,
        0,
        0,
        1,
        static_cast<uint8_t>(port >> 8),
        static_cast<uint8_t>(port),
    });
  }

 private:
  enum class Stage {
    Greeting,
    Associate,
    Done,
  };

  void OnAccept(rtc::Socket*) {
    auto peer = rtc::SocketAddress();
    client_.reset(listener_->Accept(&peer));
    if (!client_) {
      failed_ = true;
      return;
    }
    client_->SignalReadEvent.connect(this, &LoopbackSocksServer::OnRead);
    OnRead(client_.get());
  }

  void OnRead(rtc::Socket*) {
    uint8_t bytes[64] = {};
    while (true) {
      const auto received = client_->Recv(bytes, sizeof(bytes), nullptr);
      if (received > 0) {
        input_.insert(input_.end(), bytes, bytes + received);
        continue;
      }
      if (received < 0 && client_->GetError() != EWOULDBLOCK) {
        failed_ = true;
      }
      break;
    }
    Parse();
  }

  void Parse() {
    if (stage_ == Stage::Greeting && input_.size() >= 3) {
      if (input_[0] != 0x05 || input_[1] != 0x01 || input_[2] != 0x00) {
        failed_ = true;
        return;
      }
      input_.erase(input_.begin(), input_.begin() + 3);
      stage_ = Stage::Associate;
      Send({ 0x05, 0x00 });
    }
    if (stage_ == Stage::Associate && input_.size() >= 10) {
      if (input_[0] != 0x05 || input_[1] != 0x03 || input_[3] != 0x01) {
        failed_ = true;
        return;
      }
      input_.erase(input_.begin(), input_.begin() + 10);
      associate_received_ = true;
      stage_ = Stage::Done;
    }
  }

  void Send(std::vector<uint8_t> bytes) {
    if (!client_ || client_->Send(bytes.data(), bytes.size())
        != static_cast<int>(bytes.size())) {
      failed_ = true;
    }
  }

  std::unique_ptr<rtc::Socket> listener_;
  std::unique_ptr<rtc::Socket> client_;
  std::vector<uint8_t> input_;
  Stage stage_ = Stage::Greeting;
  bool started_ = false;
  bool associate_received_ = false;
  bool failed_ = false;
};

class UdpPortStyleConsumer final : public sigslot::has_slots<> {
 public:
  explicit UdpPortStyleConsumer(rtc::AsyncPacketSocket* socket)
      : socket_(socket) {
    socket_->SignalAddressReady.connect(
        this, &UdpPortStyleConsumer::OnLocalAddressReady);
    socket_->SignalReadyToSend.connect(
        this, &UdpPortStyleConsumer::OnReadyToSend);
  }

  void PrepareAddress() {
    if (socket_->GetState() == rtc::AsyncPacketSocket::STATE_BOUND) {
      OnLocalAddressReady(socket_, socket_->GetLocalAddress());
    }
  }

  void close_from_address_ready() {
    close_from_address_ready_ = true;
  }

  int address_ready_count() const {
    return address_ready_count_;
  }

  int ready_to_send_count() const {
    return ready_to_send_count_;
  }

  bool duplicate_preparation() const {
    return duplicate_preparation_;
  }

  bool address_ready_was_bound() const {
    return address_ready_was_bound_;
  }

 private:
  void OnLocalAddressReady(
      rtc::AsyncPacketSocket*,
      const rtc::SocketAddress&) {
    ++address_ready_count_;
    address_ready_was_bound_ =
        socket_->GetState() == rtc::AsyncPacketSocket::STATE_BOUND;
    if (request_pending_) {
      duplicate_preparation_ = true;
    }
    request_pending_ = true;
    if (close_from_address_ready_) {
      socket_->Close();
    }
  }

  void OnReadyToSend(rtc::AsyncPacketSocket*) {
    ++ready_to_send_count_;
  }

  rtc::AsyncPacketSocket* socket_;
  int address_ready_count_ = 0;
  int ready_to_send_count_ = 0;
  bool request_pending_ = false;
  bool duplicate_preparation_ = false;
  bool address_ready_was_bound_ = false;
  bool close_from_address_ready_ = false;
};

class Harness final {
 public:
  Harness()
      : socket_server_(std::make_unique<rtc::PhysicalSocketServer>()),
        thread_(socket_server_.get()),
        server_(socket_server_.get()),
        socket_(std::make_unique<rtc::AsyncSocksProxyUdpSocket>(
            socket_server_.get(),
            LoopbackAddress(0),
            server_.address())),
        consumer_(socket_.get()) {
    consumer_.PrepareAddress();
  }

  ~Harness() {
    socket_->Close();
    thread_.ProcessMessages(1);
  }

  bool PumpUntil(const std::function<bool()>& condition, int timeout_ms = 500) {
    const auto deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(timeout_ms);
    while (!condition() && std::chrono::steady_clock::now() < deadline) {
      thread_.ProcessMessages(1);
    }
    return condition();
  }

  void PumpFor(int duration_ms) {
    const auto deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(duration_ms);
    while (std::chrono::steady_clock::now() < deadline) {
      thread_.ProcessMessages(1);
    }
  }

  std::unique_ptr<rtc::SocketServer> socket_server_;
  rtc::AutoSocketServerThread thread_;
  LoopbackSocksServer server_;
  std::unique_ptr<rtc::AsyncSocksProxyUdpSocket> socket_;
  UdpPortStyleConsumer consumer_;
};

bool Check(bool value, const char* test, const char* expectation) {
  if (!value) {
    std::fprintf(stderr, "FAILED: %s: %s\n", test, expectation);
  }
  return value;
}

bool ReportsBindingBeforeSuccessfulHandshakeCompletes() {
  constexpr auto test = "reports binding before successful handshake completes";
  auto harness = Harness();
  auto passed = Check(harness.server_.started(), test, "server starts");
  passed &= Check(
      harness.PumpUntil([&] { return harness.server_.associate_received(); }),
      test,
      "adapter sends UDP ASSOCIATE");
  passed &= Check(!harness.server_.failed(), test, "SOCKS handshake is valid");
  passed &= Check(
      harness.socket_->GetState() == rtc::AsyncPacketSocket::STATE_BINDING,
      test,
      "GetState remains STATE_BINDING while ASSOCIATE reply is withheld");
  return passed;
}

bool EmitsAddressReadyExactlyOnceAfterBecomingBound() {
  constexpr auto test = "emits address ready exactly once after becoming bound";
  auto harness = Harness();
  auto passed = Check(
      harness.PumpUntil([&] { return harness.server_.associate_received(); }),
      test,
      "adapter sends UDP ASSOCIATE");
  harness.server_.SendAssociateSuccess();
  passed &= Check(
      harness.PumpUntil([&] {
        return harness.consumer_.address_ready_count() == 1;
      }),
      test,
      "SignalAddressReady is emitted");
  harness.PumpFor(20);
  passed &= Check(
      harness.consumer_.address_ready_count() == 1,
      test,
      "SignalAddressReady is emitted once");
  passed &= Check(
      harness.consumer_.address_ready_was_bound(),
      test,
      "GetState is STATE_BOUND inside SignalAddressReady");
  return passed;
}

bool DoesNotRepeatUdpPortStylePreparation() {
  constexpr auto test = "does not repeat UDPPort-style preparation";
  auto harness = Harness();
  auto passed = Check(
      harness.PumpUntil([&] { return harness.server_.associate_received(); }),
      test,
      "adapter sends UDP ASSOCIATE");
  harness.server_.SendAssociateSuccess();
  passed &= Check(
      harness.PumpUntil([&] {
        return harness.consumer_.address_ready_count() == 1;
      }),
      test,
      "consumer prepares its address");
  harness.PumpFor(20);
  passed &= Check(
      !harness.consumer_.duplicate_preparation(),
      test,
      "PrepareAddress and SignalAddressReady do not both prepare requests");
  return passed;
}

bool RejectedHandshakeClosesWithoutReadySignals() {
  constexpr auto test = "rejected handshake closes without ready signals";
  auto harness = Harness();
  auto passed = Check(
      harness.PumpUntil([&] { return harness.server_.associate_received(); }),
      test,
      "adapter sends UDP ASSOCIATE");
  harness.server_.SendAssociateRejection();
  passed &= Check(
      harness.PumpUntil([&] {
        return harness.socket_->GetState()
            == rtc::AsyncPacketSocket::STATE_CLOSED;
      }),
      test,
      "rejected ASSOCIATE closes the adapter");
  passed &= Check(
      harness.consumer_.address_ready_count() == 0,
      test,
      "SignalAddressReady is not emitted");
  passed &= Check(
      harness.consumer_.ready_to_send_count() == 0,
      test,
      "SignalReadyToSend is not emitted");
  return passed;
}

bool CloseBeforeAssociateReplySuppressesReadySignals() {
  constexpr auto test = "close before ASSOCIATE reply suppresses ready signals";
  auto harness = Harness();
  auto passed = Check(
      harness.PumpUntil([&] { return harness.server_.associate_received(); }),
      test,
      "adapter sends UDP ASSOCIATE");
  harness.socket_->Close();
  harness.server_.SendAssociateSuccess();
  harness.PumpFor(20);
  passed &= Check(
      harness.consumer_.address_ready_count() == 0,
      test,
      "SignalAddressReady is not emitted after close");
  passed &= Check(
      harness.consumer_.ready_to_send_count() == 0,
      test,
      "SignalReadyToSend is not emitted after close");
  return passed;
}

bool CloseFromAddressReadySuppressesReadyToSend() {
  constexpr auto test = "close from address ready suppresses ready to send";
  auto harness = Harness();
  auto passed = Check(
      harness.PumpUntil([&] { return harness.server_.associate_received(); }),
      test,
      "adapter sends UDP ASSOCIATE");
  harness.consumer_.close_from_address_ready();
  harness.server_.SendAssociateSuccess();
  passed &= Check(
      harness.PumpUntil([&] {
        return harness.consumer_.address_ready_count() == 1;
      }),
      test,
      "SignalAddressReady is emitted");
  harness.PumpFor(20);
  passed &= Check(
      harness.socket_->GetState() == rtc::AsyncPacketSocket::STATE_CLOSED,
      test,
      "callback closes the adapter");
  passed &= Check(
      harness.consumer_.ready_to_send_count() == 0,
      test,
      "SignalReadyToSend is suppressed after callback closes adapter");
  return passed;
}

} // namespace

int main() {
#if defined(WEBRTC_WIN)
  WSADATA socket_data = {};
  if (WSAStartup(MAKEWORD(2, 2), &socket_data) != 0) {
    std::fprintf(stderr, "FAILED: Winsock initialization\n");
    return 1;
  }
#endif
  auto passed = true;
  passed &= ReportsBindingBeforeSuccessfulHandshakeCompletes();
  passed &= EmitsAddressReadyExactlyOnceAfterBecomingBound();
  passed &= DoesNotRepeatUdpPortStylePreparation();
  passed &= RejectedHandshakeClosesWithoutReadySignals();
  passed &= CloseBeforeAssociateReplySuppressesReadySignals();
  passed &= CloseFromAddressReadySuppressesReadyToSend();
#if defined(WEBRTC_WIN)
  WSACleanup();
#endif
  return passed ? 0 : 1;
}
