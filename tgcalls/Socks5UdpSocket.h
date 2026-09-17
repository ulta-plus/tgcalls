#ifndef TGCALLS_SOCKS5_UDP_SOCKET_H
#define TGCALLS_SOCKS5_UDP_SOCKET_H

#include <array>
#include <memory>
#include <vector>

#include "api/task_queue/pending_task_safety_flag.h"
#include "Socks5UdpProtocol.h"
#include "rtc_base/async_packet_socket.h"
#include "rtc_base/async_socket.h"
#include "rtc_base/socket_factory.h"

namespace rtc {

class AsyncUDPSocket;

class AsyncSocksProxyUdpSocket final : public AsyncPacketSocket {
 public:
  AsyncSocksProxyUdpSocket(SocketFactory* socket_factory,
                           const SocketAddress& local_bind,
                           const SocketAddress& socks_server);
  ~AsyncSocksProxyUdpSocket() override;

  AsyncSocksProxyUdpSocket(const AsyncSocksProxyUdpSocket&) = delete;
  AsyncSocksProxyUdpSocket& operator=(const AsyncSocksProxyUdpSocket&) = delete;

  bool IsBound() const;

  SocketAddress GetLocalAddress() const override;
  SocketAddress GetRemoteAddress() const override;
  int Send(const void* pv, size_t cb, const PacketOptions& options) override;
  int SendTo(const void* pv,
             size_t cb,
             const SocketAddress& addr,
             const PacketOptions& options) override;
  int Close() override;
  State GetState() const override;
  int GetOption(Socket::Option opt, int* value) override;
  int SetOption(Socket::Option opt, int value) override;
  int GetError() const override;
  void SetError(int error) override;

 private:
  enum class Stage {
    Connecting,
    GreetingWrite,
    GreetingReply,
    AssociateWrite,
    AssociateReply,
    PendingReady,
    Ready,
    Closed,
  };

  void OnControlConnect(Socket* socket);
  void OnControlRead(Socket* socket);
  void OnControlWrite(Socket* socket);
  void OnControlClose(Socket* socket, int error);
  void OnUdpPacket(AsyncPacketSocket* socket, const ReceivedPacket& packet);
  void OnUdpSent(AsyncPacketSocket* socket, const SentPacket& packet);
  void OnUdpReady(AsyncPacketSocket* socket);
  void OnUdpClose(AsyncPacketSocket* socket, int error);
  void StartGreeting();
  void StartAssociate();
  void FlushControlWrite();
  void ParseControlRead();
  bool HandleHelloReply();
  bool HandleAssociateReply();
  void DisconnectSignals();
  void Fail(int error);

  std::unique_ptr<Socket> control_;
  std::unique_ptr<AsyncUDPSocket> udp_;
  SocketAddress socks_server_;
  SocketAddress udp_relay_;
  std::array<uint8_t, 512> control_read_ = {};
  size_t control_read_size_ = 0;
  tgcalls::socks5::ControlWrite control_write_;
  tgcalls::socks5::TerminalGuard terminal_;
  Stage stage_ = Stage::Connecting;
  int error_ = 0;
  webrtc::ScopedTaskSafety task_safety_;
};

} // namespace rtc

#endif // TGCALLS_SOCKS5_UDP_SOCKET_H
