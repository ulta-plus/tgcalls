#ifndef TGCALLS_SOCKS5_UDP_PROTOCOL_H
#define TGCALLS_SOCKS5_UDP_PROTOCOL_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "rtc_base/socket_address.h"

namespace rtc {
class SocketFactory;
} // namespace rtc

namespace tgcalls::socks5 {

size_t WriteUdpHeader(
    const rtc::SocketAddress& address,
    uint8_t* output);
bool ParseUdpHeader(
    const uint8_t* data,
    size_t size,
    rtc::SocketAddress* address,
    size_t* headerSize);
std::vector<uint8_t> AssociateRequest(
    rtc::SocketAddress localAddress,
    const rtc::SocketAddress& proxyAddress);
bool ValidateRelay(
    const rtc::IPAddress& replyAddress,
    uint16_t replyPort,
    const rtc::SocketAddress& proxyAddress,
    rtc::SocketAddress* relayAddress);
bool IsLoopbackRelaySource(
    const rtc::SocketAddress& source,
    const rtc::SocketAddress& proxyAddress);
rtc::SocketFactory* ReflectorRawSocketFactory(
    rtc::SocketFactory* underlying,
    bool proxyRequired);
bool ShouldDisableDirectUdpAndStun(
    bool proxyConfigured,
    bool proxySupportsUdp,
    bool enableP2P);

class ControlWrite final {
 public:
  void Reset(std::vector<uint8_t> bytes);
  const uint8_t* data() const;
  size_t size() const;
  bool Advance(size_t count);
  bool done() const;

 private:
  std::vector<uint8_t> bytes_;
  size_t offset_ = 0;
};

class TerminalGuard final {
 public:
  bool Close(int error);
  bool closed() const;
  int error() const;

 private:
  bool closed_ = false;
  int error_ = 0;
};

} // namespace tgcalls::socks5

#endif // TGCALLS_SOCKS5_UDP_PROTOCOL_H
