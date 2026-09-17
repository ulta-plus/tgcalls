#include "Socks5UdpProtocol.h"

#include <algorithm>
#include <cstring>

#include "rtc_base/byte_order.h"
#include "rtc_base/ip_address.h"

namespace tgcalls::socks5 {

size_t WriteUdpHeader(
    const rtc::SocketAddress& address,
    uint8_t* output) {
  if (!address.port() || address.IsUnresolvedIP()) {
    return 0;
  }
  auto size = size_t(0);
  output[size++] = 0;
  output[size++] = 0;
  output[size++] = 0;
  const auto& ip = address.ipaddr();
  if (ip.family() == AF_INET) {
    output[size++] = 1;
    const auto ipv4 = ip.ipv4_address();
    memcpy(output + size, &ipv4.s_addr, 4);
    size += 4;
  } else if (ip.family() == AF_INET6) {
    output[size++] = 4;
    const auto ipv6 = ip.ipv6_address();
    memcpy(output + size, &ipv6.s6_addr, 16);
    size += 16;
  } else {
    return 0;
  }
  const auto port = rtc::HostToNetwork16(address.port());
  memcpy(output + size, &port, 2);
  return size + 2;
}

bool ParseUdpHeader(
    const uint8_t* data,
    size_t size,
    rtc::SocketAddress* address,
    size_t* headerSize) {
  if (size < 4 || data[0] || data[1] || data[2]) {
    return false;
  }
  const auto addressSize = (data[3] == 1)
      ? size_t(4)
      : (data[3] == 4)
      ? size_t(16)
      : size_t(0);
  if (!addressSize || size < 4 + addressSize + 2) {
    return false;
  }
  auto ip = rtc::IPAddress();
  if (addressSize == 4) {
    auto ipv4 = in_addr();
    memcpy(&ipv4.s_addr, data + 4, 4);
    ip = rtc::IPAddress(ipv4);
  } else {
    auto ipv6 = in6_addr();
    memcpy(&ipv6.s6_addr, data + 4, 16);
    ip = rtc::IPAddress(ipv6);
  }
  auto port = uint16_t();
  memcpy(&port, data + 4 + addressSize, 2);
  port = rtc::NetworkToHost16(port);
  if (!port) {
    return false;
  }
  *address = rtc::SocketAddress(ip, port);
  *headerSize = 4 + addressSize + 2;
  return true;
}

std::vector<uint8_t> AssociateRequest(
    rtc::SocketAddress localAddress,
    const rtc::SocketAddress& proxyAddress) {
  if (!localAddress.port()) {
    return {};
  }
  if (localAddress.IsAnyIP()) {
    localAddress.SetIP(proxyAddress.ipaddr());
  }
  auto result = std::vector<uint8_t>(22);
  const auto size = WriteUdpHeader(localAddress, result.data());
  if (!size) {
    return {};
  }
  result.resize(size);
  result[0] = 5;
  result[1] = 3;
  return result;
}

bool ValidateRelay(
    const rtc::IPAddress& replyAddress,
    uint16_t replyPort,
    const rtc::SocketAddress& proxyAddress,
    rtc::SocketAddress* relayAddress) {
  if (!replyPort) {
    return false;
  }
  // Some SOCKS5 helpers return a wildcard relay address (0.0.0.0 or ::).
  // It means "use the relay bound to this control endpoint", not a remote
  // destination. Normalize it to the proxy address family before sending.
  const auto address = replyAddress.IsNil() || rtc::IPIsAny(replyAddress)
      ? proxyAddress.ipaddr()
      : replyAddress;
  const auto relay = rtc::SocketAddress(address, replyPort);
  if (address.family() != proxyAddress.ipaddr().family()
      || !relay.IsLoopbackIP()) {
    return false;
  }
  *relayAddress = relay;
  return true;
}

bool IsLoopbackRelaySource(
    const rtc::SocketAddress& source,
    const rtc::SocketAddress& proxyAddress) {
  return source.port()
      && source.ipaddr().family() == proxyAddress.ipaddr().family()
      && source.IsLoopbackIP();
}

rtc::SocketFactory* ReflectorRawSocketFactory(
    rtc::SocketFactory* underlying,
    bool proxyRequired) {
  return proxyRequired ? nullptr : underlying;
}

bool ShouldDisableDirectUdpAndStun(
    bool proxyConfigured,
    bool proxySupportsUdp,
    bool enableP2P) {
  return !enableP2P || (proxyConfigured && !proxySupportsUdp);
}

void ControlWrite::Reset(std::vector<uint8_t> bytes) {
  bytes_ = std::move(bytes);
  offset_ = 0;
}

const uint8_t* ControlWrite::data() const {
  return bytes_.data() + offset_;
}

size_t ControlWrite::size() const {
  return bytes_.size() - offset_;
}

bool ControlWrite::Advance(size_t count) {
  offset_ += std::min(count, size());
  return done();
}

bool ControlWrite::done() const {
  return offset_ == bytes_.size();
}

bool TerminalGuard::Close(int error) {
  if (closed_) {
    return false;
  }
  closed_ = true;
  error_ = error;
  return true;
}

bool TerminalGuard::closed() const {
  return closed_;
}

int TerminalGuard::error() const {
  return error_;
}

} // namespace tgcalls::socks5
