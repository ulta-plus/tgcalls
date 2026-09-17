#include "Socks5UdpProtocol.h"

#include <array>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <vector>

#include "rtc_base/ip_address.h"

namespace {

rtc::SocketAddress Address(const char* value, uint16_t port) {
  auto ip = rtc::IPAddress();
  assert(rtc::IPFromString(value, &ip));
  return rtc::SocketAddress(ip, port);
}

void TestHeaders() {
  for (const auto& address : {
           Address("149.154.167.51", 443),
           Address("2001:67c:4e8:f004::9", 8443) }) {
    auto encoded = std::array<uint8_t, 22>();
    const auto size = tgcalls::socks5::WriteUdpHeader(
        address, encoded.data());
    auto decoded = rtc::SocketAddress();
    auto header = size_t(0);
    assert(tgcalls::socks5::ParseUdpHeader(
        encoded.data(), size, &decoded, &header));
    assert(decoded == address);
    assert(header == size);

    auto fragmented = encoded;
    fragmented[2] = 1;
    assert(!tgcalls::socks5::ParseUdpHeader(
        fragmented.data(), size, &decoded, &header));
    auto domain = encoded;
    domain[3] = 3;
    assert(!tgcalls::socks5::ParseUdpHeader(
        domain.data(), size, &decoded, &header));
    assert(!tgcalls::socks5::ParseUdpHeader(
        encoded.data(), size - 1, &decoded, &header));
  }
}

void TestAssociateRequest() {
  const auto proxy = Address("127.0.0.1", 1080);
  auto local = Address("0.0.0.0", 49152);
  const auto request = tgcalls::socks5::AssociateRequest(local, proxy);
  assert(request.size() == 10);
  assert(request[0] == 5 && request[1] == 3 && request[2] == 0);
  assert(request[3] == 1);
  assert(request[4] == 127 && request[5] == 0);
  assert(request[6] == 0 && request[7] == 1);
  assert(request[8] == 0xC0 && request[9] == 0x00);
  assert(tgcalls::socks5::AssociateRequest(
      Address("0.0.0.0", 0), proxy).empty());
}

void TestRelayValidation() {
  const auto proxy = Address("127.0.0.1", 1080);
  auto relay = rtc::SocketAddress();
  assert(tgcalls::socks5::ValidateRelay(
      rtc::IPAddress(), 30000, proxy, &relay));
  assert(relay == Address("127.0.0.1", 30000));
  assert(tgcalls::socks5::ValidateRelay(
      Address("::", 1).ipaddr(), 30001, proxy, &relay));
  assert(relay == Address("127.0.0.1", 30001));
  assert(tgcalls::socks5::ValidateRelay(
      Address("0.0.0.0", 1).ipaddr(), 30002, proxy, &relay));
  assert(relay == Address("127.0.0.1", 30002));
  assert(!tgcalls::socks5::ValidateRelay(
      Address("192.168.1.1", 1).ipaddr(), 30000, proxy, &relay));
  assert(!tgcalls::socks5::ValidateRelay(
      Address("127.0.0.1", 1).ipaddr(), 0, proxy, &relay));
  assert(!tgcalls::socks5::ValidateRelay(
      Address("::1", 1).ipaddr(), 30000, proxy, &relay));
  assert(tgcalls::socks5::IsLoopbackRelaySource(
      Address("127.0.0.1", 30001), proxy));
  assert(!tgcalls::socks5::IsLoopbackRelaySource(
      Address("192.168.1.1", 30001), proxy));
  assert(!tgcalls::socks5::IsLoopbackRelaySource(
      Address("::1", 30001), proxy));
}

void TestReflectorRawFactoryPolicy() {
  auto raw = reinterpret_cast<rtc::SocketFactory*>(std::uintptr_t(1));
  assert(tgcalls::socks5::ReflectorRawSocketFactory(raw, false) == raw);
  assert(tgcalls::socks5::ReflectorRawSocketFactory(raw, true) == nullptr);
}

void TestDirectUdpPolicy() {
  using tgcalls::socks5::ShouldDisableDirectUdpAndStun;
  assert(!ShouldDisableDirectUdpAndStun(false, false, true));
  assert(ShouldDisableDirectUdpAndStun(false, false, false));
  assert(ShouldDisableDirectUdpAndStun(true, false, true));
  assert(ShouldDisableDirectUdpAndStun(true, false, false));
  assert(!ShouldDisableDirectUdpAndStun(true, true, true));
  assert(ShouldDisableDirectUdpAndStun(true, true, false));
}

void TestPartialWritesAndLifecycle() {
  auto first = tgcalls::socks5::ControlWrite();
  auto second = tgcalls::socks5::ControlWrite();
  first.Reset({ 5, 1, 0 });
  second.Reset({ 5, 3, 0, 1 });
  assert(!first.Advance(1));
  assert(first.size() == 2);
  assert(first.data()[0] == 1);
  assert(first.Advance(2));
  assert(second.size() == 4);
  assert(!second.Advance(2));
  assert(second.size() == 2);
  assert(second.Advance(2));

  auto terminal = tgcalls::socks5::TerminalGuard();
  auto callbackCount = 0;
  assert(!terminal.closed());
  ++callbackCount;
  assert(terminal.Close(ETIMEDOUT));
  if (!terminal.closed()) {
    ++callbackCount;
  }
  assert(!terminal.Close(ECONNRESET));
  assert(terminal.error() == ETIMEDOUT);
  assert(callbackCount == 1);
}

} // namespace

int main() {
  TestHeaders();
  TestAssociateRequest();
  TestRelayValidation();
  TestReflectorRawFactoryPolicy();
  TestDirectUdpPolicy();
  TestPartialWritesAndLifecycle();
}
