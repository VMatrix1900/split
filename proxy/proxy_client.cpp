#include "proxy_client.hpp"

ProxyClient::receiveSNI(char *SNIbuffer) {
    SSL_set_tlsext_host_name(ssl, SNIbuffer);
    SSL_do_handshake(ssl);
    sendPacket();
}
