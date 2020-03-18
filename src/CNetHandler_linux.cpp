/*
** SoluNET by Alessandro Ubriaco
**
** Copyright (c) 2020 Alessandro Ubriaco
**
*/
#ifdef __linux__
#include "CNetHandler.h"
#include <unistd.h>

namespace solunet
{

CNetHandlerSocket* CNetHandler::createSocket(bool ssl)
{
	if(!CNetHandler_SSLInitialized)
		initDependencies();
	return new CNetHandlerSocket(0, ssl);
}


CNetHandlerSocket::CNetHandlerSocket(int sid, bool ssl, bool sslMutual, SSL_CTX* ctx, SSL* _ssl, bool child)
{
	Timeout = 0;
	_SSL = _ssl;
	CTX = ctx;
	CTXRoot = ctx ? false : true;
	SSLEnabled = ssl;
	SSLMutual = sslMutual;
	ThrowExceptions = false;
	ClientCertificate = 0;
    Child = child;
	if(SSLEnabled && !_SSL)
		setupSSL();
	UniqueID = 0;
	if(sid == 0)
	{
		SID = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);


		if(SID == INVALID_SOCKET)
			Ready = false;
		else
		{
			int val = 1;
			int nval = 0;
			setsockopt(SID, SOL_SOCKET, SO_REUSEADDR, (const void*)&val, sizeof(val));
			setsockopt(SID, SOL_SOCKET, SO_KEEPALIVE, (const void*)&nval, sizeof(nval));
			struct timeval timeout;
			timeout.tv_sec = 10;
			timeout.tv_usec = 0;
			setsockopt(SID, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(struct timeval));
			//int set = 1;
			//setsockopt(sd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
			Ready = true;
		}
	}
	else
		SID = sid;
}

CNetHandlerSocket::~CNetHandlerSocket()
{
	close();
  if(SSLEnabled)
    cleanupSSL();
}

void CNetHandlerSocket::setTimeout(int timeout)
{
	Timeout = timeout;
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	setsockopt(SID, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,sizeof(struct timeval));
}

bool CNetHandlerSocket::bind(int port)
{
	sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	int r = ::bind(SID, (sockaddr *)&addr, sizeof(addr));

	return (r == 0);
}

int CNetHandlerSocket::listen()
{
	return ::listen(SID, SOMAXCONN);
}

CNetHandlerSocket* CNetHandlerSocket::accept()
{
	sockaddr clientAddress;
	memset(&clientAddress, 0, sizeof(sockaddr));
	socklen_t clientLength = sizeof(sockaddr);
	int sid = 0;
	while((sid = ::accept(SID, (sockaddr *) &clientAddress, &clientLength)) == SOCKET_ERROR);

	if(SSLEnabled)
		setupSSLSocket(sid,true);


	CNetHandlerSocket* sock = new CNetHandlerSocket(sid, SSLEnabled, SSLMutual, CTX, _SSL);

  _SSL = 0;

	return sock;
}

int CNetHandlerSocket::readBuffer(void* buf, int len)
{
	int r;
	if(SSLEnabled)
		r = ::SSL_read(_SSL, (char*)buf, len);
	else
		r = ::recv(SID, (char *)buf, len, 0);
	if(ThrowExceptions && r < 1)
		throw (int)r;
	return r;
}

bool CNetHandlerSocket::connect(const char* host, int port)
{
	sockaddr_in addr;

	hostent* he = gethostbyname(host);

	if(he == 0)
		return false;

	memset((char *) &addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	memcpy((char*) &addr.sin_addr, (char*)he->h_addr_list[0], he->h_length);
	addr.sin_port = htons(port);



	int r =::connect(SID, (struct sockaddr *)&addr, sizeof(addr));

	if(r == 0 && SSLEnabled)
		setupSSLSocket(SID,false);

	return (r == 0);
}

bool CNetHandlerSocket::writeBuffer(const void* buf, int len)
{
	int r = 0;
	if(SSLEnabled)
#ifdef USE_WOLFSSL
		r = ::wolfSSL_write(_SSL, (const char*)buf, len);
#elif USE_OPENSSL
		r = ::SSL_write(_SSL, (const char*)buf, len);
#endif
	else
		r = ::send(SID, (const char*) buf, len, MSG_NOSIGNAL);

	if(ThrowExceptions && r < 1)
		throw r;
	return (r >= 0);
}


bool CNetHandlerSocket::close()
{
	shutdown(SID,2);
	::close(SID);

	return true;
}

}
#endif
