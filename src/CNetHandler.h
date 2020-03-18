/*
** SoluNET by Alessandro Ubriaco
**
** Copyright (c) 2020 Alessandro Ubriaco
**
*/
#ifndef __C_NET_HANDLER_INCLUDED__
#define __C_NET_HANDLER_INCLUDED__

#include <string>
#include <solunet/ISocket.h>

#ifdef __linux__
#	include <stdio.h>
#	include <string.h>
#	include <sys/types.h>
#	include <sys/socket.h>
#	include <netinet/in.h>
#	include <netdb.h>
#	define INVALID_SOCKET 0
#	define SOCKET_ERROR -1
#endif

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace solunet
{

static bool CNetHandler_SSLInitialized = false;

class CNetHandlerSocket : public ISocket
{
private:
	int				SID;
	bool			Ready, SSLEnabled, SSLMutual, ThrowExceptions;
	SSL_CTX			*CTX;
	SSL				*_SSL;
	SSL_METHOD		*Method;
	X509			*ClientCertificate;
	std::string		CertificateFileName, PrivateKeyFileName, CertificatePassword, ClientCAFileName;

	void setupSSL(bool re = false);
	void setupSSLSocket(int sid, bool accept = false);
	void cleanupSSL();
	std::string getSSLClientCertificatePublicKey();

	int Timeout;
	bool Child;

	bool CTXRoot;
public:
	std::string CustomID, CustomUID, CustomPassword;
	int CustomStatus;
	unsigned long UniqueID;
	void* ProgramPackage;

	CNetHandlerSocket(int sid = 0, bool ssl = false, bool sslMutual = false, SSL_CTX* ctx = 0, SSL* _ssl = 0, bool child = false);
	~CNetHandlerSocket();

	bool isReady() { return Ready; }

	// SSL
	bool setSSLCertificateMem(void *data);
	bool setSSLPrivateKeyFileMem(void* data);
	bool setSSLCertificate(const char* filename);
	bool setSSLPrivateKeyFile(const char* filename);
	void setSSLCertificatePassword(const char* password);
	bool setSSLClientCAFile(const char* filename);
	bool isSSLValid();
	void setSSLMutual(bool enabled);
	void mutexSSL();
	CertificateInfo getClientCertificate();

	void setThrowExceptions(bool enabled) { ThrowExceptions = enabled; }

	bool bind(int port);
	int listen();
	CNetHandlerSocket* accept();
	int readBuffer(void *buf, int len);
	bool writeBuffer(const void* buf, int len);
	bool connect(const char* host, int port);
	bool close();

	void setTimeout(int timeout);
	int getTimeout() { return Timeout; }

	bool isConnected();

	void dispose() { delete this; }
};

class CNetHandler
{
private:

#ifdef _WIN32
	WSADATA WD;
#endif

public:
#ifdef _WIN32
	CNetHandler() { WSAStartup( MAKEWORD( 2, 0 ), & WD ); };
	~CNetHandler() { WSACleanup();  };
#elif __linux__
	CNetHandler() {};
	~CNetHandler() {};
#endif

	CNetHandlerSocket* createSocket(bool ssl = false);


	static inline void initDependencies()
	{
		if(!CNetHandler_SSLInitialized)
		{
#ifdef USE_OPENSSL
            SSL_library_init();
            SSL_load_error_strings();
            OpenSSL_add_all_algorithms();
#elif USE_WOLFSSL
			wolfSSL_Init();
#endif
            CNetHandler_SSLInitialized = true;
		}
	}
};

}

#endif
