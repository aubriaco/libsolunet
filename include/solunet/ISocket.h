/*
** SoluNET by Alessandro Ubriaco
**
** Copyright (c) 2020 Alessandro Ubriaco
**
*/
#ifndef __I_SOCKET_INCLUDED__
#define __I_SOCKET_INCLUDED__
#include <string>

namespace solunet
{
  struct CertificateInfo
  {
  	std::string Subject, Issuer, PublicKey;
  };


  class ISocket
  {
  public:
    virtual bool isReady() = 0;

    virtual bool setSSLCertificateMem(void *data) = 0;
    virtual bool setSSLPrivateKeyFileMem(void* data) = 0;
    virtual bool setSSLCertificate(const char* filename) = 0;
    virtual bool setSSLPrivateKeyFile(const char* filename) = 0;
    virtual void setSSLCertificatePassword(const char* password) = 0;
    virtual bool setSSLClientCAFile(const char* filename) = 0;
    virtual bool isSSLValid() = 0;
    virtual void setSSLMutual(bool enabled) = 0;
    virtual void mutexSSL() = 0;
    virtual CertificateInfo getClientCertificate() = 0;

    virtual void setThrowExceptions(bool enabled) = 0;

    virtual bool bind(int port) = 0;
    virtual int listen() = 0;
    virtual ISocket* accept() = 0;
    virtual int readBuffer(void *buf, int len) = 0;
    virtual bool writeBuffer(const void* buf, int len) = 0;
    virtual bool connect(const char* host, int port) = 0;
    virtual bool close() = 0;

    virtual void setTimeout(int timeout) = 0;
    virtual int getTimeout() = 0;

    virtual bool isConnected() = 0;

    virtual void dispose() = 0;
  };
}

#endif
