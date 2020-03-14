/*
** Solusek by Alessandro Ubriaco
**
** Copyright (c) 2019 Alessandro Ubriaco
**
*/
#ifdef USE_OPENSSL
#include "CNetHandler.h"
#include <stdlib.h>

namespace solunet
{

static bool bThreadSetup = false;
static pthread_mutex_t *lock_cs;
static long *lock_count;

void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

void pthreads_thread_id(CRYPTO_THREADID *tid)
{
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

void thread_setup(void)
{
    int i;

    lock_cs = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = (long int*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void CNetHandlerSocket::mutexSSL()
{
	CRYPTO_THREADID thread_id;

	CRYPTO_THREADID_current(&thread_id);
}


bool CNetHandlerSocket::isConnected()
{
	char buf;
	int err = recv(SID, &buf, 1, MSG_PEEK);
	if(err == SOCKET_ERROR)
		return false;
	else
		return true;
}

void CNetHandlerSocket::setupSSL(bool re)
{
	CNetHandler::initDependencies();

	if(!bThreadSetup)
		thread_setup();

	CTX = SSL_CTX_new(TLSv1_2_method());


	//SSL_CTX_set_options(CTX, SSL_OP_SINGLE_DH_USE);
	if (!CTX)
	{
		ERR_print_errors_fp(stderr);
		return;
	}


	if(re)
	{
		setSSLMutual(SSLMutual);
		setSSLCertificatePassword(CertificatePassword.c_str());
		setSSLCertificate(CertificateFileName.c_str());
		setSSLPrivateKeyFile(PrivateKeyFileName.c_str());
		//setSSLClientCAFile(ClientCAFileName.c_str());
	}

}

void CNetHandlerSocket::setupSSLSocket(int sid, bool accept)
{
	int err = 0;
	_SSL = SSL_new(CTX);
	err = SSL_set_fd(_SSL, sid);

	if(err == -1)
		ERR_print_errors_fp(stderr);

	if(accept)
		err = SSL_accept(_SSL);
	else
		err = SSL_connect(_SSL);
	if (err == -1)
		ERR_print_errors_fp(stderr);
}

bool CNetHandlerSocket::setSSLCertificate(const char* filename)
{
	CertificateFileName = filename;
	if(SSL_CTX_use_certificate_file(CTX, filename, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	return true;
}

bool CNetHandlerSocket::setSSLCertificateMem(void *data)
{
	if(SSL_CTX_use_certificate(CTX, (X509*)data) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	return true;
}

const char* passwd;

int pem_passwd_cb(char *buf, int size, int rwflag, void *password)
{
	strncpy(buf, (char *)(passwd), size);
	buf[size - 1] = '\0';
	return(strlen(buf));
}


void CNetHandlerSocket::setSSLCertificatePassword(const char* password)
{
	passwd = password;
	CertificatePassword = password;
	::SSL_CTX_set_default_passwd_cb(CTX, pem_passwd_cb);
}

bool CNetHandlerSocket::setSSLPrivateKeyFile(const char* filename)
{
	PrivateKeyFileName = filename;
	if(SSL_CTX_use_PrivateKey_file(CTX, filename, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	return true;
}

bool CNetHandlerSocket::setSSLPrivateKeyFileMem(void* data)
{
	if(SSL_CTX_use_PrivateKey(CTX, (EVP_PKEY*)data) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	return true;
}

bool CNetHandlerSocket::setSSLClientCAFile(const char* filename)
{
	ClientCAFileName = filename;
	if (SSL_CTX_load_verify_locations(CTX, filename, NULL) != 1)
    {
        ERR_print_errors_fp(stderr);
		return false;
    }

    // allow this CA to be sent to the client during handshake

    STACK_OF(X509_NAME) * list = SSL_load_client_CA_file(filename);
    if (NULL == list)
    {
        printf("Failed to load SSL client CA file.\n");
		return false;
    }
    SSL_CTX_set_client_CA_list(CTX, list);
    SSL_CTX_set_verify_depth(CTX, 1);

	return true;
}

bool CNetHandlerSocket::isSSLValid()
{
	return SSL_CTX_check_private_key(CTX);
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	return 1;
}

void CNetHandlerSocket::setSSLMutual(bool enabled)
{
	SSLMutual = enabled;
	if(enabled)
	{
		SSL_CTX_set_verify(CTX,SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,verify_callback);
		SSL_CTX_set_verify_depth(CTX,1);
	}
	else
	{
		SSL_CTX_set_verify(CTX, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_verify_depth(CTX,0);
	}
}

CertificateInfo CNetHandlerSocket::getClientCertificate()
{
	CertificateInfo info;
	if(SSLMutual)
	{
		char* str;
		ClientCertificate = SSL_get_peer_certificate(_SSL);
		if(ClientCertificate)
		{
			str = X509_NAME_oneline(X509_get_subject_name(ClientCertificate), 0, 0);
			info.Subject = str;
			free(str);
			str = X509_NAME_oneline(X509_get_issuer_name(ClientCertificate), 0, 0);
			info.Issuer = str;
			free(str);
			info.PublicKey = getSSLClientCertificatePublicKey();

			X509_free(ClientCertificate);
		}
	}
	return info;
}

std::string uc2hexstr(unsigned char* buf, const unsigned int len)
{
	std::string ret;
	for(unsigned int i = 0; i < len; i++)
	{
		char str[16];
		sprintf(str,"%02x",buf[i]);
		ret += str;
	}
	return ret;
}

std::string CNetHandlerSocket::getSSLClientCertificatePublicKey()
{
	std::string ret;
	EVP_PKEY * pubkey = X509_get_pubkey(ClientCertificate);

	if(pubkey)
	{

		unsigned char *ucBuf, *uctempBuf;

		const int len = i2d_PublicKey(pubkey, 0);

		ucBuf = new unsigned char[len+1];
		uctempBuf = ucBuf;


		i2d_PublicKey(pubkey,&uctempBuf);

		ret = uc2hexstr(ucBuf, len);

		delete[] ucBuf;

		EVP_PKEY_free(pubkey);


	}
	else
		printf("Failed to get public key.\n");


	return ret;
}

void CNetHandlerSocket::cleanupSSL()
{
  if(_SSL)
	 SSL_free(_SSL);
  if(CTXRoot && CTX)
	 SSL_CTX_free(CTX);
  _SSL = 0;
  CTX = 0;
}

}
#endif
