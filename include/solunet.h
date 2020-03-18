/*
** SoluNET by Alessandro Ubriaco
**
** Copyright (c) 2020 Alessandro Ubriaco
**
*/
#ifndef __SOLUNET_INCLUDED__
#define __SOLUNET_INCLUDED__
#include "solunet/ISocket.h"

namespace solunet
{
  ISocket *createSocket(bool ssl = false);
  void cleanup();
}

#endif
