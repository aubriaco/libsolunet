/*
** SoluNET by Alessandro Ubriaco
**
** Copyright (c) 2020 Alessandro Ubriaco
**
*/
#include <solunet.h>
#include "CNetHandler.h"

namespace solunet
{
  ISocket *createSocket(bool ssl)
  {
    return CNetHandler().createSocket(ssl);
  }
}
