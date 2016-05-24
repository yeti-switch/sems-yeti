#ifndef _DbConfig_h_
#define _DbConfig_h_

#include <string>
#include "AmConfigReader.h"
#include "AmUtils.h"
#include "log.h"

class DbConfig{
public:
  string host,name,user,pass;
  unsigned int port;
  unsigned int timeout;
  string conn_str();
  string info_str();
  int cfg2dbcfg(AmConfigReader& cfg,string& prefix);
};

#endif
