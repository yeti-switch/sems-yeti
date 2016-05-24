#include "DbConfig.h"

#define DBCONFIG_DEFAULT_TIMEOUT 2

string DbConfig::conn_str()
{
  string ret;
  ret="host="+host+
	  " port="+int2str(port)+
	  " user="+user+
	  " dbname="+name+
	  " password="+pass+
	  " connect_timeout="+int2str(timeout);
  return ret;
}

string DbConfig::info_str(){
	string ret;
	ret = user +"@" + host+":"+ int2str(port) + "/" + name;
	return ret;
}

int DbConfig::cfg2dbcfg(AmConfigReader& cfg, string& prefix)
{
  string var;
  var=prefix+"_host";
  if(cfg.hasParameter(var)){
    host=cfg.getParameter(var);
  } else {
    host="127.0.0.1";
    WARN("Variable %s not found in config. Using default value: %s",var.c_str(),host.c_str());
  }
  var=prefix+"_port";
  if(cfg.hasParameter(var)){
    port=cfg.getParameterInt(var);
  } else {
    port=5432;
    WARN("Variable %s not found in config. Using default value: %d",var.c_str(),port);
  }
  var=prefix+"_name";
  if(cfg.hasParameter(var)){
    name=cfg.getParameter(var);
  } else {
    name="sqlrouter";
    WARN("Variable %s not found in config. Using default value: %s",var.c_str(),name.c_str());
  }
  var=prefix+"_user";
  if(cfg.hasParameter(var)){
    user=cfg.getParameter(var);
  } else {
    user="sqlrouter";
    WARN("Variable %s not found in config. Using default value: %s",var.c_str(),user.c_str());
  }
  var=prefix+"_pass";
  if(cfg.hasParameter(var)){
    pass=cfg.getParameter(var);
  } else {
    pass="sqlrouter";
    WARN("Variable %s not found in config. Using default value: %s",var.c_str(),pass.c_str());
  }
  var=prefix+"_timeout";
  timeout=cfg.getParameterInt(var,DBCONFIG_DEFAULT_TIMEOUT);
  return 0;
}
