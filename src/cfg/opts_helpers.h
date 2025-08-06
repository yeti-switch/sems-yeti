#pragma once

#define DCFG_INT(name)      CFG_INT((char *)#name, 0, CFGF_NODEFAULT)
#define DCFG_BOOL(name)     CFG_BOOL((char *)#name, cfg_false, CFGF_NODEFAULT)
#define DCFG_STR(name)      CFG_STR((char *)#name, NULL, CFGF_NODEFAULT)
#define DCFG_STR_LIST(name) CFG_STR((char *)#name, NULL, CFGF_LIST)

#define DCFG_SEC(name, sec_opt_name, sec_opts) CFG_SEC((char *)#name, sec_opt_name, sec_opts)

#define VCFG_INT(name, value)  CFG_INT((char *)#name, value, CFGF_NONE)
#define VCFG_BOOL(name, value) CFG_BOOL((char *)#name, value, CFGF_NONE)
#define VCFG_STR(name, value)  CFG_STR((char *)#name, (char *)#value, CFGF_NONE)
