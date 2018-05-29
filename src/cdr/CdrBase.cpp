#include "CdrBase.h"

CdrBase::CdrBase(cdr_type type)
  : type(type),
    suppress(false)
{
    gettimeofday(&cdr_born_time, NULL);
}

