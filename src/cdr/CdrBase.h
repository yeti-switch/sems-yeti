#pragma once

#include "../SqlCallProfile.h"
#include "AmThread.h"

class CdrBase {
  public:
    enum cdr_type { Call = 0, Auth };

  private:
    cdr_type type;

  public:
    bool           suppress;
    struct timeval cdr_born_time;

    CdrBase() = delete;
    CdrBase(cdr_type type);

    cdr_type getType() { return type; }

    virtual void info(AmArg &s) = 0;

    virtual ~CdrBase() {}
};
