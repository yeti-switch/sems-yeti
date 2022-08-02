#pragma on

#include "db/DbConfig.h"

class OptionsProberManager
{
  public:
    int configure();
    void load_probers(const AmArg &data);
};
