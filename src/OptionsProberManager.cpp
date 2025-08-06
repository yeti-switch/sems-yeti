#include "OptionsProberManager.h"

#include "AmLcConfig.h"
#include "AmSessionContainer.h"
#include "ampi/OptionsProberAPI.h"

int OptionsProberManager::configure()
{
    return 0;
}

void OptionsProberManager::load_probers(const AmArg &data)
{
    AmSessionContainer::instance()->postEvent(OPTIONS_PROBER_QUEUE,
                                              new OptionsProberCtlEvent(OptionsProberCtlEvent::Flush, AmArg()));

    if (isArgArray(data)) {
        AmSessionContainer::instance()->postEvent(OPTIONS_PROBER_QUEUE,
                                                  new OptionsProberCtlEvent(OptionsProberCtlEvent::Add, data));
    }
}
