#include "DbConfigStates.h"

void DbConfigStates::readFromDbReply(const AmArg &r)
{
#define assign_var(var) var = r[#var].asInt()

    assign_var(auth_credentials);
    assign_var(codec_groups);
    assign_var(ip_auth);
    assign_var(options_probers);
    assign_var(radius_accounting_profiles);
    assign_var(radius_authorization_profiles);
    assign_var(registrations);
    assign_var(sensors);
    assign_var(stir_shaken_trusted_certificates);
    assign_var(stir_shaken_trusted_repositories);
    assign_var(translations);
    assign_var(trusted_lb);

#undef assign_var
}
