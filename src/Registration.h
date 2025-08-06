#pragma once

#include "AmSession.h"
#include "AmConfigReader.h"
#include "db/DbConfig.h"

class Registration {
    static Registration *_instance;
    AmDynInvoke         *registrar_client_i;

    using RegistrationsContainer = std::map<std::string, AmArg>;

    // store last DB response to provide partial updates
    RegistrationsContainer registrations;

    bool read_registration(const AmArg &r, RegistrationsContainer &regs);

    bool is_reg_updated(const AmArg &local_reg, const AmArg &db_reg);
    void add_registration(const AmArg &r);
    void remove_registration(const string &reg_id);

  public:
    Registration();
    ~Registration();

    static Registration *instance();
    static void          dispose();

    int  configure(AmConfigReader &cfg);
    void load_registrations(const AmArg &data);

    void list_registrations(AmArg &ret);
    bool get_registration_info(int reg_id, AmArg &reg);
};
