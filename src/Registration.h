#ifndef REGISTRATION_H
#define REGISTRATION_H

#include "AmSession.h"
#include "AmConfigReader.h"
#include "db/DbConfig.h"
#include <pqxx/pqxx>

class Registration {
	static Registration* _instance;
	AmCondition<bool> stopped;
	DbConfig dbc;
	string db_schema;

	bool create_registration(const pqxx::row &r, AmDynInvoke* registrar_client_i);
	void clean_registrations();

public:
	Registration();
	~Registration();
	static Registration* instance();
	static void dispose();

	void configure_db(AmConfigReader &cfg);
	int load_registrations();
	int configure(AmConfigReader &cfg);
	int reload(AmConfigReader &cfg);
	int reload_registration(AmConfigReader &cfg, const AmArg &args);
	void list_registrations(AmArg &ret);
	bool get_registration_info(int reg_id,AmArg &reg);
};

#endif // REGISTRATION_H
