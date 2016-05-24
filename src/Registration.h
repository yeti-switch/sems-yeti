#ifndef REGISTRATION_H
#define REGISTRATION_H

#include "AmSession.h"
#include "AmConfigReader.h"
#include "db/DbConfig.h"

class Registration : public AmThread {
	static Registration* _instance;
	AmCondition<bool> stopped;
	DbConfig dbc;
	string db_schema;
	AmMutex cfg_mutex;
	int check_interval;

	struct RegInfo {
		int id;
		string domain;
		string user;
		string display_name;
		string auth_user;
		string passwd;
		string proxy;
		string contact;

		string handle;
		int expires;
		int state;

		int expire_interval;
		bool force_reregister;
		struct timeval internal_expire_time;
	};

	void reg2arg(const RegInfo &reg,AmArg &arg);
	vector<RegInfo> registrations;

	void create_registration(RegInfo& ri);
	bool check_registration(RegInfo& ri);
	void remove_registration(RegInfo& ri);
	void clean_registrations();
	bool time_to_reregister(RegInfo& ri, time_t now_sec);

protected:
	void run();
	void on_stop();

public:
	Registration();
	~Registration();
	static Registration* instance();

	void configure_db(AmConfigReader &cfg);
	int load_registrations();
	int configure(AmConfigReader &cfg);
	int reload(AmConfigReader &cfg);
	void list_registrations(AmArg &ret);
	long get_registrations_count();
	bool get_registration_info(int reg_id,AmArg &reg);
	bool reregister(int reg_id);
};

#endif // REGISTRATION_H
