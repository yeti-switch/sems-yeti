#ifndef TRUSTEDHEADERS_H
#define TRUSTEDHEADERS_H

#include <singleton.h>
#include <vector>

#include <pqxx/pqxx>

#include "AmConfigReader.h"
#include "AmSipMsg.h"
#include "AmThread.h"
#include "AmArg.h"

#include "../db/DbConfig.h"

#include <fstream>

class _TrustedHeaders {
  private:
	DbConfig dbc;
	string db_schema;
	vector<string> hdrs;

  public:
	_TrustedHeaders();
	~_TrustedHeaders();

	int configure(AmConfigReader &cfg);
	void configure_db(AmConfigReader &cfg);
	bool reload();

	int load_config();
	int count();

	void parse_reply_hdrs(const AmSipReply &reply, vector<AmArg> &trusted_hdrs);
	void init_hdrs(vector<AmArg> &trusted_hdrs);

#if PQXX_VERSION_MAJOR == 3 && PQXX_VERSION_MINOR == 1
	void invocate(pqxx::prepare::declaration &d);
#endif

	void print_hdrs(const vector<AmArg> &trusted_hdrs);
	void print_csv(std::ofstream &s);
};

typedef singleton <_TrustedHeaders> TrustedHeaders;

#endif // TRUSTEDHEADERS_H
