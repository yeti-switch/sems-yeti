#ifndef ALARMS_H
#define ALARMS_H

#include <string>
#include <singleton.h>
#include "AmThread.h"
#include "AmArg.h"

#define RAISE_ALARM(alarm_id) alarms::instance()->get(alarm_id).raise();
#define CLEAR_ALARM(alarm_id) alarms::instance()->get(alarm_id).clear();
#define SET_ALARM(alarm_id,args...) alarms::instance()->get(alarm_id).set(args);

class alarm_entry {
  public:
	alarm_entry();
	~alarm_entry();

	void set(int value, bool silent = false);
	void raise();
	void clear();
	bool is_raised();
	int value();

	const timeval &get_change_time() const;

	void set_info(int alarm_id, std::string alarm_descr);
	const std::string &get_name() const;
	void getInfo(AmArg &ret);

  private:
	int id;
	std::string name;

	timeval change_time;
	int raised;
	AmMutex _lock;
};

class _alarms {
  public:

	struct InvalidAlarmIdException: public std::exception {
		const char* what(){ return "invalid alarm id"; }
	};

	enum {
		MGMT_DB_CONN = 0,
		MGMT_DB_CONN_SLAVE,
		CDR_DB_CONN,
		CDR_DB_CONN_SLAVE,
		REDIS_READ_CONN,
		REDIS_WRITE_CONN,
		MAX_ALARMS
	};

	alarm_entry &get(int alarm_id);

	static const char *id2str(int alarm_id);

  private:
	alarm_entry entries[MAX_ALARMS];

  protected:
	_alarms();
	~_alarms();

};

typedef singleton<_alarms> alarms;

#endif // ALARMS_H
