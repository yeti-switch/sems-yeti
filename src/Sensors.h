#ifndef SENSORS_H
#define SENSORS_H

#include "AmConfigReader.h"
#include "AmThread.h"
#include "AmArg.h"
#include "db/DbConfig.h"
#include "sip/msg_sensor.h"

#include <map>
#include <singleton.h>

using namespace std;

class sensor {
	msg_sensor *_sensor;
public:
	typedef enum {
		SENS_TYPE_IPIP = 1,
		SENS_TYPE_ETHERNET = 2,
		SENS_TYPE_MAX
	} sensor_mode;

	sensor(sensor_mode mode, msg_sensor *sensor_ptr):
		_mode(mode), _sensor(sensor_ptr)
	{
		//INFO("sensor(%p) _sensor = %p",this,_sensor);
		if(_sensor) inc_ref(_sensor);
	}
	sensor(const sensor &obj):
		_mode(obj._mode), _sensor(obj._sensor)
	{
		//INFO("sensor(%p from %p)",this,&obj);
		if(_sensor) inc_ref(_sensor);
	}
	~sensor() {
		//INFO("~sensor(%p) _sensor = %p",this,_sensor);
		if(_sensor) dec_ref(_sensor);
	}
	void getConfig(AmArg& ret) const;
	msg_sensor *getSensor() { return _sensor; }
private:
	sensor_mode _mode;
};

class _Sensors {
	typedef map<int,sensor> sensors_container;
	sensors_container _sensors;
	AmMutex lock;

	DbConfig dbc;
	string db_schema;
	int load_sensors_config();

  public:
	_Sensors();
	~_Sensors();

	msg_sensor *getSensor(int id);

	int configure(AmConfigReader &cfg);
	void configure_db(AmConfigReader &cfg);
	bool reload();

	void GetConfig(AmArg& ret);
};

typedef singleton<_Sensors> Sensors;

#endif // SENSORS_H
