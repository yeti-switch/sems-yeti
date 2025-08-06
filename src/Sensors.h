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
    typedef enum { SENS_TYPE_IPIP = 1, SENS_TYPE_ETHERNET = 2, SENS_TYPE_HEP = 3, SENS_TYPE_MAX } sensor_mode;

    sensor(sensor_mode mode, msg_sensor *sensor_ptr)
        : _sensor(sensor_ptr)
        , _mode(mode)
    {
        // INFO("sensor(%p) _sensor = %p",this,_sensor);
        if (_sensor)
            inc_ref(_sensor);
    }

    sensor(const sensor &obj)
        : _sensor(obj._sensor)
        , _mode(obj._mode)
    {
        // INFO("sensor(%p from %p)",this,&obj);
        if (_sensor)
            inc_ref(_sensor);
    }

    ~sensor()
    {
        // INFO("~sensor(%p) _sensor = %p",this,_sensor);
        if (_sensor)
            dec_ref(_sensor);
    }

    void        getConfig(AmArg &ret) const;
    msg_sensor *getSensor() { return _sensor; }

  private:
    sensor_mode _mode;
};

class _Sensors {
    typedef map<int, sensor> sensors_container;
    sensors_container        _sensors;
    AmMutex                  lock;

  public:
    _Sensors();
    ~_Sensors();
    void dispose() {}

    msg_sensor *getSensor(int id);

    int configure(AmConfigReader &cfg);
    int load_sensors_config(const AmArg &data);

    void GetConfig(AmArg &ret);
};

typedef singleton<_Sensors> Sensors;

#endif // SENSORS_H
