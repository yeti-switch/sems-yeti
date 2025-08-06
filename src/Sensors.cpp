#include "Sensors.h"
#include "yeti.h"
#include "sip/defs.h"
#include "netdb.h"
#include "sip/msg_sensor_hep.h"
#include "db/DbHelpers.h"

void sensor::getConfig(AmArg &ret) const
{
    static const char *mode2str[] = { NULL, "IPIP encapsulation", "Ethernet encapsulation", "HEPv3 encapsulation",
                                      NULL };

    switch (_mode) {
    case SENS_TYPE_IPIP:
    case SENS_TYPE_ETHERNET:
    case SENS_TYPE_HEP:
        ret["mode"] = mode2str[_mode];
        if (_sensor)
            _sensor->getInfo(ret);
        break;
    default: ret["mode"] = "unknown";
    }
}

_Sensors::_Sensors()
{
    // stat.clear();
}

_Sensors::~_Sensors()
{
    //
}

int _Sensors::configure(AmConfigReader &cfg)
{
    return 0;
}

int _Sensors::load_sensors_config(const AmArg &data)
{
    int ret = 1;

    sensors_container sensors;

    try {
        if (isArgArray(data)) {
            for (size_t i = 0; i < data.size(); i++) {
                const AmArg &row = data[i];

                int id   = DbAmArg_hash_get_int(row, "o_id", 0);
                int mode = DbAmArg_hash_get_int(row, "o_mode_id", 0);
                switch (mode) {
                case sensor::SENS_TYPE_IPIP:
                {
                    DBG("load IPIP sensor params");
                    string src = DbAmArg_hash_get_str(row, "o_source_ip");
                    string dst = DbAmArg_hash_get_str(row, "o_target_ip");

                    ipip_msg_sensor *ipip_sensor = new ipip_msg_sensor();
                    if (ipip_sensor->init(DbAmArg_hash_get_str(row, "o_source_ip").data(),
                                          DbAmArg_hash_get_str(row, "o_target_ip").data(), NULL))
                    {
                        ERROR("can't init IPIP sensor %d", id);
                        delete ipip_sensor;
                        continue;
                    }
                    sensors.insert(make_pair(id, sensor(sensor::SENS_TYPE_IPIP, ipip_sensor)));
                } break;

                case sensor::SENS_TYPE_ETHERNET:
                {
                    DBG("load Ethernet sensor params");
                    ethernet_msg_sensor *ethernet_sensor = new ethernet_msg_sensor();
                    if (ethernet_sensor->init(DbAmArg_hash_get_str(row, "o_source_interface").data(),
                                              DbAmArg_hash_get_str(row, "o_target_mac").data()))
                    {
                        ERROR("can't init ETHERNET sensor %d", id);
                        delete ethernet_sensor;
                        continue;
                    }
                    sensors.insert(make_pair(id, sensor(sensor::SENS_TYPE_ETHERNET, ethernet_sensor)));
                } break;

                case sensor::SENS_TYPE_HEP:
                {
                    DBG("load HEP sensor params");
                    string capture_host = row["o_target_ip"].asCStr();

                    hep_msg_sensor *hep_sensor = new hep_msg_sensor();
                    if (hep_sensor->init(DbAmArg_hash_get_str(row, "o_target_ip").data(),
                                         DbAmArg_hash_get_int(row, "o_target_port", 15060),
                                         DbAmArg_hash_get_int(row, "o_hep_capture_id", AmConfig.node_id),
                                         DbAmArg_hash_get_str(row, "o_capture_password"),
                                         DbAmArg_hash_get_bool(row, "o_capture_compression")))
                    {
                        ERROR("can't init HEP sensor %d", id);
                        delete hep_sensor;
                        continue;
                    }
                    sensors.emplace(id, sensor(sensor::SENS_TYPE_HEP, hep_sensor));
                } break;

                default: ERROR("unknown sensor mode: %d. skip this sensor", mode); continue;
                }
            }
        }

        DBG("sensors are loaded successfully. apply changes");

        lock.lock();
        _sensors.swap(sensors);
        lock.unlock();

        ret = 0;
    } catch (...) {
        ERROR("unexpected exception");
    }

    return ret;
}

msg_sensor *_Sensors::getSensor(int id)
{
    if (_sensors.empty())
        return NULL;

    sensors_container::iterator i = _sensors.find(id);
    if (i == _sensors.end())
        return NULL;

    return i->second.getSensor();
}

void _Sensors::GetConfig(AmArg &ret)
{
    // ret["db"] = dbc.info_str()+"#"+db_schema;
    lock.lock();
    try {
        AmArg &ss = ret["sensors"];
        if (!_sensors.empty()) {
            ss.assertStruct();
            for (sensors_container::const_iterator i = _sensors.begin(); i != _sensors.end(); ++i)
                i->second.getConfig(ss[int2str(i->first)]);
        }
    } catch (...) {
        ERROR("Sensors::GetConfig() error");
    }
    lock.unlock();
}
