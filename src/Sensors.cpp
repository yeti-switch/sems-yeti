#include "Sensors.h"
#include "yeti.h"
#include "sip/defs.h"
#include <pqxx/pqxx>
#include "netdb.h"

void sensor::getConfig(AmArg& ret) const {
	switch(_mode){
	case SENS_TYPE_IPIP: {
		ret["mode"] = "IPIP encapsulation";
		if(_sensor){
			ipip_msg_sensor *s = dynamic_cast<ipip_msg_sensor *>(_sensor);
			if(s) s->getInfo(ret);
		}
	} break;
	case SENS_TYPE_ETHERNET: {
		ret["mode"] = "Ethernet encapsulation";
		if(_sensor){
			ethernet_msg_sensor *s = dynamic_cast<ethernet_msg_sensor *>(_sensor);
			if(s) s->getInfo(ret);
		}
	} break;
	default:
		ret["mode"] = "uknown";
	}
}

_Sensors::_Sensors(){
	//stat.clear();
}

_Sensors::~_Sensors(){
	//
}

int _Sensors::configure(AmConfigReader &cfg){
	db_schema = Yeti::instance()->config.routing_schema;
	configure_db(cfg);
	if(load_sensors_config()){
		ERROR("can't load sensors config");
		return -1;
	}

	return 0;
}

void _Sensors::configure_db(AmConfigReader &cfg){
	string prefix("master");
	dbc.cfg2dbcfg(cfg,prefix);
}

bool _Sensors::reload(){
	if(load_sensors_config()){
		return false;
	}
	return true;
}

int _Sensors::load_sensors_config(){
	int ret = 1;

	sensors_container sensors;

	try {
		pqxx::result r;
		pqxx::connection c(dbc.conn_str());
		c.set_variable("search_path",db_schema+", public");
		pqxx::work t(c);
		r = t.exec("SELECT * FROM load_sensor()");
		t.commit();
		c.disconnect();

		for(pqxx::result::size_type i = 0; i < r.size();++i){
			const pqxx::result::tuple &row = r[i];

			int id = row["o_id"].as<int>(0);
			int mode = row["o_mode_id"].as<int>(0);
			switch(mode){
			case sensor::SENS_TYPE_IPIP: {
				DBG("load IPIP sensor params");
				string src = row["o_source_ip"].c_str();
				string dst = row["o_target_ip"].c_str();

				ipip_msg_sensor *ipip_sensor = new ipip_msg_sensor();
				if(ipip_sensor->init(src.c_str(),dst.c_str(),NULL)){
					ERROR("can't init IPIP sensor %d",id);
					delete ipip_sensor;
					continue;
				}
				sensors.insert(make_pair(id,sensor(sensor::SENS_TYPE_IPIP,ipip_sensor)));
			} break;

			case sensor::SENS_TYPE_ETHERNET: {
				DBG("load Ethernet sensor params");
				string dst_mac = row["o_target_mac"].c_str();
				string iface = row["o_source_interface"].c_str();

				ethernet_msg_sensor *ethernet_sensor = new ethernet_msg_sensor();
				if(ethernet_sensor->init(iface.c_str(),dst_mac.c_str())){
					ERROR("can't init ETHERNET sensor %d",id);
					delete ethernet_sensor;
					continue;
				}
				sensors.insert(make_pair(id,sensor(sensor::SENS_TYPE_ETHERNET,ethernet_sensor)));
			} break;

			default:
				ERROR("uknown sensor mode: %d. skip this sensor",mode);
				continue;
			}
		}

		INFO("sensors are loaded successfully. apply changes");

		lock.lock();
		_sensors.swap(sensors);
		lock.unlock();

		ret = 0;
	} catch(const pqxx::pqxx_exception &e){
		ERROR("pqxx_exception: %s ",e.base().what());
	} catch(...){
		ERROR("unexpected exception");
	}

	return ret;
}

msg_sensor *_Sensors::getSensor(int id){
	if(_sensors.empty()) return NULL;

	sensors_container::iterator i = _sensors.find(id);
	if(i==_sensors.end()) return NULL;

	return i->second.getSensor();
}

void _Sensors::GetConfig(AmArg& ret){
	//ret["db"] = dbc.info_str()+"#"+db_schema;
	lock.lock();
	try {
		AmArg &ss = ret["sensors"];
		if(!_sensors.empty()){
			ss.assertStruct();
			for(sensors_container::const_iterator i = _sensors.begin();i!=_sensors.end();++i)
				i->second.getConfig(ss[int2str(i->first)]);
		}
	} catch(...){
		ERROR("Sensors::GetConfig() error");
	}
	lock.unlock();
}
