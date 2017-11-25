#include "CallCtx.h"
#include "AmSession.h"
#include "sip/defs.h"


int fake_logger::log(const char* buf, int len,
        sockaddr_storage* src_ip,
        sockaddr_storage* dst_ip,
        cstring method, int reply_code)
{
    /* DBG("fake_logger called for reply_code = %d, buf = %p, len = %d",
         reply_code, buf,len); */
    if(0!=reply_code) {
        if(msg.buf) delete[] msg.buf;
        msg.buf = new char[len];
        memcpy(msg.buf,buf,len);
        msg.len = len;

        msg.local_ip = *src_ip;
        msg.remote_ip = *dst_ip;
        code = reply_code;

        msg.type = SIP_REPLY;
    }
    return 0;
}

int fake_logger::relog(msg_logger *logger){
    if(NULL==msg.buf || msg.type != SIP_REPLY)
        return -1;
    return  logger->log(
        msg.buf,
        msg.len,
        &msg.local_ip,
        &msg.remote_ip,
        cstring(),code);
}

SqlCallProfile *CallCtx::getFirstProfile(){
	//DBG("%s() this = %p",FUNC_NAME,this);
	if(profiles.empty())
		return NULL;
	current_profile = profiles.begin();
	attempt_num = 0;
	cdr = new Cdr(**current_profile);
	return *current_profile;
}

/*
 *we should not change the cdr or increase the number of attempts in early_state
 */
SqlCallProfile *CallCtx::getNextProfile(bool early_state, bool resource_failover){
	list<SqlCallProfile *>::iterator next_profile;
	DBG("%s()",FUNC_NAME);

	next_profile = current_profile;
	++next_profile;
	if(next_profile == profiles.end()){
		return NULL;
	}
	if(!early_state){
		if((*next_profile)->disconnect_code_id!=0){
			//ignore refuse profiles for non early state
			return NULL;
		}
		if(!resource_failover){
			attempt_num++;
			cdr = new Cdr(*cdr,**next_profile);
		} else {
			cdr->update_sql(**next_profile);
		}
	} else {
		cdr->update_sql(**next_profile);
	}
	current_profile = next_profile;
	return *current_profile;
}

SqlCallProfile *CallCtx::getCurrentProfile(){
	if(current_profile == profiles.end())
		return NULL;
	return *current_profile;
}

int CallCtx::getOverrideId(bool aleg){
	if(current_profile == profiles.end())
		return 0;
	if(aleg){
		return (*current_profile)->aleg_override_id;
	}
	return (*current_profile)->bleg_override_id;
}

ResourceList &CallCtx::getCurrentResourceList(){
	if(current_profile == profiles.end())
		throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
	return (*current_profile)->rl;
}

template <>
//safe cdr getter for write (clear reference to Cdr in CallCtx)
Cdr *CallCtx::getCdrSafe<true>(){
	Cdr *ret;
	lock();
	if(!cdr){
		unlock();
		return NULL;
	}
	ret = cdr;
	cdr = NULL;
	unlock();
	return ret;
}

template <>
//safe cdr getter for read
Cdr *CallCtx::getCdrSafe<false>(){
	Cdr *ret;
	lock();
    ret = cdr;
	unlock();
	return ret;
}

vector<SdpMedia> &CallCtx::get_self_negotiated_media(bool a_leg){
	if(a_leg) return aleg_negotiated_media;
	else return bleg_negotiated_media;
}

vector<SdpMedia> &CallCtx::get_other_negotiated_media(bool a_leg){
	if(a_leg) return bleg_negotiated_media;
	else return aleg_negotiated_media;
}

CallCtx::CallCtx():
	initial_invite(NULL),
	cdr(NULL),
	SQLexception(false),
	ringing_timeout(false),
	ringing_sent(false),
	bleg_early_media_muted(false),
	on_hold(false),
	transfer_intermediate_state(false),
	early_trying_logger(new fake_logger())
{
	inc_ref(early_trying_logger);
	//DBG("%s() this = %p",FUNC_NAME,this);
}

CallCtx::~CallCtx(){
	//DBG("%s() this = %p",FUNC_NAME,this);
	list<SqlCallProfile *>::iterator it = profiles.begin();
	for(;it != profiles.end();++it){
		delete (*it);
	}
	if(initial_invite)
		delete initial_invite;
	dec_ref(early_trying_logger);
}

