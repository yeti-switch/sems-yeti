#include "CallCtx.h"
#include "CodesTranslator.h"
#include "SqlRouter.h"
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

bool CallCtx::setRejectCdr(int disconnect_code_id)
{
    if(cdr) {
        ERROR("attempt to override existent CDR with reject one for code: %d",
            disconnect_code_id);
        return false;
    }

    cdr.reset(new Cdr());

    unsigned int internal_code,response_code;
    string internal_reason,response_reason;

    if(!CodesTranslator::instance()->translate_db_code(
        disconnect_code_id,
        internal_code,internal_reason,
        response_code,response_reason))
    {
        cdr->setSuppress(true);
        return false;
    }

    cdr->update_internal_reason(
        DisconnectByTS,
        internal_reason,internal_code, disconnect_code_id);

    cdr->update_aleg_reason(response_reason, response_code);

    return true;
}

SqlCallProfile *CallCtx::getFirstProfile()
{
    //DBG("%s() this = %p",FUNC_NAME,this);
    if(profiles.empty())
        return nullptr;
    current_profile = profiles.begin();

    cdr.reset(new Cdr(*current_profile));

    return &(*current_profile);
}

/*
 *we should not change the cdr or increase the number of attempts in early_state
 */
SqlCallProfile *CallCtx::getNextProfile(bool early_state, bool resource_failover)
{
	DBG("%s()",FUNC_NAME);

	auto next_profile = current_profile;
	int attempts_counter = cdr->attempt_num;

	if((*next_profile).skip_code_id != 0) {
		//skip profiles with skip_code_id writing CDRs
		do {
			unsigned int internal_code,response_code;
			string internal_reason,response_reason;
			SqlCallProfile &p = *next_profile;

			DBG("process profile with skip_code_id: %d",p.skip_code_id);

			bool write_cdr = CodesTranslator::instance()->translate_db_code(
						p.skip_code_id,
						internal_code,internal_reason,
						response_code,response_reason,
						p.aleg_override_id);

			if(write_cdr) {
				std::unique_ptr<Cdr> skip_cdr(new Cdr(*cdr,p));
				skip_cdr->attempt_num = attempts_counter;
				skip_cdr->update_internal_reason(
					DisconnectByTS,internal_reason,internal_code, p.skip_code_id);
				router.write_cdr(skip_cdr, false);
				attempts_counter++;
			}

			++next_profile;

			if(next_profile == profiles.end())
				return nullptr;

		} while((*next_profile).skip_code_id != 0);
	} else {
		++next_profile;
		if(next_profile == profiles.end()) {
			return nullptr;
		}
	}

	if(!early_state){
		if((*next_profile).disconnect_code_id!=0){
			//ignore refuse profiles for non early state
			return nullptr;
		}
		if(!resource_failover) {
			std::unique_ptr<Cdr> new_cdr(new Cdr(*cdr,*next_profile));
			router.write_cdr(cdr, false);
			cdr.reset(new_cdr.release());
			attempts_counter++;
		} else {
			cdr->update_sql(*next_profile);
		}
	} else {
		cdr->update_sql(*next_profile);
	}

	cdr->attempt_num = attempts_counter;
	current_profile = next_profile;
	return &(*current_profile);
}

SqlCallProfile *CallCtx::getCurrentProfile(){
	if(current_profile == profiles.end())
		return NULL;
	return &(*current_profile);
}

int CallCtx::getOverrideId(bool aleg){
	if(current_profile == profiles.end())
		return 0;
	if(aleg){
		return (*current_profile).aleg_override_id;
	}
	return (*current_profile).bleg_override_id;
}

ResourceList &CallCtx::getCurrentResourceList(){
    if(current_profile == profiles.end()) {
        ERROR("empty profiles ci:%s r_uri: %s",
            initial_invite ? initial_invite->callid.data() : "empty",
            initial_invite ? initial_invite->r_uri.data() : "empty");
        throw AmSession::Exception(500, SIP_REPLY_SERVER_INTERNAL_ERROR);
    }
    return (*current_profile).rl;
}

vector<SdpMedia> &CallCtx::get_self_negotiated_media(bool a_leg){
	if(a_leg) return aleg_negotiated_media;
	else return bleg_negotiated_media;
}

vector<SdpMedia> &CallCtx::get_other_negotiated_media(bool a_leg){
	if(a_leg) return bleg_negotiated_media;
	else return aleg_negotiated_media;
}

CallCtx::CallCtx(SqlRouter &router):
	references(0),
	initial_invite(NULL),
	SQLexception(false),
	on_hold(false),
	bleg_early_media_muted(false),
	ringing_timeout(false),
	ringing_sent(false),
	transfer_intermediate_state(false),
	router(router)
{
	current_profile = profiles.end();
	//DBG("%s() this = %p",FUNC_NAME,this);
}

CallCtx::~CallCtx(){
	//DBG("%s() this = %p",FUNC_NAME,this);
	if(initial_invite)
		delete initial_invite;
}

