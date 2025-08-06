#ifndef CODECSGROUP_H
#define CODECSGROUP_H

#include <AmArg.h>
#include <AmSdp.h>

#include "HeaderFilter.h"
#include "db/DbConfig.h"
#include "CodesTranslator.h"

#include <string>
#include <vector>
#include <map>
using namespace std;

#define NO_DYN_PAYLOAD -1

struct CodecsGroupException : public InternalException {
    CodecsGroupException(unsigned int code, unsigned int codecs_group);
};

class CodecsGroupEntry {
    vector<SdpPayload> codecs_payloads;
    unsigned int       ptime;

  public:
    CodecsGroupEntry();
    ~CodecsGroupEntry() {}
    bool                add_codec(string codec, string sdp_params, int dyn_payload_id);
    vector<SdpPayload> &get_payloads() { return codecs_payloads; }
    void                getConfig(AmArg &ret) const;
    void                set_ptime(unsigned int val) { ptime = val; };
    unsigned int        get_ptime() const { return ptime; };
};

class CodecsGroups {
    static CodecsGroups                *_instance;
    map<unsigned int, CodecsGroupEntry> codec_groups;
    AmMutex                             codec_groups_mutex;

  public:
    CodecsGroups() {}
    ~CodecsGroups() {}
    static CodecsGroups *instance()
    {
        if (!_instance)
            _instance = new CodecsGroups();
        return _instance;
    }
    static void dispose()
    {
        if (_instance)
            delete _instance;
    }

    int  configure(AmConfigReader &cfg);
    void load_codecs(const AmArg &data);
    void load_codec_groups(const AmArg &data);

    void get(int group_id, CodecsGroupEntry &e)
    {
        AmLock l(codec_groups_mutex);
        auto   i = codec_groups.find(group_id);
        if (i == codec_groups.end()) {
            ERROR("can't find codecs group %d", group_id);
            throw CodecsGroupException(FC_CG_GROUP_NOT_FOUND, group_id);
        }
        e = i->second;
    }

    bool insert(map<unsigned int, CodecsGroupEntry> &dst, unsigned int group_id, string codec, string sdp_params,
                int dyn_payload_id = NO_DYN_PAYLOAD)
    {
        return dst[group_id].add_codec(codec, sdp_params, dyn_payload_id);
    }

    void         clear() { codec_groups.clear(); }
    unsigned int size() { return codec_groups.size(); }

    void GetConfig(AmArg &ret);
};

#endif // CODECSGROUP_H
