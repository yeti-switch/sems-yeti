#pragma once

//#include <vector>
#include <list>
#include <string>

#include <AmThread.h>

using namespace std;

struct ResourceParseException {
  string what;
  string ctx;
  ResourceParseException(string w,string c) : what(w), ctx(c) {}
};

struct Resource {
	int id,					//unique id within type space
		type,				//determines behavior when resource is busy
		takes,				//how many takes one get()
		limit;				//upper limit for such active resources
	bool taken,				//resource grabbed
		 active,			//whether we should grab resource after checking phase
		 failover_to_next;	//whether we should use resource which follows if current overloaded
	Resource():
		id(0),type(0),takes(0),limit(0),
		taken(false), active(false), failover_to_next(false) {}
	string print() const;
};

class ResourceOperation : public Resource
{
public:
    enum Operation {
        RES_PUT,
        RES_GET,
        RES_NONE
    } op;
    ResourceOperation() : op(RES_NONE){}
    ResourceOperation(Operation op_, const Resource& res)
    : Resource(res), op(op_){}
};

template <typename Res>
struct ResList: public list<Res> {
	void parse(const string s);
};

typedef ResList<Resource> ResourceList;
typedef ResList<ResourceOperation> ResourceOperationList;
