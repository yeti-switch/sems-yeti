#pragma once

//#include <vector>
#include <list>
#include <string>

#include <AmThread.h>

using namespace std;

struct ResourceParseException {
    string what;
    string ctx;
    ResourceParseException(string w,string c)
      : what(w), ctx(c)
    {}
};

struct Resource
{
    string id;              //unique id within type space
    int type,               //determines behavior when resource is busy
        takes,              //how many takes one get()
        limit;              //upper limit for such active resources
    bool taken,             //resource grabbed
         active,            //whether we should grab resource after checking phase
         failover_to_next;  //whether we should use resource which follows if current overloaded

    /* resource rate-limit mode
     *  'takes' size of the sliding window size in seconds
     *  'limit' max allowed entries within window
     */
    bool rate_limit; //'takes' will mean sliding window size in seconds

    Resource()
      : id{},type(0),takes(0),limit(0),
        taken(false), active(false), failover_to_next(false),
        rate_limit(false)
    {}

    string print() const;
};

struct ResourceList
  : public list<Resource>
{
    void parse(const string &s);
};

struct ResourcesOperation
{
  public:
    ResourceList resources;
    string local_tag;

    enum Operation {
        RES_PUT,
        RES_GET
    } op;

    ResourcesOperation(Operation op)
      : op(op)
    {}

    ResourcesOperation(const string &local_tag, const ResourceList& resources, Operation op)
      : resources(resources),
        local_tag(local_tag),
        op(op)
    {}

    ResourcesOperation(const ResourcesOperation &) = delete;
};

class ResourcesOperationList
  : public list<ResourcesOperation>
{
  public:
    ResourcesOperationList() = default;
    ResourcesOperationList(ResourcesOperationList &&) = default;
    ResourcesOperationList(const ResourcesOperationList &) = delete;
};
