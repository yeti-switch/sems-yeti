#include "yeti_base.h"

#include "AmEventDispatcher.h"

const string yeti_routing_pg_worker("routing");
const string yeti_cdr_pg_worker("cdr");
const string yeti_auth_log_pg_worker("auth_log");

bool yeti_routing_db_query(const string &query, const string &token)
{
    return AmEventDispatcher::instance()->post(POSTGRESQL_QUEUE,
        new PGExecute(
            PGQueryData(
                yeti_routing_pg_worker,
                query,
                true, /* single */
                YETI_QUEUE_NAME,
                token),
            PGTransactionData()));
    return 0;
}

int YetiBase::sync_db::exec_query(const string &query, const string &token)
{
    db_reply_condition.set(DB_REPLY_WAITING);

    yeti_routing_db_query(query, token);

    if(!db_reply_condition.wait_for_to(5000)) {
        ERROR("%s(%s) timeout", token.data(), query.data());
        return 1;
    }

    switch(db_reply_condition.get()) {
    case DB_REPLY_WAITING:
        throw std::logic_error("unexpected switch value");
    case DB_REPLY_RESULT:
        break;
    case DB_REPLY_ERROR:
    case DB_REPLY_TIMEOUT:
        return 1;
    }

    return 0;
}
