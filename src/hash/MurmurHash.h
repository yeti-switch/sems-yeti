#ifndef _MurmurHash_
#define _MurmurHash_

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <AmThread.h>

#include "log.h"

template<class key_type,class lookup_key_type,class data_type>
class MurmurHash : public AmMutex {
public:
	struct entry {
		struct entry *next,*prev;
		struct entry *list_next,*list_prev;
		key_type *key;
		data_type *data;
	};

	MurmurHash(unsigned long buckets = 65000);
	virtual ~MurmurHash();

	uint64_t hashfn(const void *k, int len);

	unsigned long get_count();

	bool insert(const lookup_key_type *data_key,data_type *data,bool locked	= true,bool unique = false);
	bool erase_lookup_key(const lookup_key_type *key,bool locked	= true);
	void erase(entry	*e,bool locked = true);
	entry * at(const lookup_key_type *key,bool locked = true);
	data_type * at_data(const lookup_key_type *key,bool locked = true);

protected:
	virtual uint64_t hash_lookup_key(const lookup_key_type *key) = 0;
	virtual bool cmp_lookup_key(const lookup_key_type *k1,const key_type *k2) = 0;
	virtual void init_key(key_type **dest,const lookup_key_type *src) = 0;
	virtual void free_key(key_type *key) = 0;

	struct entry *l,*first;
private:
	entry * _at(const lookup_key_type *key);
	void _erase(entry	*e);

	unsigned long hash_size;
	unsigned long count;
};

#include "MurmurHash.impl"

#endif
