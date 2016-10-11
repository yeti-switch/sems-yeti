template<class key_type,class lookup_key_type,class data_type>
MurmurHash<key_type,lookup_key_type,data_type>::MurmurHash(unsigned long buckets):
	hash_size(buckets),
	count(0),
	first(NULL)
{
	l = new struct entry[buckets];
	bzero(l,sizeof(struct entry)*buckets);
	//DBG("MurmurHash()");
}

template<class key_type,class lookup_key_type,class data_type>
MurmurHash<key_type,lookup_key_type,data_type>::~MurmurHash(){
	delete []l;
	//DBG("~MurmurHash()");
}

template<class key_type,class lookup_key_type,class data_type>
uint64_t MurmurHash<key_type,lookup_key_type,data_type>::hashfn(const void * k, int len){
	//! see: https://sites.google.com/site/murmurhash/
#if defined(__LP64__)
	const uint64_t m = 0xc6a4a7935bd1e995;
	const int r = 47;
	
	uint64_t h = (len * m);
	
	const uint64_t * data = (const uint64_t *)k;
	const uint64_t * end = data + (len/8);

	while(data != end)
	{
		uint64_t k = *data++;

		k *= m; 
		k ^= k >> r; 
		k *= m; 
		
		h ^= k;
		h *= m; 
	}

	const unsigned char * data2 = (const unsigned char*)data;

	switch(len & 7)
	{
	case 7: h ^= uint64_t(data2[6]) << 48;
	case 6: h ^= uint64_t(data2[5]) << 40;
	case 5: h ^= uint64_t(data2[4]) << 32;
	case 4: h ^= uint64_t(data2[3]) << 24;
	case 3: h ^= uint64_t(data2[2]) << 16;
	case 2: h ^= uint64_t(data2[1]) << 8;
	case 1: h ^= uint64_t(data2[0]);
	        h *= m;
	};
 
	h ^= h >> r;
	h *= m;
	h ^= h >> r;

	return h/*%hash_size*/;  
#else
	const unsigned int m = 0x5bd1e995;
	const int r = 24;

	unsigned int h1 = len;
	unsigned int h2 = 0;

	const unsigned int * data = (const unsigned int *)k;

	while(len >= 8)
	{
		unsigned int k1 = *data++;
		k1 *= m; k1 ^= k1 >> r; k1 *= m;
		h1 *= m; h1 ^= k1;
		len -= 4;

		unsigned int k2 = *data++;
		k2 *= m; k2 ^= k2 >> r; k2 *= m;
		h2 *= m; h2 ^= k2;
		len -= 4;
	}

	if(len >= 4)
	{
		unsigned int k1 = *data++;
		k1 *= m; k1 ^= k1 >> r; k1 *= m;
		h1 *= m; h1 ^= k1;
		len -= 4;
	}

	switch(len)
	{
	case 3: h2 ^= ((unsigned char*)data)[2] << 16;
	case 2: h2 ^= ((unsigned char*)data)[1] << 8;
	case 1: h2 ^= ((unsigned char*)data)[0];
			h2 *= m;
	};

	h1 ^= h2 >> 18; h1 *= m;
	h2 ^= h1 >> 22; h2 *= m;
	h1 ^= h2 >> 17; h1 *= m;
	h2 ^= h1 >> 19; h2 *= m;

	uint64_t h = h1;

	h = (h << 32) | h2;

	return h/*%hash_size*/;
#endif
}

template<class key_type,class lookup_key_type,class data_type>
bool MurmurHash<key_type,lookup_key_type,data_type>::insert(const lookup_key_type *key,data_type* data,bool locked,bool unique)
{
	struct entry *e,*p = NULL;
	bool inserted = true;

	if(locked)
		lock();

	e = &l[hash_lookup_key(key)%hash_size];
	if(e->data||e->next){
		if(unique){
			if(e->data&&cmp_lookup_key(key,e->key)){
				inserted = false;
				goto out;
			}
			while(e->next){
				e = e->next;
				if(e->data&&cmp_lookup_key(key,e->key)){
					inserted = false;
					goto out;
				}
			}
		} else {
			while(e->next){
				e = e->next;
			}
		}
		e->next = new struct entry;
		p = e;
		e = e->next;
	}

	e->prev = p;
	e->next = NULL;
	e->data = data;
	init_key(&e->key,key);

	if(first)
		first->list_prev = e;
	e->list_next = first;
	e->list_prev = NULL;
	first = e;
	count++;
out:
	if(locked)
		unlock();

	return inserted;
}

template<class key_type,class lookup_key_type,class data_type>
void MurmurHash<key_type,lookup_key_type,data_type>::_erase(entry  *e){
	/*remove entry from dl list*/
	if(e->list_next)
		e->list_next->list_prev = e->list_prev;
	if(e->list_prev)
		e->list_prev->list_next = e->list_next;
	else
		first = e->list_next;
	/*remove entry*/
	free_key(e->key);
	if(e->prev){
		e->prev->next = e->next;
		if(e->next)
			e->next->prev = e->prev;
		delete e;
	} else {
		e->data = NULL;
	}
	count--;
}

template<class key_type,class lookup_key_type,class data_type>
void MurmurHash<key_type,lookup_key_type,data_type>::erase(entry  *e,bool locked){
	if(locked){
		lock();
			_erase(e);
		unlock();
	} else {
		_erase(e);
	}
}

template<class key_type,class lookup_key_type,class data_type>
void MurmurHash<key_type,lookup_key_type,data_type>::erase_lookup_key(const lookup_key_type *key,bool locked){
	struct entry *e;

	if(locked){
		lock();
			if((e = _at(key))) {
				_erase(e);
			}
		unlock();
	} else {
		if((e = _at(key))) {
			_erase(e);
		}
	}
}

template<class key_type,class lookup_key_type,class data_type>
typename MurmurHash<key_type,lookup_key_type,data_type>::entry * MurmurHash<key_type,lookup_key_type,data_type>::_at(const lookup_key_type *key){
	struct entry *e = &l[hash_lookup_key(key)%hash_size];

	if(!e->data&&!e->next){
		return NULL;
	}
	if(e->next){
		if(!e->data)
			e = e->next;
		while(e){
			if(cmp_lookup_key(key,e->key))
			break;
			e = e->next;
		}
	}
	return e;
}

template<class key_type,class lookup_key_type,class data_type>
typename MurmurHash<key_type,lookup_key_type,data_type>::entry * MurmurHash<key_type,lookup_key_type,data_type>::at(const lookup_key_type *key,bool locked){
	struct entry *e;

	if(locked){
		lock();
			e = _at(key);
		unlock();
	} else {
		e = _at(key);
	}
	return e;
}

template<class key_type,class lookup_key_type,class data_type>
data_type * MurmurHash<key_type,lookup_key_type,data_type>::at_data(const lookup_key_type *key,bool locked){
	data_type *data = NULL;
	typename MurmurHash<key_type,lookup_key_type,data_type>::entry *e = NULL;

	e = at(key,locked);
	if(e)
		data = e->data;
	return data;
}

template<class key_type,class lookup_key_type,class data_type>
unsigned long MurmurHash<key_type,lookup_key_type,data_type>::get_count(){
	return count;
}
