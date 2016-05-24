#include "codecs_bench.h"

#include "AmPlugIn.h"
#include "AmAudioFile.h"
#include "AmUtils.h"

int load_testing_source(string path,unsigned char *&buf){
	AmAudioFile f;

	if(f.open(path,AmAudioFile::Read)){
		ERROR("can't open file");
		return -1;
	}

	int seconds = f.getLength()/1e3;
	if(!seconds){
		ERROR("file should contain at least one second but has length: %dms", f.getLength());
		return -1;
	}

	unsigned int samples = seconds*8e3;
	unsigned int buf_size = samples << 1;

	buf = new unsigned char[buf_size];
	unsigned char *p = buf;
	for(unsigned int i =0; i< samples;i++)
		p+=f.get(0,p,8000,1);

	return p-buf;
}

void get_codec_cost(int payload_id,unsigned char *buf, int size, AmArg &cost){
#define DEFAULT_SDP_PARAMS ""

	long h_codec = -1;
	int out_buf_size,ret;
	amci_codec_fmt_info_t fmt_i[4];
	amci_codec_t *codec = NULL;
	unsigned char *out_buf,*tmp_buf;
	timeval start,end,diff;

	double  pcm16_len;
	double  encode_cost,encode_ch,
			decode_cost,decode_ch,
			both_cost,both_ch;

	/** init codec */

	AmPlugIn* plugin = AmPlugIn::instance();
	amci_payload_t *payload = plugin->payload(payload_id);
	if(!payload) return;

	codec = plugin->codec(payload->codec_id);
	if(!codec) return;

	cost["pcm16_size"] = size;

	DBG("codec_id = %d, payload_id = %d",codec->id,payload_id);

	if(codec->init){
		fmt_i[0].id = 0;
		h_codec = (*codec->init)(DEFAULT_SDP_PARAMS, fmt_i);
		int i=0;
		while (fmt_i[i].id) {
			switch (fmt_i[i].id) {
			case AMCI_FMT_FRAME_LENGTH : {
				cost["frame_length"] = fmt_i[i].value;
			} break;
			case AMCI_FMT_FRAME_SIZE: {
				cost["frame_size"] = fmt_i[i].value;
			} break;
			case AMCI_FMT_ENCODED_FRAME_SIZE: {
				cost["encoded_frame_size"] = fmt_i[i].value;
			} break;
			default: {
			  DBG("Unknown codec format descriptor: %d\n", fmt_i[i].id);
			} break;
			}
			i++;
		}
	}

	/****************
	 ** encode cost *
	 ****************/

	if(!codec->encode||!codec->decode){
		DBG("codec for payload %s. doesn't have either encode or decode func",payload->name);
		return;
	}

	unsigned int in_buf_samples = size >> 1;
	cost["pcm16_samples"] = (int)in_buf_samples;

	pcm16_len = in_buf_samples/8e3;
	cost["pcm16_len"] = pcm16_len;

	if(!codec->samples2bytes){
		ERROR("no samples2byte implemented for this codec. skip bench");
		return;
	}
	out_buf_size = (*codec->samples2bytes)(h_codec,in_buf_samples);
	DBG("%s.samples2bytes(%ld,%d) = %d",
		payload->name,h_codec,in_buf_samples,out_buf_size);

	out_buf = new unsigned char[out_buf_size];
	if(!out_buf) {
		ERROR("couldn't allocate memory for encode buffer");
		return;
	}

	DBG("encode: h_codec = %ld, in: %p[%i], out: %p[%i]",
		h_codec,buf,size,out_buf,out_buf_size);

	gettimeofday(&start,NULL);
		ret = (*codec->encode)(out_buf,buf,size,1,8e3,h_codec);
	gettimeofday(&end,NULL);

	if(codec->destroy)
		(*codec->destroy)(h_codec);
	if(ret<0){
		ERROR("%s.encode() = %d",payload->name,ret);
		goto free_out;
	}
	DBG("%s.encode() = %d (alleged: %d)",payload->name,ret,out_buf_size);
	h_codec = -1;

	timersub(&end,&start,&diff);
	encode_cost = timeval2double(diff);
	encode_ch = pcm16_len/encode_cost;

	cost["encoded_size"] = ret;
	cost["encode_cost"] = encode_cost;
	cost["encode_ch"] = encode_ch;

	/****************
	 ** decode cost *
	 ****************/

	tmp_buf =  new unsigned char[size];
	if(!tmp_buf) {
		ERROR("couldn't allocate memory for decode buffer size = %i",size);
		goto free_out;
	}

	if(codec->init){
		fmt_i[0].id = 0;
		h_codec = (*codec->init)(DEFAULT_SDP_PARAMS, fmt_i);
	}

	DBG("decode: h_codec = %ld, in: %p[%i], out: %p[%i]",
		h_codec,out_buf,ret,tmp_buf,size);

	if(codec->bytes2samples){
		out_buf_size = PCM16_S2B((*codec->bytes2samples)(h_codec,ret));
		DBG("%s.bytes2samples(%ld,%d) = %d",
			payload->name, h_codec,ret,out_buf_size);
	} else {
		out_buf_size = -1;
	}

	gettimeofday(&start,NULL);
		ret = (*codec->decode)(tmp_buf,out_buf,ret,1,8e3,h_codec);
	gettimeofday(&end,NULL);

	if(codec->destroy)
		(*codec->destroy)(h_codec);
	if(ret<0){
		ERROR("%s.decode() = %d",payload->name,ret);
		goto free_tmp;
	}
	DBG("%s.decode() = %d (alleged: %d)",payload->name,ret,out_buf_size);

	timersub(&end,&start,&diff);
	decode_cost = timeval2double(diff);
	decode_ch = pcm16_len/decode_cost;

	cost["decode_cost"] = decode_cost;
	cost["decode_ch"] = decode_ch;

	/****************
	 ** both cost   *
	 ****************/

	both_cost = decode_cost+encode_cost;
	both_ch = pcm16_len/both_cost;

	cost["both_cost"] = both_cost;
	cost["both_ch"] = both_ch;

free_tmp:
	delete[] tmp_buf;
free_out:
	delete[] out_buf;
}
