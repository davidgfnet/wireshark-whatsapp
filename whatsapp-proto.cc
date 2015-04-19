
/*
 * WhatsApp protocol dissector
 * Written by David Guillen Fandos <david@davidgf.net>
 * Based on WhatsAPI sources
 *
 */


#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h> 
#include <iostream>
#include <map>
#include <vector>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
extern "C" {
#include <config.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include "whatsapp-proto.h"
}

const char * key_desc[4] = {
	"Out key", "Out HMAC", "In key", "In HMAC"
};

extern "C" {
	size_t tinfl_decompress_mem_to_mem(void *pOut_buf, size_t out_buf_len, const void *pSrc_buf, size_t src_buf_len, int flags);
}

std::string base64_decode(std::string const& encoded_string);

class Tree; class DataBuffer; class KeyGenerator; class RC4Decoder;

class DissectSession {
private:
	// Current dissection classes
	address server_addr, client_addr, client_mac; // Identify server/client role
	RC4Decoder * in, * out;
	unsigned char session_key[20*4];  // V12 session | V14 session keys (4)
	std::string challenge_data, challenge_response;
	std::map < unsigned int, DataBuffer* > * blist;
	std::map < unsigned int, DataBuffer* > * dlist;
	std::string userphone;
	bool found_auth;
	unsigned int wa_version;

	bool check_key();
	bool tryKeys();

public:
	DissectSession (const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
	int dissect(const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
	Tree * next_tree(DataBuffer * data,proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
	Tree * read_tree(DataBuffer * data, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
};

enum EncodingManner { EncType12 = 0, EncType14, EncType14Ext, EncType15, EncType15Ext, EncTypePlain };
enum EncodingKind   { TokenTypeKey = 0, TokenTypeVal, TokenTypeTag, TokenTypeNValue };

int * encoding_table[4][6] = {
	{&hf_whatsapp_attr_key_enc_12, &hf_whatsapp_attr_key_enc_14, &hf_whatsapp_attr_key_enc_ext14, &hf_whatsapp_attr_key_enc_15, &hf_whatsapp_attr_key_enc_ext15, &hf_whatsapp_attr_key_plain},
	{&hf_whatsapp_attr_val_enc_12, &hf_whatsapp_attr_val_enc_14, &hf_whatsapp_attr_val_enc_ext14, &hf_whatsapp_attr_val_enc_15, &hf_whatsapp_attr_val_enc_ext15, &hf_whatsapp_attr_val_plain},
	{&hf_whatsapp_tag_enc_12, &hf_whatsapp_tag_enc_14, &hf_whatsapp_tag_enc_ext14, &hf_whatsapp_attr_key_enc_15, &hf_whatsapp_attr_key_enc_ext15, &hf_whatsapp_tag_plain},
	{&hf_whatsapp_nvalue_enc_12, &hf_whatsapp_nvalue_enc_14, &hf_whatsapp_nvalue_enc_ext14, &hf_whatsapp_attr_key_enc_15, &hf_whatsapp_attr_key_enc_ext15, &hf_whatsapp_nvalue_plain}
};


#define COPY_ADDRESS_CC(to, from) { \
	guint8 *COPY_ADDRESS_data; \
	(to)->type = (from)->type; \
	(to)->len = (from)->len; \
	COPY_ADDRESS_data = (guint8*)g_malloc((from)->len); \
	memcpy(COPY_ADDRESS_data, (from)->data, (from)->len); \
	(to)->data = COPY_ADDRESS_data; \
	}

extern const value_string strings_list[];

std::string getDecoded12(int n) {
	return std::string(strings_list12[n].strptr);
}

void HMAC_SHA1(const unsigned char *text, int text_len, const unsigned char *key, int key_len, unsigned char *digest) {
	const int SHA1_BLOCK_SIZE = 64;
	const int SHA1_DIGEST_LENGTH = 20;

	unsigned char SHA1_Key[4096], AppendBuf2[4096], szReport[4096];
	unsigned char * AppendBuf1 = new unsigned char[text_len+64];
	unsigned char m_ipad[64], m_opad[64];

	memset(SHA1_Key, 0, SHA1_BLOCK_SIZE);

	/* repeated 64 times for values in ipad and opad */
	memset(m_ipad, 0x36, sizeof(m_ipad));
	memset(m_opad, 0x5c, sizeof(m_opad));

	/* STEP 1 */
	if (key_len > SHA1_BLOCK_SIZE)
		SHA1(key,key_len,SHA1_Key);
	else
		memcpy(SHA1_Key, key, key_len);

	/* STEP 2 */
	for (int i=0; i<sizeof(m_ipad); i++)
		m_ipad[i] ^= SHA1_Key[i];              

	/* STEP 3 */
	memcpy(AppendBuf1, m_ipad, sizeof(m_ipad));
	memcpy(AppendBuf1 + sizeof(m_ipad), text, text_len);

	/* STEP 4 */
	SHA1(AppendBuf1, sizeof(m_ipad) + text_len, szReport);

	/* STEP 5 */
	for (int j=0; j<sizeof(m_opad); j++)
		m_opad[j] ^= SHA1_Key[j];

	/* STEP 6 */
	memcpy(AppendBuf2, m_opad, sizeof(m_opad));
	memcpy(AppendBuf2 + sizeof(m_opad), szReport, SHA1_DIGEST_LENGTH);

	/*STEP 7 */
	SHA1(AppendBuf2, sizeof(m_opad) + SHA1_DIGEST_LENGTH, digest);
	
	delete [] AppendBuf1;
}


const char hexmap[16]  = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
const char hexmap2[16] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };
class KeyGenerator {
public:
	static void generateKeyImei(const char * imei, const char * salt, int saltlen, char * out) {
		char imeir[strlen(imei)];
		for (int i = 0; i < strlen(imei); i++)
			imeir[i] = imei[strlen(imei)-i-1];
		
		char hash[16];
		MD5((unsigned char*)imeir,strlen(imei),(unsigned char*)hash);
		
		// Convert to hex
		char hashhex[32];
		for (int i = 0; i < 16; i++) {
			hashhex[2*i] = hexmap[(hash[i]>>4)&0xF];
			hashhex[2*i+1] = hexmap[hash[i]&0xF];
		}
		
		PKCS5_PBKDF2_HMAC_SHA1 (hashhex,32,(unsigned char*)salt,saltlen,16,20,(unsigned char*)out);
	}
	static void generateKeyV2(const std::string pw, const char * salt, int saltlen, char * out) {
		std::string dpw = base64_decode(pw);
			
		PKCS5_PBKDF2_HMAC_SHA1 (dpw.c_str(),20,(unsigned char*)salt,saltlen,16,20,(unsigned char*)out);
	}
	static void generateKeyV14(const std::string pw, const char * salt, int saltlen, char * out) {
		std::string dec = base64_decode(pw);
		char salt_[saltlen+1]; memcpy(salt_,salt,saltlen);
		
		for (int i = 0; i < 4; i++) {
			salt_[saltlen] = (i+1);
			PKCS5_PBKDF2_HMAC_SHA1(dec.c_str(), 20, (unsigned char *)salt_, saltlen+1, 2, 20, (unsigned char *)&out[20*i]);
		}
	}

	static void generateKeyMAC(const address * macaddr, const char * salt, int saltlen, char * out) {
		unsigned char * ad = (unsigned char*)macaddr->data;
		if (ad == NULL) return;
		char fmt_addr[6*3*2];
		for (int i = 0; i < 6; i++) {
			fmt_addr[i*3+0] = hexmap2[ad[i]>>4];
			fmt_addr[i*3+1] = hexmap2[ad[i]&0xF];
			fmt_addr[i*3+2] = ':';
			
			fmt_addr[i*3+0+17] = hexmap2[ad[i]>>4];
			fmt_addr[i*3+1+17] = hexmap2[ad[i]&0xF];
			fmt_addr[i*3+2+17] = ':';
		}
		
		char hash[16];
		MD5((unsigned char*)fmt_addr,34,(unsigned char*)hash);
		
		// Convert to hex
		char hashhex[32];
		for (int i = 0; i < 16; i++) {
			hashhex[2*i] = hexmap[(hash[i]>>4)&0xF];
			hashhex[2*i+1] = hexmap[hash[i]&0xF];
		}
		
		PKCS5_PBKDF2_HMAC_SHA1 (hashhex,32,(unsigned char*)salt,saltlen,16,20,(unsigned char*)out);
	}
	static void calc_hmac(const unsigned char *data, int l, const unsigned char *key, bool hash_at_end, 
			unsigned char * hmac, unsigned int seq) {
		
		unsigned char temp[20];
		unsigned char data_temp[l];
		if (hash_at_end) memcpy(data_temp, data,   l-4);
		else             memcpy(data_temp,&data[4],l-4);
		data_temp[l-4] = (seq >> 24);
		data_temp[l-3] = (seq >> 16);
		data_temp[l-2] = (seq >>  8);
		data_temp[l-1] = (seq      );

		HMAC_SHA1 (data_temp,l,key,20,temp);
		
		memcpy(hmac,temp,4);
	}
};


class RC4Decoder {
private:
	unsigned char s[256];
	unsigned char i,j;
	inline void swap (unsigned char i, unsigned char j) {
		unsigned char t = s[i];
		s[i] = s[j];
		s[j] = t;
	}
public:
	RC4Decoder(const unsigned char * key, int keylen, int drop, bool zerodrop) {
		for (unsigned int k = 0; k < 256; k++) s[k] = k;
		i = j = 0;
		do {
			unsigned char k = key[i % keylen];
			j = (j + k + s[i]) & 0xFF;
			swap(i,j);
		} while (++i != 0);
		i = j = 0;
		
		unsigned char temp[drop];
		for (int k = 0; k < drop; k++) temp[k] = zerodrop ? 0 : k;
		cipher(temp,drop);
	}
	
	void cipher (unsigned char * data, int len) {
		while (len--) {
			i++;
			j += s[i];
			swap(i,j);
			unsigned char idx = s[i]+s[j];
			*data++ ^= s[idx];
		}
	}
};

class DataBuffer {
private:
	unsigned char * buffer;
	int blen, skip;
	unsigned char hmac[4];
public:
	int version;

	DataBuffer (const void * ptr, int size, int v) {
		if (ptr != NULL and size > 0) {
			buffer = (unsigned char*)malloc(size);
			memcpy(buffer,ptr,size);
			blen = size;
		}else{
			blen = 0;
			buffer = (unsigned char*)malloc(1024);
		}
		skip = 0;
		version = v;
		memset(hmac,0,4);
	}
	~DataBuffer() {
		free(buffer);
	}
	DataBuffer (const DataBuffer * d) {
		skip = d->skip;
		blen = d->blen;
		version = d->version;
		buffer = (unsigned char*)malloc(blen+1024);
		memcpy(buffer,d->buffer,blen);
		memcpy(hmac,d->hmac,4);
	}
	
	DataBuffer * decodedBuffer(RC4Decoder * decoder, int clength, bool dout) {
		DataBuffer * deco = new DataBuffer(this->buffer,clength,version);
		if (dout) decoder->cipher(&deco->buffer[0],clength-4);
		else      decoder->cipher(&deco->buffer[4],clength-4);
		return deco;
	}
	
	unsigned int getPacketHMAC(bool dout, int size) {
		unsigned int r;
		if (dout) memcpy(&r,&buffer[size-4],4);
		else memcpy(&r,&buffer[0],4);
		return r;
	}
	
	void getHMAC(unsigned char * p) {
		memcpy(p,hmac,4);
	}
	void setHMAC(const unsigned char * p) {
		memcpy(hmac,p,4);
	}
	void * getPtr() { return buffer; }
	void addData(void * ptr, int size) {
		if (ptr != NULL and size > 0) {
			buffer = (unsigned char*)realloc(buffer,blen+size);
			memcpy(&buffer[blen],ptr,size);
			blen += size;
		}
	}
	void popData(int size) {
		if (size > blen) {
			throw 0;
		}else{
			memmove(&buffer[0],&buffer[size],blen-size);
			blen -= size;
			buffer = (unsigned char*)realloc(buffer,blen+1);
		}
		skip += size;
	}
	void crunchData(int size) {
		if (size > blen) {
			throw 0;
		}else{
			blen -= size;
		}
	}
	int curr() { return skip; }
	int getInt(int nbytes, int offset = 0) {
		if (nbytes > blen)
			throw 0;
		int ret = 0;
		for (int i = 0; i < nbytes; i++) {
			ret <<= 8;
			ret |= buffer[i+offset];
		}
		return ret;
	}
	int readInt(int nbytes) {
		if (nbytes > blen)
			throw 0;
		int ret = getInt(nbytes);
		popData(nbytes);
		return ret;
	}
	
	int readListSize(proto_tree *tree, tvbuff_t *tvb) {
		if (blen == 0)
			throw 0;
		int ret;
		if (buffer[0] == 0xf8 or buffer[0] == 0xf3) {
			if (tree)
				proto_tree_add_item (tree, hf_whatsapp_nodesize8, tvb, curr()+1, 1, ENC_BIG_ENDIAN);
			ret = buffer[1];
			popData(2);
		}
		else if (buffer[0] == 0xf9) {
			if (tree)
				proto_tree_add_item (tree, hf_whatsapp_nodesize16, tvb, curr()+1, 2, ENC_BIG_ENDIAN);
			ret = getInt(2,1);
			popData(3);
		}
		else {
			// FIXME throw 0 error
			printf("Parse error! %d\n", (int)buffer[0]);
			return 0;
		}
		return ret;
	}
	std::string readRawString(int size) {
		if (size < 0 or size > blen)
			throw 0;
		std::string st(size,' ');
		memcpy(&st[0],buffer,size);
		popData(size);
		return st;
	}

	std::string readString(proto_tree *tree, tvbuff_t *tvb, EncodingKind encoding, int wa_version) {
		if (blen == 0)
			throw 0;
		int type = readInt(1);
		// Version specific
		int vn = (wa_version == 12) ? 0 : (wa_version == 14 ? 1 : 2);
		const int max_reg_dict[]          = { 245, 236, 236 };
		const EncodingManner enc[]        = { EncType12, EncType14, EncType15 };
		const EncodingManner encext[]     = { EncType12, EncType14Ext, EncType15Ext };
		const value_string * strlist[]    = { strings_list12, strings_list14, strings_list15 };
		const value_string * strlistext[] = { 0, strings_list_ext14, strings_list_ext15 };

		if (type > 2 and type < max_reg_dict[vn]) {
			proto_tree_add_item (tree, *encoding_table[encoding][enc[vn]], tvb, curr()-1, 1, ENC_NA);
			return std::string(strlist[vn][type].strptr);
		}
		else if (type == 0) {
			return "";
		}
		else if (type == 236) {
			// Extended Token
			proto_tree_add_item (tree, *encoding_table[encoding][enc[vn]],    tvb, curr()-1, 1, ENC_NA);
			proto_tree_add_item (tree, *encoding_table[encoding][encext[vn]], tvb, curr()  , 1, ENC_NA);
			type = readInt(1);

			return std::string(strlistext[vn][type].strptr);
		}
		else if (type == 0xfc) {
			int slen = readInt(1);
			proto_tree_add_item (tree, *encoding_table[encoding][EncTypePlain], tvb, curr(), slen, ENC_NA);
			return readRawString(slen);
		}
		else if (type == 0xfd) {
			int slen = readInt(3);
			proto_tree_add_item (tree, *encoding_table[encoding][EncTypePlain], tvb, curr(), slen, ENC_NA);
			return readRawString(slen);
		}
		else if (type == 0xfe) {
		   return getDecoded12(readInt(1)+0xf5);
		}
		else if (type == 0xfa) {
			proto_item * ti = 0; proto_tree * msg = 0; int ns = curr();
			if (tree != 0) {
				ti = proto_tree_add_item (tree, hf_whatsapp_userserver, tvb, curr(), 0, ENC_NA);
				msg = proto_item_add_subtree (ti, userserver_string);
			}

			std::string u = readString(msg,tvb,encoding, wa_version);
			std::string s = readString(msg,tvb,encoding, wa_version);
			
			if (ti)
				proto_item_set_len(ti,curr()-ns);
			
			if (u.size() > 0 and s.size() > 0)
				return u + "@" + s;
			else if (s.size() > 0)
				return s;
			return "";
		}
		else if (type == 0xff) {
			// Some sort of number encoding (using 4 bit)
			int nbyte = readInt(1);
			int size = nbyte & 0x7f;
			int numnibbles = size*2 - ((nbyte&0x80) ? 1 : 0);

			proto_item * hh = proto_tree_add_item (tree, hf_whatsapp_nibble_enc15, tvb, curr()-2, size+2, ENC_NA);

			std::string rawd = readRawString(size);
			std::string s;
			for (int i = 0; i < numnibbles; i++) {
				char c = (rawd[i/2] >> (4-((i&1)<<2))) & 0xF;
				if (c < 10) s += (c+'0');
				else s += (c-10+'-');
			}

			proto_item_append_text(hh, " (%s)", s.c_str());

			return s;
		}
		return "";
	}
	bool isList() {
		if (blen == 0)
			throw 0;
		return (buffer[0] == 248 or buffer[0] == 0 or buffer[0] == 249);
	}
	std::vector <Tree*> readList(proto_tree * tree , tvbuff_t *tvb,packet_info *pinfo, DissectSession * session) {
		std::vector <Tree*> l;
		int size = readListSize(0,0);
		while (size--) {
			l.push_back(session->read_tree(this,tree,tvb,pinfo));
		}
		return l;
	}
	int size() { return blen; }
};

class Tree {
private:
	std::map < std::string, std::string > attributes;
	std::vector < Tree* > children;
	std::string tag, data;
public:
	Tree() {}
	~Tree() {
		for (int i = 0; i < children.size(); i++)
			delete children[i];
	}
	
	void setTag(std::string tag) {
		this->tag = tag;
	}
	void readAttributes(DataBuffer * data, int size, proto_tree *tree, tvbuff_t *tvb, int wa_version) {
		int count = (size - 2 + (size % 2)) / 2;
		while (count--) {
			proto_item * ti; proto_tree * msg = 0; int ns = data->curr();
			if (tree) {
				ti = proto_tree_add_item (tree, hf_whatsapp_attribute, tvb, data->curr(), 0, ENC_NA);
				msg = proto_item_add_subtree (ti, tree_whatsapp);
			}

			std::string key   = data->readString(msg,tvb,TokenTypeKey,wa_version);
			std::string value = data->readString(msg,tvb,TokenTypeVal,wa_version);
			
			if (ti)
				proto_item_set_len(ti,data->curr()-ns);
			
			attributes[key] = value;
		}
	}
	void setData(std::string d) {
		data = d;
	}
	std::string getData() {
		return data;
	}
	void setChildren(std::vector < Tree* > c) {
		children = c;
	}
	std::string getAttr(const std::string & key) const {
		if (attributes.find(key) != attributes.end()) {
			return attributes.at("user");
		}
		return "";
	}
};

DissectSession::DissectSession (const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo) {
	found_auth = false;
	in = 0; out = 0;
	this->blist = new std::map < unsigned int, DataBuffer* >();
	this->dlist = new std::map < unsigned int, DataBuffer* >();
}
	
int DissectSession::dissect(const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo) {
	int rlen = 0;
	try {
		DataBuffer * d = new DataBuffer(data,len,wa_version);
	
		// Skip initial header
		if (d->getInt(1,0) == (int)'W' and d->getInt(1,1) == (int)'A' and
		    d->getInt(1,2) >= 0 and d->getInt(1,2) <= 9 and d->getInt(1,3) >= 0 and
		    d->getInt(1,3) <= 9 ) {
		    
		    	// Important to properly handle token parsing and ciphering
			wa_version = d->getInt(1,2) * 10 + d->getInt(1,3);

			d->popData(4);
		}
		if (d->size() <= 3) return 0;
	
		// Consume as many trees as possible
		Tree * t = NULL;
		int n = 0;
		do {
			t = next_tree(d,tree,tvb,pinfo);
			if (t != NULL) delete t;
		} while (t != NULL and d->size() >= 3);

		rlen = len - d->size();
		delete d;
	}catch (int n) {
		return 0;
	}
	return rlen;
}

Tree * DissectSession::next_tree(DataBuffer * data,proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo) {
	int bflag = (data->getInt(1) & 0xF0)>>4;
	int bsize = data->getInt(2,1);
	if (bsize > data->size()-3) {
		return NULL;  // Next message incomplete, return consumed data
	}

	proto_tree * msg = 0; proto_item *ti;
	if (tree) {
		ti = proto_tree_add_item (tree, whatsapp_msg, tvb, data->curr(), bsize+3, ENC_NA);
		msg = proto_item_add_subtree (ti, message_whatsapp);
		proto_tree_add_item (msg, hf_whatsapp_message, tvb, data->curr()+1, 2, ENC_BIG_ENDIAN);
		ti = proto_tree_add_item (msg, hf_whatsapp_attr_flags, tvb, data->curr(), 1, ENC_LITTLE_ENDIAN);

		proto_tree * msgf = proto_item_add_subtree(ti, tree_msg_flags);
		proto_tree_add_boolean (msgf, hf_whatsapp_attr_crypted, tvb, data->curr(), 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_boolean (msgf, hf_whatsapp_attr_compressed, tvb, data->curr(), 1, ENC_LITTLE_ENDIAN);
	}

	data->popData(3);	

	if (bflag & 8 || bflag & 1) {
		// Decode data, buffer conversion
		if (global_enable_decoding and found_auth) {
			DataBuffer * decoded_data;
			RC4Decoder * decoder = this->in;
			bool dataout = ADDRESSES_EQUAL(&server_addr,&pinfo->dst);
			if (dataout)
				decoder = out;
		
			unsigned int packet_hmac = data->getPacketHMAC(dataout,bsize);
			unsigned char hmac[4];
			if (blist->find(packet_hmac) != blist->end()) {
				decoded_data = new DataBuffer((*blist)[packet_hmac]);
				decoded_data->getHMAC(hmac);
			}else{
				unsigned char * skey = &session_key[0];
				if (wa_version == 14 || wa_version == 15) {
					skey = dataout ? &session_key[20*1] : &session_key[20*3];
				}
				
				KeyGenerator::calc_hmac((unsigned char*)data->getPtr(),bsize,skey,dataout,hmac,0);
				decoded_data = data->decodedBuffer(decoder,bsize,dataout || wa_version == 14 || wa_version == 15);
				decoded_data->setHMAC(hmac);
				(*blist)[packet_hmac] = new DataBuffer(decoded_data);
			}

			guint8* decrypted_buffer = (guint8*)g_malloc(bsize);
			memcpy(decrypted_buffer,decoded_data->getPtr(),bsize);
			tvbuff_t * decoded_tvb = tvb_new_child_real_data(tvb, decrypted_buffer, bsize, bsize);
			tvb_set_free_cb(decoded_tvb, g_free);
			add_new_data_source(pinfo, decoded_tvb, "Decrypted data");
		
			if (tree) {
				ti = proto_tree_add_item (msg, whatsapp_msg_crypted_payload, tvb, data->curr(), -1, ENC_NA);

				msg = proto_item_add_subtree (ti, message_whatsapp);
			
				proto_item * hh;
				if (dataout || wa_version == 14 || wa_version == 15) {
					hh = proto_tree_add_item (msg,hf_whatsapp_crypted_hmac_hash,
										decoded_tvb, bsize-4, 4, ENC_BIG_ENDIAN);
					ti = proto_tree_add_item (msg, whatsapp_msg_crypted_message,
										decoded_tvb, 0, bsize-4, ENC_NA);
					decoded_data->crunchData(4); // Remove hash
				}else{
					hh = proto_tree_add_item (msg,hf_whatsapp_crypted_hmac_hash,
										decoded_tvb, 0, 4, ENC_BIG_ENDIAN);
					ti = proto_tree_add_item (msg, whatsapp_msg_crypted_message,decoded_tvb, 4, -1, ENC_NA);
					decoded_data->popData(4); // Remove hash
				}
				proto_item_append_text(hh, " (calculated: 0x%02x%02x%02x%02x)",
										hmac[0],hmac[1],hmac[2],hmac[3]);
			
				msg = proto_item_add_subtree (ti, message_whatsapp);
			}

			if (bflag & 4) {
				DataBuffer * decomp_data;
				if (dlist->find(packet_hmac) != dlist->end()) {
					decomp_data = new DataBuffer((*dlist)[packet_hmac]);
				}else{
					// Deflate data
					int osize = decoded_data->size()*2+64;
					char tmpbuf[osize];
					size_t r = tinfl_decompress_mem_to_mem(tmpbuf, osize, decoded_data->getPtr(), decoded_data->size(), 1);

					decomp_data = new DataBuffer(tmpbuf, r, decoded_data->version);
					(*dlist)[packet_hmac] = new DataBuffer(decomp_data);
				}

				guint8* decompressed_buffer = (guint8*)g_malloc(decomp_data->size());
				memcpy(decompressed_buffer,decomp_data->getPtr(),decomp_data->size());
				tvbuff_t * decomp_tvb = tvb_new_child_real_data(decoded_tvb, decompressed_buffer, decomp_data->size(), decomp_data->size());
				tvb_set_free_cb(decomp_tvb, g_free);
				add_new_data_source(pinfo, decomp_tvb, "Decompressed data");

				ti = proto_tree_add_item (msg, whatsapp_msg_compressed_message,
									decomp_tvb, 0, decomp_data->size(), ENC_NA);
				msg = proto_item_add_subtree (ti, message_whatsapp);

				// Call recursive
				data->popData(bsize);     // Pop data for next parsing!
				return read_tree(decomp_data,msg,decomp_tvb,pinfo);
			}
		
			// Call recursive
			data->popData(bsize);     // Pop data for next parsing!
			return read_tree(decoded_data,msg,decoded_tvb,pinfo);
		
		}else{
			if (tree) {
				proto_tree_add_item (msg, whatsapp_msg_crypted_payload, tvb, data->curr(), -1, ENC_NA);
			}
			data->popData(bsize);
			return NULL;
		}
	}
	return read_tree(data,msg,tvb,pinfo);
}
	
Tree * DissectSession::read_tree(DataBuffer * data, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo) {
	proto_item * ti = proto_tree_add_item (tree, hf_whatsapp_node, tvb, data->curr(), 0, ENC_NA);
	proto_tree * msg = proto_item_add_subtree (ti, tree_whatsapp);
	int nstart = data->curr();

	int lsize = data->readListSize(msg,tvb);
	int type = data->getInt(1);
	if (type == 1) {
		data->popData(1);
		Tree * t = new Tree();
		t->readAttributes(data,lsize,msg,tvb,wa_version);
		t->setTag("start");
		proto_item_set_len(ti,data->curr()-nstart);
		return t;
	}else if (type == 2) {
		data->popData(1);
		proto_item_set_len(ti,data->curr()-nstart);
		return NULL; // No data in this tree...
	}
	std::string tag = data->readString(msg,tvb,TokenTypeTag, wa_version);
	Tree * t = new Tree();
	t->readAttributes(data,lsize,msg,tvb,wa_version);
	t->setTag(tag);

	// Look for the phone number
	if (tag == "auth")
		userphone = t->getAttr("user");

	if ((lsize & 1) == 1) {
		proto_item_set_len(ti,data->curr()-nstart);
		return t;
	}
	if (data->isList()) {
		std::vector <Tree*> l = data->readList(msg,tvb,pinfo,this);
		t->setChildren(l);
		proto_item_set_len(ti,data->curr()-nstart);
		return t;
	}
	int dstart = data->curr();
	t->setData(data->readString(msg,tvb,TokenTypeNValue, wa_version));
	proto_item_set_len(ti,data->curr()-nstart);

	// Check for challenge send
	if (tag == "challenge" and not found_auth) {
		challenge_data = t->getData();
		COPY_ADDRESS_CC(&server_addr,&pinfo->src);
		COPY_ADDRESS_CC(&client_addr,&pinfo->dst);
	}
	else if (tag == "response") {
		if (not found_auth) {
			COPY_ADDRESS_CC(&client_mac,&pinfo->dl_src);
			challenge_response = t->getData();
		
			found_auth = this->tryKeys();  // Try keys and find a good one
			unsigned char * in_key  = session_key;
			unsigned char * out_key = session_key;
			if (wa_version == 14 || wa_version == 15) {
				in_key  = &session_key[20*2];
				out_key = &session_key[20*0];
			}
			in = new RC4Decoder (in_key,  20, wa_version >= 14 ? 768 : 256, wa_version >= 14);
			out = new RC4Decoder(out_key, 20, wa_version >= 14 ? 768 : 256, wa_version >= 14);
		}

		// Decode the response data, to train the decoder
		DataBuffer * resp;
		
		unsigned char hmac[4];
		if (blist->find(0) != blist->end()) {
			resp = (*blist)[0];
			resp->getHMAC(hmac);
		}else{
			bool dataout = ADDRESSES_EQUAL(&server_addr,&pinfo->dst);
			
			unsigned char * skey = &session_key[0];
			if (wa_version == 14 || wa_version == 15) {
				skey = dataout ? &session_key[20*1] : &session_key[20*3];
			}

			DataBuffer * orig = new DataBuffer(t->getData().c_str(),t->getData().size(),wa_version);
			KeyGenerator::calc_hmac((unsigned char*)orig->getPtr(),orig->size(),skey,false,hmac,0);
			resp = orig->decodedBuffer(out,t->getData().size(),false);
			resp->setHMAC(hmac);

			(*blist)[0] = resp;
		}
	
		guint8* decrypted_buffer = (guint8*)malloc(resp->size());
		memcpy(decrypted_buffer,resp->getPtr(),resp->size());

		tvbuff_t * decoded_tvb = tvb_new_child_real_data(tvb, decrypted_buffer, t->getData().size(), t->getData().size());
		tvb_set_free_cb(decoded_tvb, g_free);
		add_new_data_source(pinfo, decoded_tvb, "Decrypted data");
		if (msg != 0) {
			ti = proto_tree_add_item(msg,whatsapp_msg_crypted_payload,tvb,dstart,t->getData().size(), ENC_NA);

			msg = proto_item_add_subtree (ti, message_whatsapp);
			proto_item *hh=proto_tree_add_item (msg, hf_whatsapp_crypted_hmac_hash,decoded_tvb, 0, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item (msg, whatsapp_msg_crypted_message,decoded_tvb, 4, -1, ENC_NA);
			
			proto_item_append_text(hh, " (calculated: 0x%02x%02x%02x%02x)",
						hmac[0],hmac[1],hmac[2],hmac[3]);
						
			if (wa_version == 14 || wa_version == 15) {
				proto_item_append_text(hh, " (session key: ");
				for (int i = 0; i < 20; i++) {
					if (i % 5 == 0)
						proto_item_append_text(hh, "%s: ", key_desc[i/5]);
					proto_item_append_text(hh, "%02x%02x%02x%02x ", 
						session_key[i*4+0], session_key[i*4+1], session_key[i*4+2], session_key[i*4+3]
					);
				}
			}else{
				proto_item_append_text(hh, " (session key: 0x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x"
					" %02x%02x%02x%02x%02x %02x%02x%02x%02x%02x )", 	
					session_key[0], session_key[1], session_key[2], session_key[3], session_key[4],
					session_key[5], session_key[6], session_key[7], session_key[8], session_key[9],
					session_key[10],session_key[11],session_key[12],session_key[13],session_key[14],
					session_key[15],session_key[16],session_key[17],session_key[18],session_key[19]);
			}
		}
	}

	return t;
}

// Decrypt the challenge response with the session key and search for the challenge data
// If we find a match it's likely that we have the good key
bool DissectSession::check_key() {
	if (challenge_response.size() < challenge_data.size())
		return false;
		
	// Decode the data
	std::string decoded = challenge_response.substr(4);
	RC4Decoder dec(session_key, 20, wa_version >= 14 ? 768 : 256, wa_version >= 14);
	dec.cipher((unsigned char*)decoded.c_str(),decoded.size());
		
	for (int i = 0; i < decoded.size()-challenge_data.size()+1; i++) {
		if (memcmp(challenge_data.c_str(),&decoded[i],challenge_data.size()) == 0) {
			return true;
		}
	}
	
	return false;
}

// Try to guess the session key
// We use the 3 IMEIs and the SRC MAC ADDR (iPhone)
bool DissectSession::tryKeys() {
	char * pass  = NULL;
	int i;
	for (i = 0; i < wa_userpass_uats_num; i++) {
		if (strcmp(wa_userpass_uats[i].username, userphone.c_str()) == 0) {
			pass = wa_userpass_uats[i].password;
			break;
		}
	}

	if (wa_version < 12) {
		KeyGenerator::generateKeyMAC (&client_mac,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
		if (check_key()) return true;
		KeyGenerator::generateKeyImei(global_imei_whatsapp_1,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
		if (check_key()) return true;
	}
	else if (wa_version == 12) {
		if (pass) {
			KeyGenerator::generateKeyV2(pass, challenge_data.c_str(), challenge_data.size(), (char*)session_key);
			return true;
		}
	}else{
		if (pass) {
			KeyGenerator::generateKeyV14(pass, challenge_data.c_str(), challenge_data.size(), (char*)session_key);
			return true;
		}
	}
	return false;
}

int whatsapp_data_dissect_tree(const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo) {
	conversation_t * conversation = find_or_create_conversation(pinfo);
	DissectSession * session = (DissectSession*)conversation_get_proto_data(conversation, proto_whatsapp);
	
	if (session == NULL) {
		session = new DissectSession(data,len,tree,tvb,pinfo);
		conversation_add_proto_data(conversation, proto_whatsapp, session);
	}

	return session->dissect(data,len,tree,tvb,pinfo);
}


// Packet length parser
int whatsapp_data_length(const char * data, int len) {
	try {
		int aclen = 0;
		DataBuffer * d = new DataBuffer(data,len, 14); //FIXME
		
		// Skip initial header
		if (	d->getInt(1,0) == (int)'W' and
			d->getInt(1,1) == (int)'A' and
			d->getInt(1,2) >= 0 and
			d->getInt(1,2) <= 9 and
			d->getInt(1,3) >= 0 and
			d->getInt(1,3) <= 9 ) {
			
			d->popData(4);
			aclen += 4;
		}
	
		// Consume as many trees as possible
		while (d->size() >= 3) {
			int bflag = (d->getInt(1) & 0xF0)>>4;
			int bsize = d->getInt(2,1);
			aclen += bsize+3;
			if (d->size() < bsize+3) break; // Not enough data for the next packet
			d->popData(bsize+3);
		}

		delete d;
		return aclen;
	}catch (int n) {
		return 0;
	}
}


static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static inline bool is_base64(unsigned char c) {
  return (isalnum(c) || (c == '+') || (c == '/'));
}
std::string base64_decode(std::string const& encoded_string) {
  int in_len = encoded_string.size();
  int i = 0;
  int j = 0;
  int in_ = 0;
  unsigned char char_array_4[4], char_array_3[3];
  std::string ret;

  while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
    char_array_4[i++] = encoded_string[in_]; in_++;
    if (i ==4) {
      for (i = 0; i <4; i++)
        char_array_4[i] = base64_chars.find(char_array_4[i]);

      char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
      char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
      char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

      for (i = 0; (i < 3); i++)
        ret += char_array_3[i];
      i = 0;
    }
  }

  if (i) {
    for (j = i; j <4; j++)
      char_array_4[j] = 0;

    for (j = 0; j <4; j++)
      char_array_4[j] = base64_chars.find(char_array_4[j]);

    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

    for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
  }

  return ret;
}


