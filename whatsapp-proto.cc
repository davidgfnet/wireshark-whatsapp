
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

std::string base64_decode(std::string const& encoded_string);

class Tree; class DataBuffer; class KeyGenerator; class RC4Decoder;

class DissectSession {
private:
	// Current dissection classes
	address server_addr, client_addr, client_mac; // Identify server/client role
	RC4Decoder * in, * out;
	unsigned char session_key[20];
	std::string challenge_data, challenge_response;
	std::map < unsigned int, DataBuffer* > * blist;
	bool found_auth;

	bool check_key();
	bool tryKeys();

public:
	DissectSession (const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
	int dissect(const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
	Tree * next_tree(DataBuffer * data,proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
	Tree * read_tree(DataBuffer * data, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo);
};


#define COPY_ADDRESS_CC(to, from) { \
	guint8 *COPY_ADDRESS_data; \
	(to)->type = (from)->type; \
	(to)->len = (from)->len; \
	COPY_ADDRESS_data = (guint8*)g_malloc((from)->len); \
	memcpy(COPY_ADDRESS_data, (from)->data, (from)->len); \
	(to)->data = COPY_ADDRESS_data; \
	}


const char dictionary[256][40] = { "","","","","",  "account","ack","action","active","add","after",
	"ib","all","allow","apple","audio","auth","author","available","bad-protocol","bad-request",
	"before","Bell.caf","body","Boing.caf","cancel","category","challenge","chat","clean","code",
	"composing","config","conflict","contacts","count","create","creation","default","delay",
	"delete","delivered","deny","digest","DIGEST-MD5-1","DIGEST-MD5-2","dirty","elapsed","broadcast",
	"enable","encoding","duplicate","error","event","expiration","expired","fail","failure","false",
	"favorites","feature","features","field","first","free","from","g.us","get","Glass.caf","google",
	"group","groups","g_notify","g_sound","Harp.caf","http://etherx.jabber.org/streams",
	"http://jabber.org/protocol/chatstates","id","image","img","inactive","index","internal-server-error",
	"invalid-mechanism","ip","iq","item","item-not-found","user-not-found","jabber:iq:last","jabber:iq:privacy",
	"jabber:x:delay","jabber:x:event","jid","jid-malformed","kind","last","latitude","lc","leave","leave-all",
	"lg","list","location","longitude","max","max_groups","max_participants","max_subject","mechanism",
	"media","message","message_acks","method","microsoft","missing","modify","mute","name","nokia","none",
	"not-acceptable","not-allowed","not-authorized","notification","notify","off","offline","order","owner",
	"owning","paid","participant","participants","participating","password","paused","picture","pin","ping",
	"platform","pop_mean_time","pop_plus_minus","port","presence","preview","probe","proceed","prop","props",
	"p_o","p_t","query","raw","reason","receipt","receipt_acks","received","registration","relay",
	"remote-server-timeout","remove","Replaced by new connection","request","required","resource",
	"resource-constraint","response","result","retry","rim","s.whatsapp.net","s.us","seconds","server",
	"server-error","service-unavailable","set","show","sid","silent","sound","stamp","unsubscribe","stat",
	"status","stream:error","stream:features","subject","subscribe","success","sync","system-shutdown",
	"s_o","s_t","t","text","timeout","TimePassing.caf","timestamp","to","Tri-tone.caf","true","type",
	"unavailable","uri","url","urn:ietf:params:xml:ns:xmpp-sasl","urn:ietf:params:xml:ns:xmpp-stanzas",
	"urn:ietf:params:xml:ns:xmpp-streams","urn:xmpp:delay","urn:xmpp:ping","urn:xmpp:receipts",
	"urn:xmpp:whatsapp","urn:xmpp:whatsapp:account","urn:xmpp:whatsapp:dirty","urn:xmpp:whatsapp:mms",
	"urn:xmpp:whatsapp:push","user","username","value","vcard","version","video","w","w:g","w:p","w:p:r",
	"w:profile:picture","wait","x","xml-not-well-formed","xmlns","xmlns:stream","Xylophone.caf","1","WAUTH-1",
	"","","","","","","","","","","","XXX","","","","","","",""
};

std::string getDecoded(int n) {
	return std::string(dictionary[n]);
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
	static void generateKeyMAC(const address * macaddr, const char * salt, int saltlen, char * out) {
		unsigned char * ad = (unsigned char*)macaddr->data;
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
	static void calc_hmac(const unsigned char *data, int l, const unsigned char *key, bool hash_at_end, unsigned char * hmac) {
		unsigned char temp[20];
		if (hash_at_end) HMAC_SHA1 (data,l-4,key,20,temp);
		else HMAC_SHA1 (&data[4],l-4,key,20,temp);
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
	RC4Decoder(const unsigned char * key, int keylen, int drop) {
		for (unsigned int k = 0; k < 256; k++) s[k] = k;
		i = j = 0;
		do {
			unsigned char k = key[i % keylen];
			j = (j + k + s[i]) & 0xFF;
			swap(i,j);
		} while (++i != 0);
		i = j = 0;
		
		unsigned char temp[drop];
		for (int k = 0; k < drop; k++) temp[k] = k;
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
	DataBuffer (const void * ptr, int size) {
		if (ptr != NULL and size > 0) {
			buffer = (unsigned char*)malloc(size);
			memcpy(buffer,ptr,size);
			blen = size;
		}else{
			blen = 0;
			buffer = (unsigned char*)malloc(1024);
		}
		skip = 0;
		memset(hmac,0,4);
	}
	~DataBuffer() {
		free(buffer);
	}
	DataBuffer (const DataBuffer * d) {
		skip = d->skip;
		blen = d->blen;
		buffer = (unsigned char*)malloc(blen+1024);
		memcpy(buffer,d->buffer,blen);
		memcpy(hmac,d->hmac,4);
	}
	
	DataBuffer * decodedBuffer(RC4Decoder * decoder, int clength, bool dout) {
		DataBuffer * deco = new DataBuffer(this->buffer,clength);
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
			printf("Parse error!!\n");
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
	std::string readString(proto_tree *tree = 0, tvbuff_t *tvb = 0, int encoded = 0, int plain= 0) {
		if (blen == 0)
			throw 0;
		int type = readInt(1);
		if (type > 4 and type < 0xf5) {
			proto_tree_add_item (tree, encoded, tvb, curr()-1, 1, ENC_NA);
			return getDecoded(type);
		}
		else if (type == 0) {
			return "";
		}
		else if (type == 0xfc) {
			int slen = readInt(1);
			proto_tree_add_item (tree, plain, tvb, curr(), slen, ENC_NA);
			return readRawString(slen);
		}
		else if (type == 0xfd) {
			int slen = readInt(3);
			proto_tree_add_item (tree, plain, tvb, curr(), slen, ENC_NA);
			return readRawString(slen);
		}
		else if (type == 0xfe) {
			return getDecoded(readInt(1)+0xf5);
		}
		else if (type == 0xfa) {
			proto_item * ti = 0; proto_tree * msg = 0; int ns = curr();
			if (tree != 0) {
				ti = proto_tree_add_item (tree, hf_whatsapp_userserver, tvb, curr(), 0, ENC_NA);
				msg = proto_item_add_subtree (ti, userserver_string);
			}

			std::string u = readString(msg,tvb,encoded,plain);
			std::string s = readString(msg,tvb,encoded,plain);
			
			if (ti)
				proto_item_set_len(ti,curr()-ns);
			
			if (u.size() > 0 and s.size() > 0)
				return u + "@" + s;
			else if (s.size() > 0)
				return s;
			return "";
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
	void readAttributes(DataBuffer * data, int size, proto_tree *tree = 0, tvbuff_t *tvb = 0) {
		int count = (size - 2 + (size % 2)) / 2;
		while (count--) {
			proto_item * ti; proto_tree * msg = 0; int ns = data->curr();
			if (tree) {
				ti = proto_tree_add_item (tree, hf_whatsapp_attribute, tvb, data->curr(), 0, ENC_NA);
				msg = proto_item_add_subtree (ti, tree_whatsapp);
			}

			std::string key = data->readString(msg,tvb,hf_whatsapp_attr_key_enc,hf_whatsapp_attr_key_plain);
			std::string value = data->readString(msg,tvb,hf_whatsapp_attr_val_enc,hf_whatsapp_attr_val_plain);
			
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
};

DissectSession::DissectSession (const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo) {
	found_auth = false;
	in = 0; out = 0;
	this->blist = new std::map < unsigned int, DataBuffer* >();
}
	
int DissectSession::dissect(const char * data, int len, proto_tree *tree, tvbuff_t *tvb,packet_info *pinfo) {
	try {
		DataBuffer * d = new DataBuffer(data,len);
	
		// Skip initial header
		if (d->getInt(1,0) == (int)'W' and d->getInt(1,1) == (int)'A' and
		    d->getInt(1,2) >= 0 and d->getInt(1,2) <= 9 and d->getInt(1,3) >= 0 and
		    d->getInt(1,3) <= 9 ) {
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

		delete d;
	}catch (int n) {
		return 0;
	}
	return 0;
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
		proto_tree_add_item (msg, hf_whatsapp_attr_flags, tvb, data->curr(), 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item (msg, hf_whatsapp_attr_crypted, tvb, data->curr(), 1, ENC_LITTLE_ENDIAN);
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
				KeyGenerator::calc_hmac((unsigned char*)data->getPtr(),bsize,session_key,dataout,hmac);
				decoded_data = data->decodedBuffer(decoder,bsize,dataout);
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
				if (dataout) {
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
		t->readAttributes(data,lsize,msg,tvb);
		t->setTag("start");
		proto_item_set_len(ti,data->curr()-nstart);
		return t;
	}else if (type == 2) {
		data->popData(1);
		proto_item_set_len(ti,data->curr()-nstart);
		return NULL; // No data in this tree...
	}
	std::string tag = data->readString(msg,tvb,hf_whatsapp_tag_enc,hf_whatsapp_tag_plain);
	Tree * t = new Tree();
	t->readAttributes(data,lsize,msg,tvb);
	t->setTag(tag);
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
	t->setData(data->readString(msg,tvb,hf_whatsapp_nvalue_enc,hf_whatsapp_nvalue_plain));
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
			in = new RC4Decoder(session_key, 20, 256);
			out = new RC4Decoder(session_key, 20, 256);
		}

		// Decode the response data, to train the decoder
		DataBuffer * resp;
		
		unsigned char hmac[4];
		if (blist->find(0) != blist->end()) {
			resp = (*blist)[0];
			resp->getHMAC(hmac);
		}else{
			DataBuffer * orig = new DataBuffer(t->getData().c_str(),t->getData().size());
			KeyGenerator::calc_hmac((unsigned char*)orig->getPtr(),orig->size(),session_key,false,hmac);
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
	RC4Decoder dec(session_key, 20, 256);
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
	KeyGenerator::generateKeyMAC (&client_mac,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
	if (check_key()) return true;
	KeyGenerator::generateKeyImei(global_imei_whatsapp_1,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
	if (check_key()) return true;
	KeyGenerator::generateKeyImei(global_imei_whatsapp_2,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
	if (check_key()) return true;
	KeyGenerator::generateKeyImei(global_imei_whatsapp_3,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
	if (check_key()) return true;
	KeyGenerator::generateKeyV2(global_v2pw_whatsapp_1,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
	if (check_key()) return true;
	KeyGenerator::generateKeyV2(global_v2pw_whatsapp_2,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
	if (check_key()) return true;
	KeyGenerator::generateKeyV2(global_v2pw_whatsapp_3,challenge_data.c_str(),challenge_data.size(),(char*)session_key);
	if (check_key()) return true;
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
		DataBuffer * d = new DataBuffer(data,len);
		
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


