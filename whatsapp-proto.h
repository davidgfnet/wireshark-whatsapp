
/*
 * WhatsApp protocol dissector
 * Written by David Guillen Fandos <david@davidgf.net>
 * Based on WhatsAPI sources
 *
 */


extern const char * global_imei_whatsapp_1;
extern gboolean global_enable_decoding;

typedef struct _wa_userpass_t {
    char* username;
    char* password;
} wa_userpass_t;
extern wa_userpass_t * wa_userpass_uats;
extern guint wa_userpass_uats_num;


int whatsapp_data_length(const char * data, int len);
int whatsapp_data_dissect_tree(const char * data, int len, proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo);

extern int hf_whatsapp_node;
extern int hf_whatsapp_nodesize8;
extern int hf_whatsapp_nodesize16;
extern int hf_whatsapp_attr_key;
extern int hf_whatsapp_attr_val;
extern int hf_whatsapp_attr_crypted;
extern int hf_whatsapp_attr_compressed;
extern int hf_whatsapp_attr_flags;
extern int hf_whatsapp_message;
extern int message_whatsapp;
extern int tree_whatsapp;
extern int userserver_string;
extern int tree_msg_flags;

extern int hf_whatsapp_userserver;
extern int hf_whatsapp_attribute;
extern int hf_whatsapp_attr_key_enc;
extern int hf_whatsapp_attr_val_enc;
extern int hf_whatsapp_attr_key_enc_ext;
extern int hf_whatsapp_attr_val_enc_ext;
extern int hf_whatsapp_attr_key_plain;
extern int hf_whatsapp_attr_val_plain;
extern int hf_whatsapp_tag_enc;
extern int hf_whatsapp_tag_enc_ext;
extern int hf_whatsapp_tag_plain;
extern int hf_whatsapp_nvalue_enc;
extern int hf_whatsapp_nvalue_enc_ext;
extern int hf_whatsapp_nibble_enc;
extern int hf_whatsapp_nvalue_plain;
extern int hf_whatsapp_crypted_hmac_hash;
extern int whatsapp_msg_crypted_message;
extern int whatsapp_msg_crypted_payload;
extern int whatsapp_msg_crypted_payload_mismatch;
extern int whatsapp_msg_compressed_message;
extern int whatsapp_msg;
extern int proto_whatsapp;

extern const value_string strings_list[];
extern const value_string strings_list_ext[];


