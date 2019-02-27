
/*
 * WhatsApp protocol dissector
 * Written by David Guillen Fandos <david@davidgf.net>
 * Based on WhatsAPI sources
 *
 */


#include <config.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>

#define WHATSAPP_PORT 5222
#define WHATSAPP_PORT_NEW 443

int whatsapp_data_length(const char * data, int len);
int whatsapp_data_dissect_tree(const char * data, int len, proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo);

const char * global_imei_whatsapp_1 = 0;
gboolean global_enable_decoding;
int proto_whatsapp = -1;
int message_whatsapp = -1;
int userserver_string = -1;
int tree_whatsapp = -1;
int tree_msg_flags = -1;
static gint ett_whatsapp = -1;
int whatsapp_msg_crypted_payload = -1;
int whatsapp_msg_crypted_payload_mismatch = -1;
int whatsapp_msg_crypted_message = -1;
int whatsapp_msg_compressed_message = -1;

/* Variables for whatsapp packets */
int hf_whatsapp_message = -1;
int hf_whatsapp_node = -1;
int hf_whatsapp_nodesize16 = -1;
int hf_whatsapp_nodesize8 = -1;
int hf_whatsapp_attr_key_enc = -1;
int hf_whatsapp_attr_val_enc = -1;
int hf_whatsapp_attr_key_enc_ext = -1;
int hf_whatsapp_attr_val_enc_ext = -1;
int hf_whatsapp_attr_key_plain = -1;
int hf_whatsapp_attr_val_plain = -1;
int hf_whatsapp_attr_crypted = -1;
int hf_whatsapp_attr_compressed = -1;
int hf_whatsapp_attr_flags = -1;
int hf_whatsapp_attribute = -1;
int hf_whatsapp_tag_enc = -1;
int hf_whatsapp_tag_enc_ext = -1;
int hf_whatsapp_tag_plain = -1;
int hf_whatsapp_nvalue_enc = -1;
int hf_whatsapp_nvalue_enc_ext = -1;
int hf_whatsapp_nibble_enc = -1;
int hf_whatsapp_nvalue_plain = -1;
int hf_whatsapp_crypted_hmac_hash = -1;
int hf_whatsapp_userserver = -1;

const value_string strings_list[];
const value_string strings_list_ext[];

int whatsapp_msg = -1;

#define MIN_PAKCET_SIZE 4

typedef struct _wa_userpass_t {
    char* username;
    char* password;
} wa_userpass_t;

wa_userpass_t * wa_userpass_uats = NULL;
guint wa_userpass_uats_num = 0;

UAT_CSTRING_CB_DEF(wa_userpass_uats,username,wa_userpass_t)
UAT_CSTRING_CB_DEF(wa_userpass_uats,password,wa_userpass_t)

static uat_t * wa_userpass_uat = NULL;

void waup_free_cb(void* r) {
  wa_userpass_t* h = (wa_userpass_t*)r;

  g_free(h->username);
  g_free(h->password);
}
void * waup_copy_cb(void* dest, const void* orig, size_t len _U_) {
  const wa_userpass_t* o = (const wa_userpass_t*)orig;
  wa_userpass_t*       d = (wa_userpass_t*)dest;

  d->username = g_strdup(o->username);
  d->password = g_strdup(o->password);
  return d;
}

gboolean fld_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, const char ** err) {
  return TRUE;
}

static guint get_whatsapp_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
  int length = tvb_length(tvb)-offset;
  guint8* buffer = tvb_memdup(NULL, tvb, offset, length);
  int wa_len = whatsapp_data_length(buffer, length);
  g_free(buffer);
  return wa_len;
}

static int dissect_whatsapp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "WhatsApp XMPP protocol packet");
  col_clear (pinfo->cinfo, COL_INFO);
  int r = 0;

  if (tree) {
    proto_item *ti = proto_tree_add_item (tree, proto_whatsapp, tvb, 0,-1, ENC_NA);
    proto_tree * subtree = proto_item_add_subtree (ti, message_whatsapp);

    int length = tvb_length(tvb);
    guint8* buffer = tvb_memdup(NULL, tvb, 0, length);
    r = whatsapp_data_dissect_tree(buffer, length, subtree, tvb, pinfo);
    g_free(buffer);
  }
  return r;
}

static int dissect_whatsapp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * u) {
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MIN_PAKCET_SIZE,
                     get_whatsapp_message_len, dissect_whatsapp_message);
  return get_whatsapp_message_len(pinfo, tvb, 0);
}
void proto_reg_handoff_whatsapp(void);

void proto_register_whatsapp(void) {
  static hf_register_info hf_whatsapp[] = {
    { &whatsapp_msg,
        { "Message", "whatsapp.message",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &whatsapp_msg_crypted_payload,
        { "Crypted payload", "whatsapp.payload",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &whatsapp_msg_crypted_payload_mismatch,
        { "Crypted payload (version mismatch!)", "whatsapp.payload",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &whatsapp_msg_crypted_message,
        { "Crypted message", "whatsapp.crypted_message",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &whatsapp_msg_compressed_message,
        { "Crypted message", "whatsapp.compressed_message",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },

    { &hf_whatsapp_message,
        { "Message size", "whatsapp.message",
          FT_UINT24, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_node,
        { "Node", "whatsapp.node",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_nodesize16,
        { "Size", "whatsapp.node",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attribute,
        { "Attribute", "whatsapp.attr",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_userserver,
        { "User@Server", "whatsapp.userserver",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_nodesize8,
        { "Size", "whatsapp.node",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL },
    },
	// Version 1.6 key+val+tag+nval (+exts)
    { &hf_whatsapp_attr_key_enc,
        { "Key", "whatsapp.keyenc",
          FT_UINT8, BASE_DEC,
          VALS(strings_list), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attr_val_enc,
        { "Value", "whatsapp.valueenc",
          FT_UINT8, BASE_DEC,
          VALS(strings_list), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attr_key_enc_ext,
        { "Key", "whatsapp.keyencext",
          FT_UINT16, BASE_DEC,
          VALS(strings_list_ext), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attr_val_enc_ext,
        { "Value", "whatsapp.valueencext",
          FT_UINT16, BASE_DEC,
          VALS(strings_list_ext), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_tag_enc,
        { "Tag", "whatsapp.tagenc",
          FT_UINT8, BASE_DEC,
          VALS(strings_list), 0x0,
          NULL, HFILL },
    },    
    { &hf_whatsapp_tag_enc_ext,
        { "Tag", "whatsapp.tagencext",
          FT_UINT16, BASE_DEC,
          VALS(strings_list_ext), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_nvalue_enc,
        { "Value", "whatsapp.nodevalueenc",
          FT_UINT8, BASE_DEC,
          VALS(strings_list), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_nvalue_enc_ext,
        { "Value", "whatsapp.nodevalueencext",
          FT_UINT16, BASE_DEC,
          VALS(strings_list_ext), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_nibble_enc,
        { "Nibble encoded number", "whatsapp.nibbleencoded",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
	// No encryption
    { &hf_whatsapp_attr_key_plain,
        { "Key", "whatsapp.keyplain",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attr_val_plain,
        { "Value", "whatsapp.valueplain",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_tag_plain,
        { "Tag", "whatsapp.tagplain",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_nvalue_plain,
        { "Value", "whatsapp.nodevalueplain",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },

    { &hf_whatsapp_attr_flags,
        { "Flags", "whatsapp.flags",
          FT_UINT8, BASE_HEX,
          NULL, 0xF0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attr_crypted,
        { "Crypted", "whatsapp.crypted",
          FT_BOOLEAN, BASE_NONE,
          TFS(&tfs_set_notset), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attr_compressed,
        { "Compressed", "whatsapp.compressed",
          FT_BOOLEAN, BASE_NONE,
          TFS(&tfs_set_notset), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_crypted_hmac_hash,
        { "HMAC-SHA1", "whatsapp.crypt_hash",
          FT_UINT32, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL },
    }
  };
  static gint *ett_whatsapp_arr[] = { /* protocol subtree array */
    &message_whatsapp,
    &tree_whatsapp,
    &userserver_string,
	&tree_msg_flags
  };
  proto_whatsapp = proto_register_protocol(
    "WhatsApp XMPP protocol", "WhatsApp", "whatsapp");
  proto_register_field_array (proto_whatsapp, hf_whatsapp, array_length (hf_whatsapp));
  proto_register_subtree_array (ett_whatsapp_arr, array_length (ett_whatsapp_arr));
  
  struct pref_module * whatsapp_module = 
		(struct pref_module *)prefs_register_protocol(proto_whatsapp, proto_reg_handoff_whatsapp);
  prefs_register_string_preference(whatsapp_module, "imei1",
				 "Phone IMEI (1)",
				 "Telephone IMEI to use as key",
				 &global_imei_whatsapp_1);

  static uat_field_t wa_auth_uats_flds[] = {
    UAT_FLD_CSTRING_OTHER(wa_userpass_uats, username, "Phone",    fld_chk_cb, "Whatapp phone number username"),
    UAT_FLD_CSTRING_OTHER(wa_userpass_uats, password, "Password", fld_chk_cb, "Whatapp account password (base64 encoded)"),
    UAT_END_FIELDS
  };

  wa_userpass_uat = uat_new("WhatsApp accounts",
                            sizeof(wa_userpass_t),
                            "wauserpasstable",              /* filename */
                            TRUE,                           /* from_profile */
                            &wa_userpass_uats,              /* data_ptr */
                            &wa_userpass_uats_num,          /* numitems_ptr */
                            UAT_AFFECTS_DISSECTION,         /* affects dissection of packets, but not set of named fields */
                            "WAUSERPASS_DOC",
                            waup_copy_cb,
                            NULL,
                            waup_free_cb,
                            NULL,
                            NULL,
                            wa_auth_uats_flds);

  prefs_register_uat_preference(whatsapp_module, "cfg",
                                  "Whatsapp user/pass list",
                                  "A table for phones and passwords to decrypt conversations",
                                  wa_userpass_uat);

  prefs_register_bool_preference(whatsapp_module, "enable_decoding",
				 "Enable packet decoding",
				 "Decodes network traffic if possible",
				 &global_enable_decoding);
}

void proto_reg_handoff_whatsapp(void) {
  static dissector_handle_t whatsapp_handle;
  whatsapp_handle = new_create_dissector_handle (dissect_whatsapp, proto_whatsapp);
  dissector_add_uint ("tcp.port", WHATSAPP_PORT, whatsapp_handle);
  dissector_add_uint ("tcp.port", WHATSAPP_PORT_NEW, whatsapp_handle);
}



const value_string strings_list[] = {
	{ 0, "" },
	{ 1, "" },
	{ 2, "" },
	{ 3, "account" },
	{ 4, "ack" },
	{ 5, "action" },
	{ 6, "active" },
	{ 7, "add" },
	{ 8, "after" },
	{ 9, "all" },
	{ 10, "allow" },
	{ 11, "apple" },
	{ 12, "audio" },
	{ 13, "auth" },
	{ 14, "author" },
	{ 15, "available" },
	{ 16, "bad-protocol" },
	{ 17, "bad-request" },
	{ 18, "before" },
	{ 19, "bits" },
	{ 20, "body" },
	{ 21, "broadcast" },
	{ 22, "cancel" },
	{ 23, "category" },
	{ 24, "challenge" },
	{ 25, "chat" },
	{ 26, "clean" },
	{ 27, "code" },
	{ 28, "composing" },
	{ 29, "config" },
	{ 30, "contacts" },
	{ 31, "count" },
	{ 32, "create" },
	{ 33, "creation" },
	{ 34, "debug" },
	{ 35, "default" },
	{ 36, "delete" },
	{ 37, "delivery" },
	{ 38, "delta" },
	{ 39, "deny" },
	{ 40, "digest" },
	{ 41, "dirty" },
	{ 42, "duplicate" },
	{ 43, "elapsed" },
	{ 44, "enable" },
	{ 45, "encoding" },
	{ 46, "encrypt" },
	{ 47, "error" },
	{ 48, "event" },
	{ 49, "expiration" },
	{ 50, "expired" },
	{ 51, "fail" },
	{ 52, "failure" },
	{ 53, "false" },
	{ 54, "favorites" },
	{ 55, "feature" },
	{ 56, "features" },
	{ 57, "feature-not-implemented" },
	{ 58, "field" },
	{ 59, "file" },
	{ 60, "filehash" },
	{ 61, "first" },
	{ 62, "free" },
	{ 63, "from" },
	{ 64, "g.us" },
	{ 65, "gcm" },
	{ 66, "get" },
	{ 67, "google" },
	{ 68, "group" },
	{ 69, "groups" },
	{ 70, "groups_v2" },
	{ 71, "http://etherx.jabber.org/streams" },
	{ 72, "http://jabber.org/protocol/chatstates" },
	{ 73, "ib" },
	{ 74, "id" },
	{ 75, "image" },
	{ 76, "img" },
	{ 77, "index" },
	{ 78, "internal-server-error" },
	{ 79, "ip" },
	{ 80, "iq" },
	{ 81, "item-not-found" },
	{ 82, "item" },
	{ 83, "jabber:iq:last" },
	{ 84, "jabber:iq:privacy" },
	{ 85, "jabber:x:event" },
	{ 86, "jid" },
	{ 87, "kind" },
	{ 88, "last" },
	{ 89, "leave" },
	{ 90, "list" },
	{ 91, "max" },
	{ 92, "mechanism" },
	{ 93, "media" },
	{ 94, "message_acks" },
	{ 95, "message" },
	{ 96, "method" },
	{ 97, "microsoft" },
	{ 98, "mimetype" },
	{ 99, "missing" },
	{ 100, "modify" },
	{ 101, "msg" },
	{ 102, "mute" },
	{ 103, "name" },
	{ 104, "nokia" },
	{ 105, "none" },
	{ 106, "not-acceptable" },
	{ 107, "not-allowed" },
	{ 108, "not-authorized" },
	{ 109, "notification" },
	{ 110, "notify" },
	{ 111, "off" },
	{ 112, "offline" },
	{ 113, "order" },
	{ 114, "owner" },
	{ 115, "owning" },
	{ 116, "p_o" },
	{ 117, "p_t" },
	{ 118, "paid" },
	{ 119, "participant" },
	{ 120, "participants" },
	{ 121, "participating" },
	{ 122, "paused" },
	{ 123, "picture" },
	{ 124, "pin" },
	{ 125, "ping" },
	{ 126, "pkmsg" },
	{ 127, "platform" },
	{ 128, "port" },
	{ 129, "presence" },
	{ 130, "preview" },
	{ 131, "probe" },
	{ 132, "prop" },
	{ 133, "props" },
	{ 134, "qcount" },
	{ 135, "query" },
	{ 136, "raw" },
	{ 137, "read" },
	{ 138, "readreceipts" },
	{ 139, "reason" },
	{ 140, "receipt" },
	{ 141, "relay" },
	{ 142, "remote-server-timeout" },
	{ 143, "remove" },
	{ 144, "request" },
	{ 145, "required" },
	{ 146, "resource-constraint" },
	{ 147, "resource" },
	{ 148, "response" },
	{ 149, "result" },
	{ 150, "retry" },
	{ 151, "rim" },
	{ 152, "s_o" },
	{ 153, "s_t" },
	{ 154, "s.us" },
	{ 155, "s.whatsapp.net" },
	{ 156, "seconds" },
	{ 157, "server-error" },
	{ 158, "server" },
	{ 159, "service-unavailable" },
	{ 160, "set" },
	{ 161, "show" },
	{ 162, "silent" },
	{ 163, "size" },
	{ 164, "skmsg" },
	{ 165, "stat" },
	{ 166, "state" },
	{ 167, "status" },
	{ 168, "stream:error" },
	{ 169, "stream:features" },
	{ 170, "subject" },
	{ 171, "subscribe" },
	{ 172, "success" },
	{ 173, "sync" },
	{ 174, "t" },
	{ 175, "text" },
	{ 176, "timeout" },
	{ 177, "timestamp" },
	{ 178, "tizen" },
	{ 179, "to" },
	{ 180, "true" },
	{ 181, "type" },
	{ 182, "unavailable" },
	{ 183, "unsubscribe" },
	{ 184, "upgrade" },
	{ 185, "uri" },
	{ 186, "url" },
	{ 187, "urn:ietf:params:xml:ns:xmpp-sasl" },
	{ 188, "urn:ietf:params:xml:ns:xmpp-stanzas" },
	{ 189, "urn:ietf:params:xml:ns:xmpp-streams" },
	{ 190, "urn:xmpp:ping" },
	{ 191, "urn:xmpp:whatsapp:account" },
	{ 192, "urn:xmpp:whatsapp:dirty" },
	{ 193, "urn:xmpp:whatsapp:mms" },
	{ 194, "urn:xmpp:whatsapp:push" },
	{ 195, "urn:xmpp:whatsapp" },
	{ 196, "user" },
	{ 197, "user-not-found" },
	{ 198, "v" },
	{ 199, "value" },
	{ 200, "version" },
	{ 201, "voip" },
	{ 202, "w:g" },
	{ 203, "w:p:r" },
	{ 204, "w:p" },
	{ 205, "w:profile:picture" },
	{ 206, "w" },
	{ 207, "wait" },
	{ 208, "WAUTH-2" },
	{ 209, "xmlns:stream" },
	{ 210, "xmlns" },
	{ 211, "1" },
	{ 212, "chatstate" },
	{ 213, "crypto" },
	{ 214, "phash" },
	{ 215, "enc" },
	{ 216, "class" },
	{ 217, "off_cnt" },
	{ 218, "w:g2" },
	{ 219, "promote" },
	{ 220, "demote" },
	{ 221, "creator" },
	{ 222, "background" },
	{ 223, "backoff" },
	{ 224, "chunked" },
	{ 225, "context" },
	{ 226, "full" },
	{ 227, "in" },
	{ 228, "interactive" },
	{ 229, "out" },
	{ 230, "registration" },
	{ 231, "sid" },
	{ 232, "urn:xmpp:whatsapp:sync" },
	{ 233, "flt" },
	{ 234, "s16" },
	{ 235, "u8" },
	{ 236, "Extended-Dict-1"},
	{ 237, "" },
	{ 238, "" },
	{ 239, "" },
	{ 240, "" },
	{ 241, "" },
	{ 242, "" },
	{ 243, "" },
	{ 244, "" },
	{ 245, "" },
	{ 246, "" },
	{ 247, "" },
	{ 248, "" },
	{ 249, "" },
	{ 250, "" },
	{ 251, "" },
	{ 252, "" },
	{ 253, "" },
	{ 254, "" },
	{ 255, "" },
	{0,NULL}
};

const value_string strings_list_ext[] = {
	{ 0, "adpcm" },
	{ 1, "amrnb" },
	{ 2, "amrwb" },
	{ 3, "mp3" },
	{ 4, "pcm" },
	{ 5, "qcelp" },
	{ 6, "wma" },
	{ 7, "h263" },
	{ 8, "h264" },
	{ 9, "jpeg" },
	{ 10, "mpeg4" },
	{ 11, "wmv" },
	{ 12, "audio/3gpp" },
	{ 13, "audio/aac" },
	{ 14, "audio/amr" },
	{ 15, "audio/mp4" },
	{ 16, "audio/mpeg" },
	{ 17, "audio/ogg" },
	{ 18, "audio/qcelp" },
	{ 19, "audio/wav" },
	{ 20, "audio/webm" },
	{ 21, "audio/x-caf" },
	{ 22, "audio/x-ms-wma" },
	{ 23, "image/gif" },
	{ 24, "image/jpeg" },
	{ 25, "image/png" },
	{ 26, "video/3gpp" },
	{ 27, "video/avi" },
	{ 28, "video/mp4" },
	{ 29, "video/mpeg" },
	{ 30, "video/quicktime" },
	{ 31, "video/x-flv" },
	{ 32, "video/x-ms-asf" },
	{ 33, "302" },
	{ 34, "400" },
	{ 35, "401" },
	{ 36, "402" },
	{ 37, "403" },
	{ 38, "404" },
	{ 39, "405" },
	{ 40, "406" },
	{ 41, "407" },
	{ 42, "409" },
	{ 43, "410" },
	{ 44, "500" },
	{ 45, "501" },
	{ 46, "503" },
	{ 47, "504" },
	{ 48, "abitrate" },
	{ 49, "acodec" },
	{ 50, "app_uptime" },
	{ 51, "asampfmt" },
	{ 52, "asampfreq" },
	{ 53, "clear" },
	{ 54, "conflict" },
	{ 55, "conn_no_nna" },
	{ 56, "cost" },
	{ 57, "currency" },
	{ 58, "duration" },
	{ 59, "extend" },
	{ 60, "fps" },
	{ 61, "g_notify" },
	{ 62, "g_sound" },
	{ 63, "gone" },
	{ 64, "google_play" },
	{ 65, "hash" },
	{ 66, "height" },
	{ 67, "invalid" },
	{ 68, "jid-malformed" },
	{ 69, "latitude" },
	{ 70, "lc" },
	{ 71, "lg" },
	{ 72, "live" },
	{ 73, "location" },
	{ 74, "log" },
	{ 75, "longitude" },
	{ 76, "max_groups" },
	{ 77, "max_participants" },
	{ 78, "max_subject" },
	{ 79, "mode" },
	{ 80, "napi_version" },
	{ 81, "normalize" },
	{ 82, "orighash" },
	{ 83, "origin" },
	{ 84, "passive" },
	{ 85, "password" },
	{ 86, "played" },
	{ 87, "policy-violation" },
	{ 88, "pop_mean_time" },
	{ 89, "pop_plus_minus" },
	{ 90, "price" },
	{ 91, "pricing" },
	{ 92, "redeem" },
	{ 93, "Replaced by new connection" },
	{ 94, "resume" },
	{ 95, "signature" },
	{ 96, "sound" },
	{ 97, "source" },
	{ 98, "system-shutdown" },
	{ 99, "username" },
	{ 100, "vbitrate" },
	{ 101, "vcard" },
	{ 102, "vcodec" },
	{ 103, "video" },
	{ 104, "width" },
	{ 105, "xml-not-well-formed" },
	{ 106, "checkmarks" },
	{ 107, "image_max_edge" },
	{ 108, "image_max_kbytes" },
	{ 109, "image_quality" },
	{ 110, "ka" },
	{ 111, "ka_grow" },
	{ 112, "ka_shrink" },
	{ 113, "newmedia" },
	{ 114, "library" },
	{ 115, "caption" },
	{ 116, "forward" },
	{ 117, "c0" },
	{ 118, "c1" },
	{ 119, "c2" },
	{ 120, "c3" },
	{ 121, "clock_skew" },
	{ 122, "cts" },
	{ 123, "k0" },
	{ 124, "k1" },
	{ 125, "login_rtt" },
	{ 126, "m_id" },
	{ 127, "nna_msg_rtt" },
	{ 128, "nna_no_off_count" },
	{ 129, "nna_offline_ratio" },
	{ 130, "nna_push_rtt" },
	{ 131, "no_nna_con_count" },
	{ 132, "off_msg_rtt" },
	{ 133, "on_msg_rtt" },
	{ 134, "stat_name" },
	{ 135, "sts" },
	{ 136, "suspect_conn" },
	{ 137, "lists" },
	{ 138, "self" },
	{ 139, "qr" },
	{ 140, "web" },
	{ 141, "w:b" },
	{ 142, "recipient" },
	{ 143, "w:stats" },
	{ 144, "forbidden" },
	{ 145, "max_list_recipients" },
	{ 146, "en-AU" },
	{ 147, "en-GB" },
	{ 148, "es-MX" },
	{ 149, "pt-PT" },
	{ 150, "zh-Hans" },
	{ 151, "zh-Hant" },
	{ 152, "relayelection" },
	{ 153, "relaylatency" },
	{ 154, "interruption" },
	{ 155, "Bell.caf" },
	{ 156, "Boing.caf" },
	{ 157, "Glass.caf" },
	{ 158, "Harp.caf" },
	{ 159, "TimePassing.caf" },
	{ 160, "Tri-tone.caf" },
	{ 161, "Xylophone.caf" },
	{ 162, "aurora.m4r" },
	{ 163, "bamboo.m4r" },
	{ 164, "chord.m4r" },
	{ 165, "circles.m4r" },
	{ 166, "complete.m4r" },
	{ 167, "hello.m4r" },
	{ 168, "input.m4r" },
	{ 169, "keys.m4r" },
	{ 170, "note.m4r" },
	{ 171, "popcorn.m4r" },
	{ 172, "pulse.m4r" },
	{ 173, "synth.m4r" },
	{ 174, "Apex.m4r" },
	{ 175, "Beacon.m4r" },
	{ 176, "Bulletin.m4r" },
	{ 177, "By The Seaside.m4r" },
	{ 178, "Chimes.m4r" },
	{ 179, "Circuit.m4r" },
	{ 180, "Constellation.m4r" },
	{ 181, "Cosmic.m4r" },
	{ 182, "Crystals.m4r" },
	{ 183, "Hillside.m4r" },
	{ 184, "Illuminate.m4r" },
	{ 185, "Night Owl.m4r" },
	{ 186, "Opening.m4r" },
	{ 187, "Playtime.m4r" },
	{ 188, "Presto.m4r" },
	{ 189, "Radar.m4r" },
	{ 190, "Radiate.m4r" },
	{ 191, "Ripples.m4r" },
	{ 192, "Sencha.m4r" },
	{ 193, "Signal.m4r" },
	{ 194, "Silk.m4r" },
	{ 195, "Slow Rise.m4r" },
	{ 196, "Stargaze.m4r" },
	{ 197, "Summit.m4r" },
	{ 198, "Twinkle.m4r" },
	{ 199, "Uplift.m4r" },
	{ 200, "Waves.m4r" },
	{ 201, "eligible" },
	{ 202, "planned" },
	{ 203, "current" },
	{ 204, "future" },
	{ 205, "disable" },
	{ 206, "expire" },
	{ 207, "start" },
	{ 208, "stop" },
	{ 209, "accuracy" },
	{ 210, "speed" },
	{ 211, "bearing" },
	{ 212, "recording" },
	{ 213, "key" },
	{ 214, "identity" },
	{ 215, "w:gp2" },
	{ 216, "admin" },
	{ 217, "locked" },
	{ 218, "unlocked" },
	{ 219, "new" },
	{ 220, "battery" },
	{ 221, "archive" },
	{ 222, "adm" },
	{ 223, "plaintext_size" },
	{ 224, "plaintext_disabled" },
	{ 225, "plaintext_reenable_threshold" },
	{ 226, "compressed_size" },
	{ 227, "delivered" },
	{ 228, "everyone" },
	{ 229, "transport" },
	{ 230, "mspes" },
	{ 231, "e2e_groups" },
	{ 232, "e2e_images" },
	{ 233, "encr_media" },
	{ 234, "encrypt_v2" },
	{ 235, "encrypt_image" },
	{ 236, "encrypt_sends_push" },
	{ 237, "force_long_connect" },
	{ 238, "audio_opus" },
	{ 239, "video_max_edge" },
	{ 240, "call-id" },
	{ 241, "call" },
	{ 242, "preaccept" },
	{ 243, "accept" },
	{ 244, "offer" },
	{ 245, "reject" },
	{ 246, "busy" },
	{ 247, "te" },
	{ 248, "terminate" },
	{ 249, "begin" },
	{ 250, "end" },
	{ 251, "opus" },
	{ 252, "rtt" },
	{ 253, "token" },
	{ 254, "priority" },
	{ 255, "p2p" },
	{ 256, "rate" },
	{ 257, "amr" },
	{ 258, "ptt" },
	{ 259, "srtp" },
	{ 260, "os" },
	{ 261, "browser" },
	{ 262, "encrypt_group_gen2" },
	{0,NULL}
};



