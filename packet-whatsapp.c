
/*
 * WhatsApp protocol dissector
 * Written by David Guillen Fandos <david@davidgf.net>
 * Based on WhatsAPI sources
 *
 */


#include <config.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#define WHATSAPP_PORT 5222
#define WHATSAPP_PORT_NEW 443

const char * global_imei_whatsapp_1 = 0;
const char * global_v2pw_whatsapp_1 = 0;
const char * global_v2pw_whatsapp_2 = 0;
const char * global_v2pw_whatsapp_3 = 0;
const char * global_v2pw_whatsapp_4 = 0;
const char * global_v2pw_whatsapp_5 = 0;
const char * global_v2pw_whatsapp_6 = 0;
const gboolean global_enable_decoding;
int proto_whatsapp = -1;
int message_whatsapp = -1;
int userserver_string = -1;
int tree_whatsapp = -1;
static gint ett_whatsapp = -1;
int whatsapp_msg_crypted_payload = -1;
int whatsapp_msg_crypted_message = -1;

/* Variables for whatsapp packets */
int hf_whatsapp_message = -1;
int hf_whatsapp_node = -1;
int hf_whatsapp_nodesize16 = -1;
int hf_whatsapp_nodesize8 = -1;
int hf_whatsapp_attr_key_enc = -1;
int hf_whatsapp_attr_val_enc = -1;
int hf_whatsapp_attr_key_plain = -1;
int hf_whatsapp_attr_val_plain = -1;
int hf_whatsapp_attr_crypted = -1;
int hf_whatsapp_attr_flags = -1;
int hf_whatsapp_attribute = -1;
int hf_whatsapp_tag_enc = -1;
int hf_whatsapp_tag_plain = -1;
int hf_whatsapp_nvalue_enc = -1;
int hf_whatsapp_nvalue_plain = -1;
int hf_whatsapp_crypted_hmac_hash = -1;
int hf_whatsapp_userserver = -1;

const value_string strings_list[];

int whatsapp_msg = -1;

#define MIN_PAKCET_SIZE 4


static guint get_whatsapp_message_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
  int length = tvb_length(tvb)-offset;
  guint8* buffer = tvb_memdup(tvb, offset, length);
  int wa_len = whatsapp_data_length(buffer, length);
  g_free(buffer);
  return wa_len;
}

static void dissect_whatsapp_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  col_set_str (pinfo-> cinfo, COL_PROTOCOL, "WhatsApp XMPP protocol packet");
  col_clear (pinfo->cinfo, COL_INFO);

  if (tree) {
    proto_item *ti = proto_tree_add_item (tree, proto_whatsapp, tvb, 0,-1, ENC_NA);
    proto_tree * subtree = proto_item_add_subtree (ti, message_whatsapp);

    int length = tvb_length(tvb);
    guint8* buffer = tvb_memdup(tvb, 0, length);
    whatsapp_data_dissect_tree(buffer, length, subtree, tvb, pinfo);
    g_free(buffer);
  }
  return; // tvb_length(tvb);
}

static int dissect_whatsapp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, MIN_PAKCET_SIZE,
                     get_whatsapp_message_len, dissect_whatsapp_message);
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
    { &whatsapp_msg_crypted_message,
        { "Crypted message", "whatsapp.crypted_message",
          FT_NONE, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_message,
        { "Message size", "whatsapp.message",
          FT_UINT16, BASE_DEC,
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
    { &hf_whatsapp_tag_enc,
        { "Tag", "whatsapp.tagenc",
          FT_UINT8, BASE_DEC,
          VALS(strings_list), 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_tag_plain,
        { "Tag", "whatsapp.tagplain",
          FT_STRING, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_nvalue_enc,
        { "Value", "whatsapp.nodevalueenc",
          FT_UINT8, BASE_DEC,
          VALS(strings_list), 0x0,
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
          NULL, 0x0,
          NULL, HFILL },
    },
    { &hf_whatsapp_attr_crypted,
        { "Crypted", "whatsapp.crypted",
          FT_BOOLEAN, BASE_NONE,
          NULL, 0x80,
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
    &userserver_string
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
  prefs_register_string_preference(whatsapp_module, "pw1",
				 "v2 password (1)",
				 "Base64 encoded password to use in v2 auth",
				 &global_v2pw_whatsapp_1);
  prefs_register_string_preference(whatsapp_module, "pw2",
				 "v2 password (2)",
				 "Base64 encoded password to use in v2 auth",
				 &global_v2pw_whatsapp_2);
  prefs_register_string_preference(whatsapp_module, "pw3",
				 "v2 password (3)",
				 "Base64 encoded password to use in v2 auth",
				 &global_v2pw_whatsapp_3);
  prefs_register_string_preference(whatsapp_module, "pw4",
				 "v2 password (4)",
				 "Base64 encoded password to use in v2 auth",
				 &global_v2pw_whatsapp_4);
  prefs_register_string_preference(whatsapp_module, "pw5",
				 "v2 password (5)",
				 "Base64 encoded password to use in v2 auth",
				 &global_v2pw_whatsapp_5);
  prefs_register_string_preference(whatsapp_module, "pw6",
				 "v2 password (6)",
				 "Base64 encoded password to use in v2 auth",
				 &global_v2pw_whatsapp_6);
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
	{ 0,"" },
	{ 1,"" },
	{ 2,"" },
	{ 3,"" },
	{ 4,"" },
	{ 5,"account" },
	{ 6,"ack" },
	{ 7,"action" },
	{ 8,"active" },
	{ 9,"add" },
	{ 10,"after" },
	{ 11,"ib" },
	{ 12,"all" },
	{ 13,"allow" },
	{ 14,"apple" },
	{ 15,"audio" },
	{ 16,"auth" },
	{ 17,"author" },
	{ 18,"available" },
	{ 19,"bad-protocol" },
	{ 20,"bad-request" },
	{ 21,"before" },
	{ 22,"Bell.caf" },
	{ 23,"body" },
	{ 24,"Boing.caf" },
	{ 25,"cancel" },
	{ 26,"category" },
	{ 27,"challenge" },
	{ 28,"chat" },
	{ 29,"clean" },
	{ 30,"code" },
	{ 31,"composing" },
	{ 32,"config" },
	{ 33,"conflict" },
	{ 34,"contacts" },
	{ 35,"count" },
	{ 36,"create" },
	{ 37,"creation" },
	{ 38,"default" },
	{ 39,"delay" },
	{ 40,"delete" },
	{ 41,"delivered" },
	{ 42,"deny" },
	{ 43,"digest" },
	{ 44,"DIGEST-MD5-1" },
	{ 45,"DIGEST-MD5-2" },
	{ 46,"dirty" },
	{ 47,"elapsed" },
	{ 48,"broadcast" },
	{ 49,"enable" },
	{ 50,"encoding" },
	{ 51,"duplicate" },
	{ 52,"error" },
	{ 53,"event" },
	{ 54,"expiration" },
	{ 55,"expired" },
	{ 56,"fail" },
	{ 57,"failure" },
	{ 58,"false" },
	{ 59,"favorites" },
	{ 60,"feature" },
	{ 61,"features" },
	{ 62,"field" },
	{ 63,"first" },
	{ 64,"free" },
	{ 65,"from" },
	{ 66,"g.us" },
	{ 67,"get" },
	{ 68,"Glass.caf" },
	{ 69,"google" },
	{ 70,"group" },
	{ 71,"groups" },
	{ 72,"g_notify" },
	{ 73,"g_sound" },
	{ 74,"Harp.caf" },
	{ 75,"http://etherx.jabber.org/streams" },
	{ 76,"http://jabber.org/protocol/chatstates" },
	{ 77,"id" },
	{ 78,"image" },
	{ 79,"img" },
	{ 80,"inactive" },
	{ 81,"index" },
	{ 82,"internal-server-error" },
	{ 83,"invalid-mechanism" },
	{ 84,"ip" },
	{ 85,"iq" },
	{ 86,"item" },
	{ 87,"item-not-found" },
	{ 88,"user-not-found" },
	{ 89,"jabber:iq:last" },
	{ 90,"jabber:iq:privacy" },
	{ 91,"jabber:x:delay" },
	{ 92,"jabber:x:event" },
	{ 93,"jid" },
	{ 94,"jid-malformed" },
	{ 95,"kind" },
	{ 96,"last" },
	{ 97,"latitude" },
	{ 98,"lc" },
	{ 99,"leave" },
	{ 100,"leave-all" },
	{ 101,"lg" },
	{ 102,"list" },
	{ 103,"location" },
	{ 104,"longitude" },
	{ 105,"max" },
	{ 106,"max_groups" },
	{ 107,"max_participants" },
	{ 108,"max_subject" },
	{ 109,"mechanism" },
	{ 110,"media" },
	{ 111,"message" },
	{ 112,"message_acks" },
	{ 113,"method" },
	{ 114,"microsoft" },
	{ 115,"missing" },
	{ 116,"modify" },
	{ 117,"mute" },
	{ 118,"name" },
	{ 119,"nokia" },
	{ 120,"none" },
	{ 121,"not-acceptable" },
	{ 122,"not-allowed" },
	{ 123,"not-authorized" },
	{ 124,"notification" },
	{ 125,"notify" },
	{ 126,"off" },
	{ 127,"offline" },
	{ 128,"order" },
	{ 129,"owner" },
	{ 130,"owning" },
	{ 131,"paid" },
	{ 132,"participant" },
	{ 133,"participants" },
	{ 134,"participating" },
	{ 135,"password" },
	{ 136,"paused" },
	{ 137,"picture" },
	{ 138,"pin" },
	{ 139,"ping" },
	{ 140,"platform" },
	{ 141,"pop_mean_time" },
	{ 142,"pop_plus_minus" },
	{ 143,"port" },
	{ 144,"presence" },
	{ 145,"preview" },
	{ 146,"probe" },
	{ 147,"proceed" },
	{ 148,"prop" },
	{ 149,"props" },
	{ 150,"p_o" },
	{ 151,"p_t" },
	{ 152,"query" },
	{ 153,"raw" },
	{ 154,"reason" },
	{ 155,"receipt" },
	{ 156,"receipt_acks" },
	{ 157,"received" },
	{ 158,"registration" },
	{ 159,"relay" },
	{ 160,"remote-server-timeout" },
	{ 161,"remove" },
	{ 162,"Replaced by new connection" },
	{ 163,"request" },
	{ 164,"required" },
	{ 165,"resource" },
	{ 166,"resource-constraint" },
	{ 167,"response" },
	{ 168,"result" },
	{ 169,"retry" },
	{ 170,"rim" },
	{ 171,"s.whatsapp.net" },
	{ 172,"s.us" },
	{ 173,"seconds" },
	{ 174,"server" },
	{ 175,"server-error" },
	{ 176,"service-unavailable" },
	{ 177,"set" },
	{ 178,"show" },
	{ 179,"sid" },
	{ 180,"silent" },
	{ 181,"sound" },
	{ 182,"stamp" },
	{ 183,"unsubscribe" },
	{ 184,"stat" },
	{ 185,"status" },
	{ 186,"stream:error" },
	{ 187,"stream:features" },
	{ 188,"subject" },
	{ 189,"subscribe" },
	{ 190,"success" },
	{ 191,"sync" },
	{ 192,"system-shutdown" },
	{ 193,"s_o" },
	{ 194,"s_t" },
	{ 195,"t" },
	{ 196,"text" },
	{ 197,"timeout" },
	{ 198,"TimePassing.caf" },
	{ 199,"timestamp" },
	{ 200,"to" },
	{ 201,"Tri-tone.caf" },
	{ 202,"true" },
	{ 203,"type" },
	{ 204,"unavailable" },
	{ 205,"uri" },
	{ 206,"url" },
	{ 207,"urn:ietf:params:xml:ns:xmpp-sasl" },
	{ 208,"urn:ietf:params:xml:ns:xmpp-stanzas" },
	{ 209,"urn:ietf:params:xml:ns:xmpp-streams" },
	{ 210,"urn:xmpp:delay" },
	{ 211,"urn:xmpp:ping" },
	{ 212,"urn:xmpp:receipts" },
	{ 213,"urn:xmpp:whatsapp" },
	{ 214,"urn:xmpp:whatsapp:account" },
	{ 215,"urn:xmpp:whatsapp:dirty" },
	{ 216,"urn:xmpp:whatsapp:mms" },
	{ 217,"urn:xmpp:whatsapp:push" },
	{ 218,"user" },
	{ 219,"username" },
	{ 220,"value" },
	{ 221,"vcard" },
	{ 222,"version" },
	{ 223,"video" },
	{ 224,"w" },
	{ 225,"w:g" },
	{ 226,"w:p" },
	{ 227,"w:p:r" },
	{ 228,"w:profile:picture" },
	{ 229,"wait" },
	{ 230,"x" },
	{ 231,"xml-not-well-formed" },
	{ 232,"xmlns" },
	{ 233,"xmlns:stream" },
	{ 234,"Xylophone.caf" },
	{ 235,"1" },
	{ 236,"WAUTH-1" },
	{ 237,"" },
	{ 238,"" },
	{ 239,"" },
	{ 240,"" },
	{ 241,"" },
	{ 242,"" },
	{ 243,"" },
	{ 244,"" },
	{ 245,"" },
	{ 246,"" },
	{ 247,"" },
	{ 248,"XXX" },
	{ 249,"" },
	{ 250,"" },
	{ 251,"" },
	{ 252,"" },
	{ 253,"" },
	{ 254,"" },
	{ 255,"" },
	{0,NULL}
};


