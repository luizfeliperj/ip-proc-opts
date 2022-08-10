#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/ip_opts.h>
#include <epan/ipproto.h>

#define IPH_MIN_LEN     20

static gint ip_proto_proc_opt = -1;

static gint ett_ip_option_proc = -1;
static gint ett_ip_option_proc_fd = -1;
static gint ett_ip_option_proc_pid = -1;
static gint ett_ip_option_proc_tgid = -1;
static gint ett_ip_option_proc_ppid = -1;
static gint ett_ip_option_proc_ptgid = -1;

static gint hf_ip_option_proc_fd = -1;
static gint hf_ip_option_proc_pid = -1;
static gint hf_ip_option_proc_tgid = -1;
static gint hf_ip_option_proc_ppid = -1;
static gint hf_ip_option_proc_ptgid = -1;

/* static dissector_handle_t ip_handle = NULL; */

extern registered_dissectors;

static guint32
berdecode (tvbuff_t *tvb, int *offset)
{
	int i = 0;
	guint32 r = 0;

	for (;;) {
		guint8 ber = tvb_get_guint8(tvb, *offset + i++);
		if (ber & 0x80) {
			r |= ber & 0x7F;
			r = r << 7;
		} else {
			r |= ber & 0xFF;
			break;
		}
	}

	*offset += i;
	return r;
}


static void
dissect_ip_proc_opt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *t = NULL;
	proto_item *ti = NULL;
	int offset, lastoffset;
	int pid, tgid, ppid, ptgid, fd;

	if (!tree || !tree->first_child || !tree->first_child->next)
		return;

	if (tvb_get_guint8(tvb, 0) != 0x48 || tvb_get_guint8(tvb, IPH_MIN_LEN) != 0xFF)
		return;

	lastoffset = offset = IPH_MIN_LEN + 2; /* 0xFF || SIZE || BERDATA... */

	ti = proto_tree_add_item(tree, ip_proto_proc_opt, tvb, IPH_MIN_LEN, tvb_get_guint8(tvb, IPH_MIN_LEN+1), FALSE);
	t = proto_item_add_subtree(ti, ett_ip_option_proc);

	pid = berdecode (tvb, &offset);
	proto_tree_add_int (t, hf_ip_option_proc_pid, tvb,lastoffset, offset - lastoffset, pid);

	lastoffset = offset;
	tgid = berdecode (tvb, &offset);
	proto_tree_add_int (t, hf_ip_option_proc_tgid, tvb, lastoffset, offset - lastoffset, tgid);

	lastoffset = offset;
	ppid = berdecode (tvb, &offset);
	proto_tree_add_int (t, hf_ip_option_proc_ppid, tvb,lastoffset, offset - lastoffset, ppid);


	lastoffset = offset;
	ptgid = berdecode (tvb, &offset);
	proto_tree_add_int (t, hf_ip_option_proc_ptgid, tvb,lastoffset, offset - lastoffset, ptgid);

	lastoffset = offset;
	fd = berdecode (tvb, &offset);
	proto_tree_add_int (t, hf_ip_option_proc_fd, tvb,lastoffset, offset - lastoffset, fd);

	proto_item_append_text(proto_tree_get_parent(t), ", tgid: %d, fd: %d", tgid, fd);

	PROTO_ITEM_SET_HIDDEN(tree->first_child->next);
	proto_tree_move_item (tree, tree->first_child, t);

	/**************************************************
	if (ip_handle)
		call_dissector(ip_handle, tvb, pinfo, tree);
	**************************************************/
}

void 
proto_register_proc_opt(void)
{
	static hf_register_info hf[] = {
		{ &hf_ip_option_proc_fd, { "Process File Descriptor", "process.fd", FT_INT32, BASE_DEC, NULL, 0x0, "Process File Descriptor", HFILL }},
		{ &hf_ip_option_proc_pid, { "Process PID", "process.pid", FT_INT32, BASE_DEC, NULL, 0x0, "Process ID", HFILL }},
		{ &hf_ip_option_proc_tgid, { "Process Task Group ID", "process.tgid", FT_INT32, BASE_DEC, NULL, 0x0, "Process Task Group ID", HFILL }},
		{ &hf_ip_option_proc_ppid, { "Parent Process PID", "process.ppid", FT_INT32, BASE_DEC, NULL, 0x0, "Parent Process ID", HFILL }},
		{ &hf_ip_option_proc_ptgid, { "Parent Process Task Group ID", "process.ptgid", FT_INT32, BASE_DEC, NULL, 0x0, "Parent Process Task Group ID", HFILL }}
	};

	static gint *ett[] = {
		&ett_ip_option_proc,
		&ett_ip_option_proc_fd,
		&ett_ip_option_proc_pid,
		&ett_ip_option_proc_tgid,
		&ett_ip_option_proc_ppid,
		&ett_ip_option_proc_ptgid
	};

	/* Register the protocol name and description */
	ip_proto_proc_opt = proto_register_protocol("Process data", "PROC", "process");
	/* register_dissector("process", dissect_ip_proc_opt, ip_proto_proc_opt); */

	/* Required function calls to register the header fields and subtree used */
	proto_register_field_array(ip_proto_proc_opt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_proc_opt(void)
{
	dissector_handle_t ip_proto_proc_opt_handle;

	ip_proto_proc_opt_handle = create_dissector_handle (dissect_ip_proc_opt, ip_proto_proc_opt);
	register_postdissector (ip_proto_proc_opt_handle);

	/*********************************************************************************************
	ip_handle = find_dissector("data");
	ip_proto_proc_opt_handle = create_dissector_handle (dissect_ip_proc_opt, ip_proto_proc_opt);
        dissector_add_uint("wtap_encap", WTAP_ENCAP_RAW_IP, ip_proto_proc_opt_handle);
	// register_dissector ("ip", dissect_ip_proc_opt, ip_proto_proc_opt);
	*********************************************************************************************/

}
