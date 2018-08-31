#!/usr/bin/env python

import re
import prlsdkapi as prl
import sys, os
import optparse
import time
import subprocess
from lxml import etree
import logging

LOG_FORMAT = "%(levelname)s:PID %(process)d:%(asctime)s:%(message)s"
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format=LOG_FORMAT)
logger = logging.getLogger()


class Actions:
	CREATE = 0
	SWITCH = 1
	REMOVE = 2
	TREE = 3

def parse_command_line_arguments():
	parser = optparse.OptionParser()

	choose_options_list = [
		optparse.make_option("--name", dest="name", type="string", help="select hosts:VMs by name and CTs by hostname like grep or CTs by id"),
	]

	choose_options_group = optparse.OptionGroup(parser, 'Select operations')
	choose_options_group.add_options(choose_options_list)
	parser.add_option_group(choose_options_group)

	def optparse_crs_callback(option, opt, value, parser):
		parser.values.tag = value
		if opt == "--create":
			parser.values.action = Actions.CREATE
		if opt == "--switch":
			parser.values.action = Actions.SWITCH
		if opt == "--remove":
			parser.values.action = Actions.REMOVE
		
	snapshot_options_list = [
		optparse.make_option("--create", action="callback", callback=optparse_crs_callback, type="string", help="create snapshot"),
		optparse.make_option("--switch", action="callback", callback=optparse_crs_callback, type="string", help="switch to snapshot"),
		optparse.make_option("--remove", action="callback", callback=optparse_crs_callback, type="string", help="remove snapshot"),
		optparse.make_option("--tree", action="store_const", const=Actions.TREE, dest="action", help="show snapshots tree"),
		optparse.make_option("--perform", dest="perform", action="store_true", default=False, help=optparse.SUPPRESS_HELP)
	]

	snapshot_options_group = optparse.OptionGroup(parser, 'Snapshot operations')
	snapshot_options_group.add_options(snapshot_options_list)
	parser.add_option_group(snapshot_options_group)

	(options, args) = parser.parse_args()

	try:
		query = options.name
		if not query:
			raise Exception("query is None")
		action = options.action
		if action is None:
			raise Exception("action is None")

		tag = options.tag if hasattr(options, "tag") else None
		if not tag and action in (Actions.CREATE, Actions.SWITCH, Actions.REMOVE):
			raise Exception("tag is None")
	except :
		parser.print_help()
		sys.exit(1)

	return (query, action, tag, options.perform)


def init():
	if not prl.is_sdk_initialized():
		prl.init_server_sdk()

def tag_value(tag):
	return "tag:%s" % tag

class Snapshot(object):
	def __init__(self, guid, dat, description, name, current):
		self.guid = guid
		self.date = dat
		self.description = description
		self.name = name
		self.current = current
		self.children = {}

	@classmethod
	def parse(cls, root):
		guid = root.attrib["guid"]
		current = root.attrib.get("current")
		dat = None
		description = None
		name = None
		for child in root:
			if child.tag == "Description":
				description = child.text
			if child.tag == "Name":
				name = child.text
		snapshot = Snapshot(guid, dat, description, name, current)
		items = root.xpath("./SavedStateItem")
		for item in items:
			child = Snapshot.parse(item)
			snapshot.children[child.guid] = child
		return snapshot

	def __repr__(self):
		return ( "Snapshot " +	repr(self.guid) + "," + repr(self.description) + repr(self.children) + ")")

	def __str__(self):
		if self.description:
			return "%s (%s)" % (self.name, self.description)
		else:
			return "%s (guid:%s)" % (self.name, self.guid)
		

def build_tree(vm):
	xml = vm.get_snapshots_tree_ex(prl.consts.PGST_WITHOUT_SCREENSHOTS).wait().get_param_as_string()
	if not xml:
		return None
	try:
		xml = xml.replace("xmlns:xsi=\"\"", "").replace("xsi:noNamespaceSchemaLocation=\"\"", "")
		tree = etree.fromstring(xml)
		items = tree.xpath("/ParallelsSavedStates/SavedStateItem")
		item = items[0]
		snapshot = Snapshot.parse(item)
		return snapshot
	except Exception, e:
		logger.error(xml)
		raise

def print_tree(snapshot, offset = 0):
	marker = u"\u251c" if len(snapshot.children) > 1 else u"\u2514"
	prefix = " "*offset
	current = ""
	if snapshot.current:
		current = "<-- current"
	print "%s%s %s %s" % (prefix, marker, unicode(snapshot), current)
	for _, child in snapshot.children.iteritems():
		print_tree(child, offset + 1)

def get_snapshot_trees(vm_list):
	snapshots = {}
	for vm in vm_list:
		snapshot = build_tree(vm)
		snapshots[vm] = snapshot
	return snapshots

def find_guid(snapshot, tag):
	if not snapshot:
		return None

	if tag_value(tag) in snapshot.description:
		return snapshot.guid

	for _, child in snapshot.children.iteritems():
		guid = find_guid(child, tag)
		if guid:
			return guid

	return None

def execute_command(vm, cmd, args):
	io = prl.VmIO()
	io.connect_to_vm(vm, prl.consts.PDCT_HIGH_QUALITY_WITHOUT_COMPRESSION).wait()

	result = vm.login_in_guest('root', '').wait()
	guest_session = result.get_param()

	sdkargs = prl.StringList()
	for arg in args:
		sdkargs.add_item(arg)
	sdkenvs = prl.StringList()
	sdkenvs.add_item("")

	ifd, ofd = os.pipe()
	flags = prl.consts.PRPM_RUN_PROGRAM_ENTER | prl.consts.PRPM_RUN_PROGRAM_IN_SHELL | prl.consts.PFD_STDOUT
	job = guest_session.run_program(cmd, sdkargs, sdkenvs, flags, 0, ofd)
	job.wait()
	os.close(ofd)

	r = os.fdopen(ifd)
	output = ""
	while True:
		str = r.read(1024)
		if not str:
			break
		output += str
	guest_session.logout()
	io.disconnect_from_vm(vm)
	return output

def stop_service(vm, name):
	cmd = "chkconfig --list %(name)s && service %(name)s stop" % {"name": name}
	execute_command(vm, "/bin/sh", ["-c", cmd])

def start_service(vm, name):
	cmd = "chkconfig --list %(name)s && service %(name)s start" % {"name": name}
	execute_command(vm, "/bin/sh", ["-c", cmd])

def create_snapshot(vm_list, tag):
	snapshots = get_snapshot_trees(vm_list)
	for vm, snapshot in snapshots.iteritems():
		if find_guid(snapshot, tag):
			raise Exception("Tag is not unique: VM %s already contains snapshot with tag '%s%s'", vm.get_name(), tag, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname())

	description = tag_value(tag) + " created at " + time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime())
	for vm in vm_list:
		vm_name = vm.get_name()
		logger.info("creating snapshot for %s %s" % (vm_name, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname()))

		# service pba preventing to create snapshot on containers
		# so need to stop this service before create snapshot
		if vm.get_vm_type() == prl.consts.PVT_CT:
			stop_service(vm, "pba")

		vm.create_snapshot(tag, description).wait()

		if vm.get_vm_type() == prl.consts.PVT_CT:
			start_service(vm, "pba")

def switch_to_snapshot(vm_list, tag):
	snapshots = get_snapshot_trees(vm_list)
	guids = {}
	for vm, snapshot in snapshots.iteritems():
		guids[vm] = find_guid(snapshot, tag)

	not_found = filter(lambda (key, value): False if value else True, guids.items())
	if not_found:
		raise Exception("Found no shapshot with tag '%s' for %s" % (tag, ", ".join(map(lambda (key, value): key.get_name(), not_found))))

	for vm, guid in guids.items():
		vm_name = vm.get_name()
		logger.info("switching to snapshot '%s' for %s%s" % (guid, vm_name, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname()))

		# service pba preventing to switch to snapshot on containers
		# so need to stop this service before create snapshot
		if vm.get_vm_type() == prl.consts.PVT_CT:
			stop_service(vm, "pba")

		vm.switch_to_snapshot(guid).wait()

		if vm.get_vm_type() == prl.consts.PVT_CT:
			start_service(vm, "pba")

def remove_snapshot(vm_list, tag):
	snapshots = get_snapshot_trees(vm_list)
	guids = {}
	for vm, snapshot in snapshots.iteritems():
		guids[vm] = find_guid(snapshot, tag)

	not_found = filter(lambda (key, value): False if value else True, guids.items())
#	if not_found:
#		raise Exception("Found no shapshot with tag '%s' for %s" % (tag, ", ".join(map(lambda (key, value): key.get_name(), not_found))))

	for vm, guid in guids.items():
		vm_name = vm.get_name()
		if not guid:
			continue
		logger.info("removing snapshot '%s' for %s%s" % (guid, vm_name, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname()))
		vm.delete_snapshot(guid).wait()

def snapshot_tree(vm_list):
	snapshots = get_snapshot_trees(vm_list)
	for vm, snapshot in snapshots.iteritems():
		print "%s %s:" % (vm.get_name(), "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname())
		# ignore root snapshot
		if snapshot:
			for _, child in snapshot.children.iteritems():
				print_tree(child)
			print
		else:
			print "No snapshots\n"


def filter_by_query(query):
	def filter(vm):
		if vm.get_vm_type() == prl.consts.PVT_VM:
			return re.search(query, vm.get_name())
		else: # prl.consts.PVT_CT
			return vm.get_name() == query or re.search(query, vm.get_hostname())
	return filter

if __name__ == "__main__":
	query, action, tag, perform = parse_command_line_arguments()

	actions = { 
		Actions.CREATE: {
			"action": create_snapshot,
			"command": "--create"
		},
		Actions.SWITCH: {
			"action": switch_to_snapshot,
			"command": "--switch"
		},
		Actions.REMOVE: {
			"action": remove_snapshot,
			"command": "--remove"
		},
		Actions.TREE: snapshot_tree,
	}

	if (actions.get(action) is None):
		raise NotImplementedError("action %s is not implemented" % str(action))

	init()
	server = prl.Server()
	server.login_local().wait()

	vm_list = server.get_vm_list_ex(prl.consts.PVTF_VM | prl.consts.PVTF_CT).wait()
	if action == Actions.TREE:
		vm_list_filtered = filter(filter_by_query(query), vm_list)
		snapshot_tree(vm_list_filtered)
		exit(0)

	if perform:
		vm_list_filtered = filter(filter_by_query(query), vm_list)
		actions[action]["action"](vm_list_filtered, tag)
	else:
		vm_list_filtered = filter(filter_by_query(query), vm_list)
		vm_full_names = [vm.get_name() for vm in vm_list_filtered]
		command = actions[action]["command"]
		processes = [subprocess.Popen([sys.executable, os.path.abspath(__file__), command, tag, "--name", full_name, "--perform"], executable=sys.executable) for full_name in vm_full_names]

		for process in processes:
			process.wait()


