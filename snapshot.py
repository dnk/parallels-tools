#!/usr/bin/env python

import re
import prlsdkapi as prl
import sys
import optparse
from lxml import etree

import pprint
pp = pprint.PrettyPrinter(indent=2)


class Actions:
	CREATE = 0
	SWITCH = 1
	REMOVE = 2
	TREE = 3

parser = optparse.OptionParser()

choose_options_list = [
	optparse.make_option("--name", dest="name", type="string", help="select VMs by name like grep"),
]

choose_options_group = optparse.OptionGroup(parser, 'Select VMs')
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



def init():
	if not prl.is_sdk_initialized():
		prl.init_server_sdk()

def wait_jobs(jobs):
	for vm, job in jobs.iteritems():
		vm_name = vm.get_name()
		print "waiting job for %s%s" % (vm_name, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname())
		job.wait()
		print "done"

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
		print xml
		raise

def print_tree(snapshot, offset = 0):
	marker = u"\u251c" if len(snapshot.children) > 1 else u"\u2514"
	prefix = " "*offset
	current = ""
	if snapshot.current:
		current = "<-- current"
	print "%s%s %s %s" % (prefix, marker, str(snapshot), current)
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

	if snapshot.description == tag_value(tag):
		return snapshot.guid

	for _, child in snapshot.children.iteritems():
		guid = find_guid(child, tag)
		if guid:
			return guid

	return None

def create_snapshot(vm_list, tag):
	snapshots = get_snapshot_trees(vm_list)
	for vm, snapshot in snapshots.iteritems():
		if find_guid(snapshot, tag):
			raise Exception("Tag is not unique: VM %s already contains snapshot with tag '%s%s'", vm.get_name(), tag, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname())

	jobs = {}
	description = tag_value(tag)
	for vm in vm_list:
		vm_name = vm.get_name()
		print "creating snapshot for %s%s" % (vm_name, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname())
		job = vm.create_snapshot(tag, description)
		jobs[vm] = job
	wait_jobs(jobs)


def switch_to_snapshot(vm_list, tag):
	snapshots = get_snapshot_trees(vm_list)
	guids = {}
	for vm, snapshot in snapshots.iteritems():
		guids[vm] = find_guid(snapshot, tag)

	not_found = filter(lambda (key, value): False if value else True, guids.items())
	if not_found:
		raise Exception("Found no shapshot with tag '%s' for %s" % (tag, ", ".join(map(lambda (key, value): key.get_name(), not_found))))

	jobs = {}
	for vm, guid in guids.items():
		vm_name = vm.get_name()
		print "switching to snapshot '%s' for %s%s" % (guid, vm_name, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname())
		job = vm.switch_to_snapshot(guid)
		jobs[vm] = job

	wait_jobs(jobs)


def remove_snapshot(vm_list, tag):
	snapshots = get_snapshot_trees(vm_list)
	guids = {}
	for vm, snapshot in snapshots.iteritems():
		guids[vm] = find_guid(snapshot, tag)

	not_found = filter(lambda (key, value): False if value else True, guids.items())
#	if not_found:
#		raise Exception("Found no shapshot with tag '%s' for %s" % (tag, ", ".join(map(lambda (key, value): key.get_name(), not_found))))

	jobs = {}
	for vm, guid in guids.items():
		vm_name = vm.get_name()
		if not guid:
			continue
		print "removing snapshot '%s' for %s%s" % (guid, vm_name, "" if vm.get_vm_type() == prl.consts.PVT_VM else vm.get_hostname())
		job = vm.delete_snapshot(guid)
		jobs[vm] = job

	wait_jobs(jobs)

def snapshot_tree(vm_list, tag):
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


init()


server = prl.Server()
server.login_local().wait()

vm_list = server.get_vm_list_ex(prl.consts.PVTF_VM | prl.consts.PVTF_CT).wait()

vm_list_filtered = filter(lambda x: re.search(query, x.get_name() if x.get_vm_type() == prl.consts.PVT_VM else x.get_hostname()), vm_list)

actions = { 
	Actions.CREATE: create_snapshot,
	Actions.SWITCH: switch_to_snapshot,
	Actions.REMOVE: remove_snapshot,
	Actions.TREE: snapshot_tree,
}

if (actions.get(action) is None):
	raise NotImplementedError("action %s is not implemented" % str(action))

actions[action](vm_list_filtered, tag)

