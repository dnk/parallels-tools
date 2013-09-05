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

option_list = [
	optparse.make_option("--name", dest="name", type="string", help="vm name"),
	optparse.make_option("--tag", dest="tag", type="string", help="tag name, used to identify snapshots"),
	optparse.make_option("--create", action="store_const", const=Actions.CREATE, dest="action", help="create snapshot"),
	optparse.make_option("--switch", action="store_const", const=Actions.SWITCH, dest="action", help="switch to snapshot"),
	optparse.make_option("--remove", action="store_const", const=Actions.REMOVE, dest="action", help="remove snapshot"),
]

parser = optparse.OptionParser(option_list=option_list)
(options, args) = parser.parse_args()

try:
	query = options.name
	if not query:
		raise Exception("query is None")
	tag = options.tag
	if not tag:
		raise Exception("tag is None")

	action = options.action
	if action is None:
		raise Exception("action is None")
except :
	parser.print_help()
	sys.exit(1)



def init():
	if not prl.is_sdk_initialized():
		prl.init_server_sdk()

def wait_jobs(jobs):
	for vm, job in jobs.iteritems():
		vm_name = vm.get_name()
		print "waiting job for %s" % vm_name
		job.wait()
		print "done"

def tag_value(tag):
	return "tag:%s" % tag

def create_snapshot(vm_list, tag):
	jobs = {}
	description = tag_value(tag)
	for vm in vm_list:
		vm_name = vm.get_name()
		print "creating snapshot for %s" % vm_name
		job = vm.create_snapshot(tag, description)
		jobs[vm] = job
	wait_jobs(jobs)


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
		return self.guid
		

def build_tree(vm):
	xml = vm.get_snapshots_tree_ex(prl.consts.PGST_WITHOUT_SCREENSHOTS).wait().get_param_as_string()
	xml = xml.replace("xmlns:xsi=\"\"", "").replace("xsi:noNamespaceSchemaLocation=\"\"", "")
	tree = etree.fromstring(xml)
	items = tree.xpath("/ParallelsSavedStates/SavedStateItem")
	item = items[0]
	snapshot = Snapshot.parse(item)
	return snapshot

def find_guid(snapshot, tag):
	if snapshot.description == tag_value(tag):
		return snapshot.guid

	for _, child in snapshot.children.iteritems():
		guid = find_guid(child, tag)
		if guid:
			return guid

	return None

def switch_snapshot(vm_list, tag):
	guids = {}
	for vm in vm_list:
		snapshots = build_tree(vm)
		guids[vm] = find_guid(snapshots, tag)

	not_found = filter(lambda (key, value): False if value else True, guids.items())
	if not_found:
		raise Exception("Found no shapshot with tag '%s' for %s" % (tag, ", ".join(map(lambda (key, value): key.get_name(), not_found))))

	jobs = {}
	for vm, guid in guids.items():
		vm_name = vm.get_name()
		print "switching to snapshot '%s' for %s" % (guid, vm_name)
		job = vm.switch_to_snapshot(guid)
		jobs[vm] = job

	wait_jobs(jobs)


def remove_snapshot(vm_list, tag):
	raise NotImplementedError("remove snapshot is not implemented")

init()


server = prl.Server()
server.login_local().wait()

vm_list = server.get_vm_list().wait()

vm_list_filtered = filter(lambda x: re.search(query, x.get_name()), vm_list)

actions = { 
	Actions.CREATE: create_snapshot,
	Actions.SWITCH: switch_snapshot,
	Actions.REMOVE: remove_snapshot,
}

if (actions.get(action) is None):
	raise NotImplementedError("action %s is not implemented" % str(action))

actions[action](vm_list_filtered, tag)

