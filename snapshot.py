#!/usr/bin/env python

import re
import prlsdkapi as prl
import sys
import optparse

option_list = [
	optparse.make_option("--name", dest="name", type="string", help="vm name"),
]

parser = optparse.OptionParser(option_list=option_list)
(options, args) = parser.parse_args()

try:
	query = options.name
	if not query:
		raise Exception("query is None")
except :
	parser.print_help()
	sys.exit(0)



def init():
	if not prl.is_sdk_initialized():
		prl.init_server_sdk()


class Snapshot(object):
	def __init__(self):
		self.guid = None
		self.date = None
		self.description = None
		pass

init()




server = prl.Server()
server.login_local().wait()

vm_list = server.get_vm_list().wait()

vm_list_filtered = filter(lambda x: re.search(query, x.get_name()), vm_list)

for vm in vm_list_filtered:
	tree = vm.get_snapshots_tree_ex(prl.consts.PGST_WITHOUT_SCREENSHOTS).wait().get_param_as_string()
	print tree
