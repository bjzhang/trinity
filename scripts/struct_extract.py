#!/usr/bin/python

#TODO
#1.  Do not support pointer in pointer.
#    E.g. a->b->c
#2.  Do not expand array at this moment. DONE
#    (Need update abi-dumper output?).
#3.  Do not support union.
#    Skip ilp32_sys_rt_sigreturn_wrapper, ilp32_sys_rt_sigreturn.

#__author__ = ""
#__version__ = "1.0"
#__date__ = ""
#__copyright__ = ""
#__license__ = ""

import json
import re
import sys #for command line arguments
import subprocess
import tempfile
import errno

#from pprint import pprint
#pprint(symbolinfo)
#pprint(typeinfo)

prtfFmtDict={"char":"%c", "unsigned char":"%c", "char const*":"%s", "char *":"%s", "unsigned char *":"%s", "short":"%h", "unsigned short": "%uh", "int":"%d","unsigned int":"%u","long":"%l","unsigned long":"%ul","long long":"%ll","unsigned long long":"%ull", "void":"%x", "Pointer":"0x%x", "FuncPtr":"0x%x", "Enum":"%d"}
skip_type=[""]
typeStrReadable={"char const*": "char pointer", "char *": "char pointer"}
syscallSkip=["ilp32_sys_rt_sigreturn_wrapper"]
syscallFixUp={"ilp32_sys_rt_sigreturn_wrapper":"ilp32_sys_rt_sigreturn"}

def getBaseType(types, t):
#	print "DEBUG: Current type is " + t
	typelist = types[t]
	for item in typelist:
		for n, v in item.items():
			if n == "BaseType":
				return v

def getTypeName(types, t):
#	print "DEBUG: Current type is ", t
	typelist = types[t]
	for item in typelist:
		for n, v in item.items():
			if n == "Name":
				return v

def parse_type(types, t, is_recursive=False, originalName=""):
	print "#####DEBUG: parse_type: current type is " + t + ", original name<" + originalName + ">"
	typelist = types[t]
#	for item in typelist:
#		for n, v in item.items():
#			print "DEBUG: " + n + " "
#			print v
	base_type = getBaseType(types, t)

	for item in typelist:
		for n, v in item.items():
			if n == "Type":
				cur_type=v
	if base_type is None:
		base_type = t
#	print "#####DEBUG: parse_type: current type name < " + cur_type + ">, set base_type as type<" + base_type + ">"

	for item in typelist:
		for n, v in item.items():
			if n == "Name":
				print "DEBUG: current name: " + v
				if originalName == "":
					originalName = v
				if v in prtfFmtDict:
					#basic type, original type name which defined the variable, base type id in json
					#unsigned int, __uid_t, 219
					return [v, originalName, base_type]
				if cur_type == "Enum":
					return [cur_type, originalName, base_type]
				if cur_type == "FuncPtr":
					return [cur_type, originalName, base_type]
				if not is_recursive and "cur_type" in vars() and cur_type == "Pointer":
					return [cur_type, originalName, base_type]
				if "cur_type" in vars() and cur_type == "Struct":
					return [cur_type, originalName, base_type]
				if not is_recursive and "cur_type" in vars() and cur_type == "Array":
					#we do not parse the base type for array.
					return [cur_type, v, t]
				if "cur_type" in vars() and cur_type == "Union":
					return [cur_type, originalName, base_type]

	if base_type is None:
		print "Unknown types<" + t + ">, exit!!!"
		print types[t]
		raise SystemExit
	return parse_type(types, base_type, False, originalName)

def parse_struct_union(types, t,prefix=""):
	print "DEBUG: parse_struct_union: Parse type " + t + ", prefix: <" + prefix + ">"
	typelist = types[t]
	varList=[]
	for item in typelist:
		for n, v in item.items():
			if n == "Memb":
				for paraName, paraType in v.items():
					#FIXME: we could not handle va_list at this moment
#					if paraName == "va" and paraType == "-1":
					if paraName == "-1" and paraType == "va":
						continue

					[cur_type, varName, type_id] = parse_type(types, paraType)
					print "###DEBUG: paraName: " + paraName + ", paraType: " + paraType + ", cur_type: " + cur_type + ", varName: " + varName + ", type_id: " + type_id
					if cur_type == "Struct" or cur_type == "Union":
						vl = parse_struct_union(types, type_id, prefix + paraName + ".")
						varList.extend(vl)
					elif cur_type == "Array":
						result=re.match(r'^(.*)\[(.+)\].*$', varName)
						[cur_type, varName, type_id] = parse_type(types, type_id, True)
						i = 0
						if result:
							while i < int(result.group(2)):
								if not cur_type in skip_type:
									var={}
									var["print_format"] = prtfFmtDict[cur_type]
									var["name"] = prefix + paraName + "[" + str(i) + "]"
									var["type_name"] = result.group(1)
									varList.append(var)

								i += 1
						else:
							result=re.match(r'^(.*)\[].*$', varName)
							cur_type = result.group(1) + " *"
							if not cur_type in skip_type:
								var={}
								var["print_format"] = prtfFmtDict[cur_type]
								var["name"] = prefix + paraName
								var["type_name"] = result.group(0)
								varList.append(var)
					else:
						if not cur_type in skip_type:
							var={}
							var["print_format"] = prtfFmtDict[cur_type]
							var["name"] = prefix + paraName
							var["type_name"] = varName
							varList.append(var)

	return varList

def parseReturn(types, t):
	return parse_type(types, t)[1]

def parse_function(symbols, types, func):
	func_vars=[]
	rootVars={}

	if func in syscallFixUp:
		print "Replace " + func + " to " + syscallFixUp[func]
		func = syscallFixUp[func]

	print "DEBUG: parse_function: " + func
	if func in symbols:
		for funcItem in symbols[func]:
			if "Return" in funcItem:
				returnType=funcItem["Return"]
				returnTypeStr=parseReturn(types, returnType)
			elif "Param" in funcItem:
				param=funcItem["Param"]
				for n, t in param.items():
					print n, t
					if n == "-1" and t == "va":
						continue

					[tStr, originalName, base_type] = parse_type(types, t)
#					print "DEBUG: " + t + " " + tStr + ". Name: " + n + ", original name: " + originalName + ", base_type: " + base_type
					if not tStr in skip_type:
						var = {}
						var["print_format"] = prtfFmtDict[tStr]
						var["name"] = n
						if tStr == "Pointer" or tStr == "FuncPtr":
							var["type_name"] = originalName
						else:
							var["type_name"] = tStr
						func_vars.append(var)

					base_type = parse_type(types, t, True)[2]
					if tStr == "Pointer" and parse_type(types, t, True)[0] == "Struct":
						complexType=parse_struct_union(types, base_type, n + "->")
						rootType = complexType
						type_name = getTypeName(types, t)
						type_name = re.sub("\ *const\ *", "", type_name)
						rootvar = {}
						rootvar["name"]=n
						rootvar["members"] = rootType
						rootVars[type_name]=rootvar

		return [returnTypeStr, func, func_vars, rootVars]
	else:
		print "Error: function " + func + " is not found"
		return ["", "", [], []]


#Generate the Jprobe hook but do not care the format. Leave it to indent
def generate_func_helper(subfix, funcRet, func, func_vars, rootVars):
	prototype = funcRet + " J" + func + "("
	funcVarStr=""
	funcVarFmt=""
	first=True

	if func_vars:
		for varList in func_vars:
			if not first:
				prototype += ", "
				funcVarStr += ", "
				funcVarFmt += ", "

			prototype += varList["type_name"] + " " + varList["name"]
			funcVarStr+= varList["name"] + "<" + varList["print_format"] + ">"
			funcVarFmt+= varList["name"]

			first = False

	prototype += ")"

	if rootVars:
		rootVarStr=""
		rootVarFmt=""
		first = True
		for type_name,type_value in rootVars.items():
			for member_lists in type_value["members"]:
				if not first:
					rootVarStr += ", "
					rootVarFmt += ", "

				rootVarStr += member_lists["name"] + "<" + member_lists["print_format"] + ">"
				rootVarFmt += member_lists["name"]
				first = False

	jprobe = prototype + "{"
	if func_vars and funcVarStr and funcVarFmt:
		jprobe += "printf(\"" + funcVarStr + "\", " + funcVarFmt + ");"
	if rootVars and rootVarStr and rootVarFmt:
		jprobe += "printf(\"" + rootVarStr + "\", " + rootVarFmt + ");"
	jprobe += subfix
	jprobe += "}"
	return jprobe

def generate_type_function(type_name, type_value):

	struct_name = re.sub("\ *\*\ *", "", type_name)
	root_name = re.sub("\ *struct\ *", "", struct_name)
	varAssign=""
	get_function = type_name + " get_" + root_name + "(){"

	name = type_value["name"]
	get_function +=  type_name + " " + name + "= malloc(sizeof(" + struct_name + "));"

	member_lists = type_value["members"]
	for member_list in member_lists:
		var = re.sub("[->.\[\]]", "_", member_list["name"])
		varAssign+=member_list["name"] + " = " + "get_" + var + "();"

	get_function += varAssign

	first = True
	var_string = ""
	var_format = ""
	for member_lists in type_value["members"]:
		if not first:
			var_string += ", "
			var_format += ", "

		var_string += member_lists["name"] + "<" + member_lists["print_format"] + ">"
		var_format += member_lists["name"]
		first = False

	get_function += "printf(\"parameter value: " + var_string + "\", " + var_format + ");"
	get_function += "return " + name + ";}"

	return get_function

def try_function_def(symbolinfo, func):
	result=re.match(r'^compat_[Ss][Yy][Ss]_(.*)$', func)
	C_SYSC_func = ""
	if result:
		C_SYSC_func = "C_SYSC_" + result.group(1)

	if C_SYSC_func in symbolinfo:
		return C_SYSC_func
	elif func in symbolinfo:
		return func
	else:
		return None

#format file as prefered formating. I hope I only need indent.
def format_file(filename):
	try:
		s = subprocess.call(["indent", "-kr -i8 -ts8 -sob -l80 -ss -bs ", filename])
		error_number = s
	except OSError, e:
		error_number = e.errno

	if error_number:
		print "errno: " + str(error_number), "err code: " + errno.errorcode[error_number]
		return

	#Create temporary file read/write
	t = tempfile.NamedTemporaryFile(mode="r+")

	#Open input file read-only
	i = open(filename, 'r')

	#Copy input file to temporary file, modifying as we go
	for line in i:
		for k in ["int","siginfo","cpu_set","struct","const","char", "__pid_t"]:
			r = re.match(r'^\} ' + k, line)
			if r:
				replaced_line = re.sub(r'^\} ' + k, "}\n\n" + k, line)
				t.write(replaced_line)
				break
		if not r:
			t.write(line)

	i.close() #Close input file

	t.seek(0) #Rewind temporary file to beginning

	o = open(filename, "w")  #Reopen input file writable

	#Overwriting original file with temporary file contents
	for line in t:
	   o.write(line)

	t.close() #Close temporary file, will cause it to be deleted

def main():
	if len(sys.argv) != 7:
		sys.exit()

	symbolinfo_file = sys.argv[1]
	typeinfo_file = sys.argv[2]
	function_list_file = sys.argv[3]
	function_helper_subfix_file = sys.argv[4]
	function_helper_file = sys.argv[5]
	struct_helper_file = sys.argv[6]

	with open(symbolinfo_file) as data_file:
	    symbolinfo = json.load(data_file)

	with open(typeinfo_file) as data_file:
	    typeinfo = json.load(data_file)

	with open(function_list_file) as data_file:
		function_list = data_file.read().splitlines()

	with open(function_helper_subfix_file) as data_file:
		function_helper_subfix = data_file.read()

	function_helper_f = open(function_helper_file, 'w')
	struct_helper_f = open(struct_helper_file, 'w')

	total_root_vars_lists={}
	for func in function_list:
		result=re.match(r'^#.*$', func)
		if result:
			continue

#		print "DEBUG: parsing function: " + func
		if func in syscallSkip:
			print "Skip " + func + " at this moment"
			continue

		prefered_function = try_function_def(symbolinfo, func)
		if prefered_function:
			funcParam=parse_function(symbolinfo, typeinfo, prefered_function)
			if funcParam[0] and funcParam[1]:
				function_helper_f.write(generate_func_helper(function_helper_subfix, funcParam[0], funcParam[1], funcParam[2], funcParam[3]))

				for type_name,type_value in funcParam[3].items():
					if not type_name in total_root_vars_lists:
						print "adding " + type_name
						print type_value
						total_root_vars_lists[type_name] = type_value
		else:
			print func + " is not found"

	for type_name,type_value in total_root_vars_lists.items():
		struct_helper_f.write(generate_type_function(type_name, type_value))

	function_helper_f.close()
	struct_helper_f.close()

	format_file(function_helper_file)
	format_file(struct_helper_file)

if __name__ == '__main__':
	main()
