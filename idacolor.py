import idc

currentEA = ''
currentMnem = ''
prevMnem = ''
nextMnem = ''
currentOp = ''


print("Running IDA setup script")
print("Setting startup options")

# set demangled names options to show names
idc.set_inf_attr(INF_DEMNAMES, DEMNAM_NAME)
# show the address next to each command
idc.set_inf_attr(INF_OUTFLAGS, OFLG_SHOW_PREF)
idc.set_inf_attr(INF_PREFFLAG, 0)
print("Finished setting options")

currentEA = idc.get_first_seg()
currentEA = idc.next_head(currentEA, 0xFFFFFFFFFFFFFFFF)

while(currentEA != BADADDR):
	currentMnem = 	idc.print_insn_mnem(currentEA)

	#Highlight call functions
	if(currentMnem == "call"):
	#check to see if it's a call pop
		nextMnem = 	idc.print_insn_mnem(idc.get_operand_value(currentEA, 0))
		if nextMnem == "pop":
			idc.set_color(currentEA, CIC_ITEM, 0xff1d4a)
			idc.set_color(idc.get_operand_value(currentEA, 0), CIC_ITEM, 0x4a1dFF)
		else:
			idc.set_color(currentEA, CIC_ITEM, 0xc7c7ff)
        
    #Non-zeroing XORs are often signs of data encoding
	if (currentMnem == "xor"):
		if (idc.print_operand(currentEA, 0) != idc.print_operand(currentEA, 1)): 
			idc.set_color(currentEA, CIC_ITEM, 0xFFFF00)
        
        
	currentEA = idc.next_head(currentEA, 0xFFFFFFFFFFFFFFFF)	
	prevMnem = currentMnem
