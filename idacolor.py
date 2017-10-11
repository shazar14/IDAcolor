currentEA = ''
currentMnem = ''
prevMnem = ''
nextMnem = ''
currentOp = ''

print("Running IDA setup script")

print("Setting startup options")
# set demangled names options to show names
SetCharPrm(INF_DEMNAMES, DEMNAM_NAME)
# show the address next to each command
# SetCharPrm(INF_SHOWPREF, 1)
print("Finished setting options")

currentEA = FirstSeg()
currentEA = NextHead(currentEA, 0xFFFFFFFFFFFFFFFF)

while(currentEA != BADADDR):
	currentMnem = GetMnem(currentEA)

	#Highlight call functions
	if(currentMnem == "call"):
	#check to see if it's a call pop
		nextMnem = GetMnem(GetOperandValue(currentEA, 0))
		if nextMnem == "pop":
			SetColor(currentEA, CIC_ITEM, 0xff1d4a)
			SetColor(GetOperandValue(currentEA, 0), CIC_ITEM, 0x4a1dFF)
		else:
			SetColor(currentEA, CIC_ITEM, 0xc7c7ff)
        
    #Non-zeroing XORs are often signs of data encoding
	if (currentMnem == "xor"):
		if (GetOpnd(currentEA, 0) != GetOpnd(currentEA, 1)): 
			SetColor(currentEA, CIC_ITEM, 0xFFFF00)
        
        
	currentEA = NextHead(currentEA, 0xFFFFFFFFFFFFFFFF)	
	prevMnem = currentMnem
