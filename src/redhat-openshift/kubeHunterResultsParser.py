import sys
import json

def fetchVulList(fileName):
    logData = open(fileName, 'r')
    logData = list(logData)
    column1 = list()    
    column2 = list()    
    column3 = list()    
    column4 = list()
    column5 = list()    
    for iter in logData:
        if "|" in iter:
            columns = iter.split("|")
        else:
            columns = iter.split("+")
        columnCount = 0
        for columnData in columns:
            if(columnData!='' and columnData!='\n'):
                columnCount=columnCount+1
                if(columnCount == 1):
                    if(columnData.strip() != ''):
                        column1.append(columnData)
                    else:
                        column1.append("#######")
                if(columnCount == 2):
                    if(columnData.strip() != ''):
                        column2.append(columnData)
                    else:
                        column2.append("#######")
                if(columnCount == 3):
                    if(columnData.strip() != ''):
                        column3.append(columnData)
                    else:
                        column3.append("#######")
                if(columnCount == 4):
                    if(columnData.strip() != ''):
                        column4.append(columnData)
                    else:
                        column4.append("#######")
                if(columnCount == 5):
                    if(columnData.strip() != ''):
                        column5.append(columnData)
                    else:
                        column5.append("#######")
    processedcolumn1 = list()   
    processedcolumn2 = list()   
    processedcolumn3 = list()   
    processedcolumn4 = list()
    processedcolumn5 = list()  
    vulnerablityList = list() 
    columnString = ""
    for columnEntry in column1:
        if '--' in columnEntry:
            if columnString.strip() != '':
                processedcolumn1.append(columnString)
            columnString = ""
        else:
            if columnEntry != '#######':
                columnString = columnString + columnEntry
    columnString = ""   
    for columnEntry in column2:
        if '--' in columnEntry:
            if columnString.strip() != '':
                processedcolumn2.append(columnString)
            columnString = ""
        else:
            if columnEntry != '#######':
                columnString = columnString + columnEntry
    for columnEntry in column3:
        if '--' in columnEntry:
            if columnString.strip() != '':
                processedcolumn3.append(columnString)
            columnString = ""
        else:
            if columnEntry != '#######':
                columnString = columnString + columnEntry
    for columnEntry in column4:
        if '--' in columnEntry:
            if columnString.strip() != '':
                processedcolumn4.append(columnString)
            columnString = ""
        else:
            if columnEntry != '#######':
                columnString = columnString + columnEntry       
    for columnEntry in column5:
        if '--' in columnEntry:
            if columnString.strip() != '':
                processedcolumn5.append(columnString)
            columnString = ""
        else:
            if columnEntry != '#######':
                columnString = columnString + columnEntry   
    column1Length = len(processedcolumn1)
    column2Length = len(processedcolumn2)
    column3Length = len(processedcolumn3)
    column4Length = len(processedcolumn4)
    column5Length = len(processedcolumn5)
    maxCount = 0
    if(column1Length > maxCount) :
        maxCount = column1Length
    if(column2Length > maxCount) :
        maxCount = column2Length
    if(column3Length > maxCount) :
        maxCount = column3Length
    if(column4Length > maxCount) :
        maxCount = column4Length
    if(column5Length > maxCount) :
        maxCount = column5Length     
    for jsonEntry in range(maxCount):
        if jsonEntry == 0 :
            continue
        vulnerablity =  {}
        if jsonEntry < len(processedcolumn1):
            vulnerablity["LOCATION"] = processedcolumn1[jsonEntry]
        if jsonEntry < len(processedcolumn2):
            vulnerablity["CATEGORY"] = processedcolumn2[jsonEntry]
        if jsonEntry < len(processedcolumn3):
            vulnerablity["VULNERABILITY"] = processedcolumn3[jsonEntry]
        if jsonEntry < len(processedcolumn4):
            vulnerablity["DESCRIPTION"] = processedcolumn4[jsonEntry]
        if jsonEntry < len(processedcolumn5):
            vulnerablity["EVIDENCE"] = processedcolumn5[jsonEntry]   
        vulnerablityList.append(vulnerablity)
    return vulnerablityList    
    
def main(args):
    fetchVulList("vul.txt")

if __name__ == "__main__":
    main(sys.argv)


