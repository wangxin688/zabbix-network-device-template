from pysnmp.hlapi import *
import json
import requests
import pickle

def zabbix_login():
    ##zabbix API
    url = "http://10.122.22.33/zabbix/api_jsonrpc.php"
    headers = {"Content-Type": "application/json-rpc"}
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "parms":
        {
            "user": "Admin",
            "password" : "zabbix"
        },
        "id":1}
    r = requests.post(url,data=json.dumps(payload),headers=headers)
    output = r.json()['result']
    return output
def snmpwalk(host,oid):
    ## SNMPWALK
    listtmp = list()
    varBindsTable = nextCmd(SnmpEngine(),
            UsmUserData('admin', authKey='Lenovo123',
                        privKey='Lenovo123', authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol,
                        securityEngineId=None, authKeyType=usmKeyTypePassphrase, privKeyType=usmKeyTypePassphrase),
            UdpTransportTarget((host, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
            )
    while True:
        try:
            errorIndication, errorStatus, errorIndex, varBinds = next(varBindsTable);
            if errorIndication:
                print(errorIndication)
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            else:
                for name, val in varBinds:
                    listtmp.append((('%s' % (name.prettyPrint()),(val.prettyPrint()))))
        except StopIteration:
            break
    return listtmp

def RegularTheListWhit1Dot(list1):
    #处理第一层的snmpindex，取值snmpindex和snmpvalue
    tmplist = [[i[0].rsplit(".")[-1], i[1]] for i in list1]
    return tmplist
def RegularTheListWhit2Dot(list):
    #处理两层的snmpindex，取值snmpindex和snmpvalue
    tmplist = [[i[0].rsplit(".")[-2], i[0].rsplit(".")[-1], i[1]] for i in list]
    return tmplist

def SplitTheParent(list1):
    tmp = list()
    output = list()
    for i in range(len(list1)):
        if list1[i][0] == tmp:
            output[-1].append(list1[i])
        else:
            tmp = list1[i][0]
            output.append([])
            output[-1].append(list1[i])
        return output

def GetThe4thItem(list1):
    tmp = list()
    output = list()
    for i in range(len(list1)):
        for d in range(len(list1[i])):
            if list1[i][d][-1] == "0":
                for e in range(len(list1[i])):
                    if list1[i][e][-1] == list1[i][d][1]:
                        for m in range(len(list1[i])):
                             if list1[i][m][-1] == list1[i][e][1]:
                                 for k in range(len(list1[i])):
                                     if list1[i][k][-1] == list1[i][m][1]:
                                         if list1[i][k][0] == tmp:
                                            output[-1].append(list1[i][k])
                                         else:
                                            tmp = list1[i][k][0]
                                            output.append([])
                                            output[-1].append(list1[i][k])
            return output

def ListInerJoin(QosIndex, IfIndex):
            output = QosIndex
            for i in range(len(QosIndex)):
                for e in range(len(IfIndex)):
                    if IfIndex[e][0] == QosIndex[i][1]:
                        output[i].append(IfIndex[e][1])
            return output

def AddIndscrTocbQosParentObjectindex(qosParIndex, indexDscr):
            output = qosParIndex
            for i in range(len(qosParIndex)):
                for e in range(len(qosParIndex[i])):
                    for m in range(len(indexDscr)):
                        if qosParIndex[i][e][0] == indexDscr[m][0]:
                            for k in range(1, len(indexDscr[m])):
                                output[i][e].append(indexDscr[m][k])
            return output

def ChangeDirectionName(directionlist):
            output = directionlist
            for i in range(len(directionlist)):
                if directionlist[i][1] == "2":
                    output[i][1] = "OutPut"
                elif directionlist[i][1] == "1":
                    output[i][1] = "InPut"
            return output

def findThePMCMname(configindex, PMname, CMname):
    #查找policy-map名称，三个参数分别为配置索引，policy-map名称，class-map名称
            tmp = configindex
            for i in range(len(tmp)):
                for e in range(len(PMname)):
                    if tmp[i][2] == PMname[e][0]:
                        tmp[i].append(PMname[e][1])
                for k in range(len(CMname)):
                    if tmp[i][2] == CMname[k][0]:
                        tmp[i].append(CMname[k][1])
            return tmp

def finalwithPMCM(finallist, PMCM):
            tmp = finallist
            for i in range(len(tmp)):
                for e in range(len(tmp[i])):
                    for k in range(len(PMCM)):
                        if (tmp[i][e][0] == PMCM[k][0]) & (tmp[i][e][1] == PMCM[k][1]):
                            tmp[i][e].append(PMCM[k][3])
            return tmp

        # 运行之前,请将在hostname内填入网络设备的ip,如:SH_C就填入168.7.229.14
        # hostname = "192.1.254.8"
hostname = "10.109.0.129"
cbQosCMName = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.7.1.1.1")
print(cbQosCMName)
cbQosconfigindex = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.5.1.1.2")
cbQosIfindex = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.1.1.1.4")
cbQosParentObjectindex = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.5.1.1.4")
cbQospolicydirection = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.1.1.1.3")
cbQosPolicymapname = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.6.1.1.1")
ifdescr = snmpwalk(hostname, "1.3.6.1.2.1.2.2.1.2")

cbQosCMName = RegularTheListWhit1Dot(cbQosCMName)
cbQosPolicymapname = RegularTheListWhit1Dot(cbQosPolicymapname)
cbQosconfigindex = RegularTheListWhit2Dot(cbQosconfigindex)
cbQosconfigindex = findThePMCMname(cbQosconfigindex, cbQosPolicymapname, cbQosCMName)
QosIndexAndIndscr = ListInerJoin(RegularTheListWhit1Dot(cbQosIfindex), RegularTheListWhit1Dot(ifdescr))
cbQosParentObjectindex = RegularTheListWhit2Dot(cbQosParentObjectindex)
cbQosParentObjectindex = SplitTheParent(cbQosParentObjectindex)
cbQosParentObjectindex = GetThe4thItem(cbQosParentObjectindex)
PMdirection = ChangeDirectionName(RegularTheListWhit1Dot(cbQospolicydirection))
finallist = AddIndscrTocbQosParentObjectindex(cbQosParentObjectindex, QosIndexAndIndscr)
finallist = AddIndscrTocbQosParentObjectindex(finallist, PMdirection)
finallist = finalwithPMCM(finallist, cbQosconfigindex)
print(finallist)
        # 数据结构[QosIfIndex, OidNodeIndex, ParentIndex, IntIndex, IntDscr, QosDirection, Class-Map or Policy-Map]
        # ['1151407774', '370922350', '1567479029', '23', 'GigabitEthernet0/0/0/3', 'OutPut', 'voice']
with open("final.pkl", 'wb') as f:
    pickle.dump(finallist, f)
    f.close()
        # 将附件保存到本地
