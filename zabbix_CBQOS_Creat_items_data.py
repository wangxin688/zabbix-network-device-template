from pysnmp.hlapi import *
import json
import requests
import pickle


### 定义snmpwalk方法，取出数据的数据结构[['snmpoid','snmpvalue'],['snmpoid','snmpvalue']]
def snmpwalk(host,oid):
    listtmp = list()
    varBindsTable = nextCmd(SnmpEngine(),
            UsmUserData('admin', authKey='test123',
                        privKey='test123', authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol,
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
### 定义snmpgetindex方法，取出数据的数据结构为[['snmpoid'],['snmpoid']]
def getsnmpindex(host,oid):
    snmpindex = list()
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
                    snmpindex.append((('%s' % (name.prettyPrint()))))
        except StopIteration:
            break
    return snmpindex
### 定义snmpgetvalue方法，取出数据的数据为[['snmpvalue'],['snmpvalue']]
def getsnmpvalue(host,oid):
    SNMPVALUE = list()
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
                    SNMPVALUE.append((('%s' % (val.prettyPrint()))))
        except StopIteration:
            break
    return SNMPVALUE

### 定义获取snmp最后一级的snmpindexid+snmpvalue
def GetLastOneSnmpindexID(list1):
    tmplist = [[i[0].rsplit(".")[-1], i[1]] for i in list1]
    return tmplist
### 定义获取snmp最后两级的snmpindexid+snmpvalue
def GetLastTwoSnmpindexID(list2):
    tmplist = [[i[0].rsplit(".")[-2], i[0].rsplit(".")[-1], i[1]] for i in list2]
    return tmplist
### 定义获取接口出方向调用PM的SNMPINDEX, 修改output snmpvalue 2为output
def GetOutputDirectionPMIndex(directionlist):
    output = directionlist
    for i in range(len(directionlist)):
        if directionlist[i][1] == "2":
            output[i][1] = "OutPut"
            output = output[i]
        #elif directionlist[i][1] == "1":
            #output[i][1] = "InPut"
    return output
### 定义policy-map、class-map和QoSconfigindex关联关系
def findThePMCMname(configindex, PMname, CMname):
    tmp = configindex
    for i in range(len(tmp)):
        for j in range(len(PMname)):
            if tmp[i][2] == PMname[j][0]:
                tmp[i].append(PMname[j][1])
        for k in range(len(CMname)):
            if tmp[i][2] == CMname[k][0]:
                tmp[i].append(CMname[k][1])
    return tmp
### 定义Qos调用接口index和物理子接口index的关联关系
def ListInerJoin(QosIndex,IfIndex):
    output = QosIndex
    for i in range(len(QosIndex)):
        for j in range(len(IfIndex)):
            if IfIndex[j][0] == QosIndex[i][1]:
                output[i].append(IfIndex[j][1])
    return output
### 分离父类对象，合并在一个list中
def SplitQosParentObject(list1):
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

### Qos方向命名mapping， 1为input，2为output
def ChangeDirectionName(directionlist):
    output = directionlist
    for i in range(len(directionlist)):
        if directionlist[i][1] == "2":
            output[i][1] = "OutPut"
        elif directionlist[i][1] == "1":
            output[i][1] = "InPut"

    return output
### 提取Qos的四级结构关系
class Node(object):
    def __init__(self, parent, value):
        self.parent = parent
        self.children = set()
        self.value = value

    def __repr__(self):
        return self.value

    def has_parent(self):
        return bool(self.parent)

    def has_children(self):
        return bool(self.children)
class Tree(object):
    def __init__(self):
        self.root = None
        self._values = dict()

    def parse(self, items):
        for v1, child, v3 in items:
            if v1 == child:
                continue
            self.get_or_create_root(v1)
            self.add_node(v3, child)
        return self

    def add_node(self, parent_value, child_value):
        parent = self._get_or_create_parent(parent_value)
        if parent.value != self.root.value:
            self.root.children.add(parent)
            parent.parent = self.root

        if child_value not in self._values:
            child = Node(parent, child_value)
            self._values[child_value] = child
            parent.children.add(child)
        return self._values.get(child_value)

    def _get_or_create_parent(self, value):
        if value not in self._values:
            self._values[value] = Node(parent=None, value=value)
        return self._values[value]

    def get_or_create_root(self, value):
        if self.root is None:
            self.root = Node(parent=None, value=value)
            self._values[value] = self.root
        return self.root

    def to_table(self):
        def _loop_node(node):
            if node.has_children():
                for child in node.children:
                    if node.has_parent():
                        items = [node.parent.value, node.value, child.value]
                        ret.append(items)
                    _loop_node(child)

        ret = []
        _loop_node(self.root)

        ret.sort(key=lambda item: (item[0], item[1]))
        return ret

    def to_partial(self):
        def _loop_node(node):
            for child in node.children:
                if child.has_children():
                    ret.append([child.parent.value, child.value, child.parent.value])
                    _loop_node(child)
                else:
                    ret.append([child.parent.parent.value, child.value, child.parent.value])

        ret = [[self.root.value, self.root.value, '0']]
        _loop_node(self.root)

        ret.sort(key=lambda item: (item[0], item[1]))
        return ret
def GetThe4thItem(list1):
    trees = []
    output = list()
    for items in list1:
        tree = Tree()
        trees.append(tree.parse(items))
    result = []
    for tree in trees:
        output.append(tree.to_table())
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

def finalwithPMCM(finallist, PMCM):
            tmp = finallist
            for i in range(len(tmp)):
                for e in range(len(tmp[i])):
                    for k in range(len(PMCM)):
                        if (tmp[i][e][0] == PMCM[k][0]) & (tmp[i][e][1] == PMCM[k][1]):
                            tmp[i][e].append(PMCM[k][3])
            return tmp


### hostname为zabbix主机IP
hostname = '10.109.0.129'
## 获取class-map的一级index和value
cbQosCMName = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.7.1.1.1")
cbQosCMName = GetLastOneSnmpindexID(cbQosCMName)

## 获取policy-map的一级index和value
cbQosPMName = snmpwalk(hostname,"1.3.6.1.4.1.9.9.166.1.6.1.1.1")
cbQosPMName = GetLastOneSnmpindexID(cbQosPMName)

## 获取Qos配置对象index二级index和value,数据结构[['index2,'index1','snmpvalue','snmpvalue']]
##
cbQosconfigindex = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.5.1.1.2")
cbQosconfigindex = GetLastTwoSnmpindexID(cbQosconfigindex)
cbQosconfigindex = findThePMCMname(cbQosconfigindex,cbQosPMName,cbQosCMName)
## 获取调用QoS service-policy的接口
cbQosIfindex = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.1.1.1.4")
ifdescr = snmpwalk(hostname, "1.3.6.1.2.1.2.2.1.2")
QosIndexAndIndscr = ListInerJoin(GetLastOneSnmpindexID(cbQosIfindex), GetLastOneSnmpindexID(ifdescr))
## 处理Qos父类对象
##### cbQosParentObjectsIndex
###QOS对象父类对象索引
###   - class-map: class-map的父类对象索引是相关联的policy-map的索引
###   - 对于match语句，父类索引是其关联的class-map的index
###   - 对于action，父类index是class-map应用的action
###   - 对于非继承的policy-map，父类索引是其关联的逻辑接口，所以为0（子接口0）
###   - 对于继承类的policy-map是其嵌套的class-map的索引
cbQosParentObjectindex = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.5.1.1.4")
cbQosParentObjectindex = GetLastTwoSnmpindexID(cbQosParentObjectindex)
cbQosParentObjectindex = SplitQosParentObject(cbQosParentObjectindex)
cbQosParentObjectindex = GetThe4thItem(cbQosParentObjectindex)


## 处理policy-map的方向
cbQospolicydirection = snmpwalk(hostname, "1.3.6.1.4.1.9.9.166.1.1.1.1.3")
PMdirection = ChangeDirectionName(GetLastOneSnmpindexID(cbQospolicydirection))

finallist = AddIndscrTocbQosParentObjectindex(cbQosParentObjectindex, QosIndexAndIndscr)
finallist = AddIndscrTocbQosParentObjectindex(finallist, PMdirection)
finallist = finalwithPMCM(finallist, cbQosconfigindex)
with open("final.pkl", 'wb') as f:
    pickle.dump(finallist, f)
    f.close()
        # 将附件保存到本地
