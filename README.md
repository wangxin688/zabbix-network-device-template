# Zabbix_Network_Device_template
zabbix tempaltes for Network Devices 
### SNMPv3
### Standard template
- ICMP
- SNMP Reachablity
- BGP
- Interface discovery module
  - must support IF-MIB
  - must have if-alias
## Vendor_lists:
- Cisco
  Interface Monitor: {#ifAilas}
    - **L2MON** in interface descirption: Network device interconnections
    ```
    interface gi0/0/1
     descripiton L2MON_TO_AccessSwtich-9300-F5-01
    ```
    - **CAPM** in interface description: Circuit Monitor, such as Interface, MPLS and etc.
    ```
    interface gi0/0/2
     description CAPM_To_Orange_MPLS_PUBOE01-01-200Mbps
    ```
  - IOS: basic-ios/nxos
  - NXOS: basic-ios/nxos
  - ASA
  - WLC 
    - AIRESPACE-WIRELESS-MIB 
    - CISCO-DOT11-SSID-SECURITY-MIB
    - IF-MIB
  - QOS
    - cannot use sample discovery rule, two ways to solve this one:
      - python
      - advance snmp discovery rule
  - IPSLA:
    - Filter monitor type: 9 udp-jitter for VOIP test
      - CISCO-IPSLA-ECHO-MIB
      - CISCO-IPSLA-ETHERNET-MIB
      - CISCO-RTTMON-MIB 
    - Filter monitor type 16: icmp-jitter 
      - CISCO-RTTMON-ICMP-MIB
    
- Huawei
- Junos
- F5-BIG-IP
- Palo Alto Firewall
- CheckPoint Firewall
- Bluecat DHCP
- Riverbed WOC
- Sangfor
