# Zabbix_Network_Device_template
zabbix tempaltes for Network Devices 
### SNMPv3
### Standard template
- ICMP
## Vendor_lists:
- Cisco
  Interface Monitor:
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
  - IPSLA: Filter monitor type: 9 udp-jitter for VOIP test
    - CISCO-IPSLA-ECHO-MIB
    - CISCO-IPSLA-ETHERNET-MIB
- Huawei
- Junos
- F5-BIG-IP
- Palo Alto Firewall
- CheckPoint Firewall
- Bluecat DHCP
- Riverbed WOC
- Sangfor
- BGP
