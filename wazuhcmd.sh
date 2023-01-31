#!/bin/bash

curl -sO https://packages.wazuh.com/4.3/wazuh-install.sh && sudo bash ./wazuh-install.sh -a


sudo apt update && sudo apt install -y wget

sudo wget https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/alienvault_reputation.ipset -O /var/ossec/etc/lists/alienvault_reputation.ipset

sudo echo "127.0.0.1" >> /var/ossec/etc/lists/alienvault_reputation.ipset

sudo wget https://wazuh.com/resources/iplist-to-cdblist.py -O /tmp/iplist-to-cdblist.py

sudo /var/ossec/framework/python/bin/python3 /tmp/iplist-to-cdblist.py /var/ossec/etc/lists/alienvault_reputation.ipset /var/ossec/etc/lists/blacklist-alienvault

sudo rm -rf /var/ossec/etc/lists/alienvault_reputation.ipset
sudo rm -rf /tmp/iplist-to-cdblist.py

sudo rm -rf /var/ossec/etc/lists/alienvault_reputation.ipset
sudo rm -rf /tmp/iplist-to-cdblist.py

file1="/var/ossec/etc/rules/local_rules.xml"

file2="/var/ossec/etc/ossec.conf"

file3="/var/ossec/etc/decoders/local_decoder.xml"

file4="/var/ossec/etc/lists/suspicious-programs"

echo "Giving permissions to $file"
chmod u+rw,g+r,o+r $file1

chmod u+rw,g+r,o+r $file2

chmod u+rw,g+r,o+r $file3



# Append to file1
echo "Appending to $file1"
echo '<group name="attack,">
    <rule id="100100" level="10">
    <if_group>web|attack|attacks</if_group>
    <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
    <description>IP address found in AlienVault reputation database.</description>
  </rule>
</group>
<group name="ossec,">
  <rule id="100050" level="0">
    <if_sid>530</if_sid>
    <match>^ossec: output: "process list"</match>
    <description>List of running processes.</description>
    <group>process_monitor,</group>
  </rule>

  <rule id="100051" level="7" ignore="900">
    <if_sid>100050</if_sid>
    <match>nc -l</match>
    <description>netcat listening for incoming connections.</description>
    <group>process_monitor,</group>
  </rule>
</group>
<group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
    <!-- Rules for Linux systems -->
    <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">/root</field>
        <description>File modified in /root directory.</description>
    </rule>
    <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">/root</field>
        <description>File added to /root directory.</description>
    </rule>
</group>
<group name="virustotal,">
  <rule id="100092" level="12">
    <if_sid>657</if_sid>
    <match>Successfully removed threat</match>
    <description>$(parameters.program) removed threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>

  <rule id="100093" level="12">
    <if_sid>657</if_sid>
    <match>Error removing threat</match>
    <description>Error removing threat located at $(parameters.alert.data.virustotal.source.file)</description>
  </rule>
</group>
<group name="syscheck,">
  <rule id="100300" level="7">
    <if_sid>550</if_sid>
    <field name="file">/tmp/yara/malware/</field>
    <description>File modified in /tmp/yara/malware/ directory.</description>
  </rule>
  <rule id="100301" level="7">
    <if_sid>554</if_sid>
    <field name="file">/tmp/yara/malware/</field>
    <description>File added to /tmp/yara/malware/ directory.</description>
  </rule>
</group>

<group name="yara,">
  <rule id="108000" level="0">
    <decoded_as>yara_decoder</decoded_as>
    <description>Yara grouping rule</description>
  </rule>
  <rule id="108001" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: INFO - Scan result: </match>
    <description>File "$(yara_scanned_file)" is a positive match. Yara rule: $(yara_rule)</description>
  </rule>
</group>
<group name="syscheck,">
  <rule id="100303" level="7">
    <if_sid>550</if_sid>
    <field name="file">C:\\Users\\<USER_NAME>\\Downloads</field>
    <description>File modified in C:\Users\<USER_NAME>\Downloads directory.</description>
  </rule>
  <rule id="100304" level="7">
    <if_sid>554</if_sid>
    <field name="file">C:\\Users\\<USER_NAME>\\Downloads</field>
    <description>File added to C:\Users\<USER_NAME>\Downloads  directory.</description>
  </rule>
</group>

<group name="yara,">
  <rule id="108000" level="0">
    <decoded_as>yara_decoder</decoded_as>
    <description>Yara grouping rule</description>
  </rule>

  <rule id="108001" level="12">
    <if_sid>108000</if_sid>
    <match>wazuh-yara: INFO - Scan result: </match>
    <description>File "$(yara_scanned_file)" is a positive match. Yara rule: $(yara_rule)</description>
  </rule>
</group>
<group name="audit">
  <rule id="100210" level="12">
      <if_sid>80792</if_sid>
  <list field="audit.command" lookup="match_key_value" check_value="red">/var/ossec/etc/lists/suspicious-programs</list>
    <description>Audit: Highly Suspicious Command executed: $(audit.exe)</description>
      <group>audit_command,</group>
  </rule>
</group>
' >> $file1



# Append to file2
echo "Appending to $file2"
echo "<ossec_config>
  <ruleset>
    <!-- Default ruleset -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>/var/ossec/etc/lists/audit-keys</list>
    <list>/var/ossec/etc/lists/amazon/aws-eventnames</list>
    <list>/var/ossec/etc/lists/security-eventchannel</list>
    <list>/var/ossec/etc/lists/blacklist-alienvault</list>
    <list>/var/ossec/etc/lists/suspicious-programs</list>

    <!-- User-defined ruleset -->
    <decoder_dir>/var/ossec/etc/decoders</decoder_dir>
    <rule_dir>/var/ossec/etc/rules</rule_dir>
  </ruleset>

  <active-response>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>100100</rules_id>
    <timeout>60</timeout>
  </active-response>

  <active-response>
    <command>netsh</command>
    <location>local</location>
    <rules_id>100100</rules_id>
    <timeout>60</timeout>
  </active-response>

  <active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>5712</rules_id>
  <timeout>1800</timeout>
</active-response>

<integration>
    <name>virustotal</name>
    <api_key></api_key> <!-- Replace with your VirusTotal API key -->
    <rule_id>100200,100201</rule_id>
    <alert_format>json</alert_format>
  </integration>

  <integration>
    <name>virustotal</name>
    <api_key></api_key> <!-- Replace with your VirusTotal API key -->
    <group>syscheck</group>
    <alert_format>json</alert_format>
  </integration>

  <command>
    <name>remove-threat</name>
    <executable>remove-threat.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>

  <command>
    <name>remove-threat</name>
    <executable>remove-threat.exe</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>remove-threat</command>
    <location>local</location>
    <rules_id>87105</rules_id>
  </active-response>

    <command>
    <name>yara_linux</name>
    <executable>yara.sh</executable>
    <extra_args>-yara_path /usr/local/bin -yara_rules /tmp/yara/rules/yara_rules.yar</extra_args>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>yara_linux</command>
    <location>local</location>
    <rules_id>100300,100301</rules_id>
  </active-response>

   <command>
    <name>yara_windows</name>
    <executable>yara.bat</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <command>yara_windows</command>
    <location>local</location>
    <rules_id>100303,100304</rules_id>
  </active-response>

   <localfile>
      <log_format>syslog</log_format>
      <location>/var/ossec/logs/active-responses.log</location>
  </localfile>
</ossec_config>" >> $file2



# Append to file2
echo "Appending to $file3"
echo '<decoder name="yara_decoder">
  <prematch>wazuh-yara:</prematch>
</decoder>

<decoder name="yara_decoder1">
  <parent>yara_decoder</parent>
  <regex>wazuh-yara: (\S+) - Scan result: (\S+) (\S+)</regex>
  <order>log_type, yara_rule, yara_scanned_file</order>
</decoder>
' >> $file3



# Append to file2
echo "Writing to $file4"
echo 'ncat:yellow
nc:red
tcpdump:orange
' >> $file4

sudo systemctl restart wazuh-manager
