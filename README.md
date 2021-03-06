# intelMQ development

This file provides an overview of additional BOTS created compared to the official intelMQ. Please note that this is provided "as is", and may be subject to change without notice. Main purpose is to showcase capabilities of McAfee integration.

## Collector: McAfee ePO DXL Commands

This bot is being used to issue McAfee ePO DXL Commands and collect information. The bot requires three parameters:

- dxl_config_file: the DXL config file
- dxl_epo_command: the actual command to issue
- dxl_epo_parameters: additional parameters

For details on available commands please review your local ePO installation:

```
-> Menu -> Server Settings -> DXL Commands
```

## Parser: McAfee Rogue System Detection Parser

This parser processes the output of the DXL Command "detected.systems", which is collected by the DXL command collector bot. The incoming data is presented as JSON object. This bot requires the following parameters:

- rsd_isrogue: only rogue systems will be processed
- rsd_isactive: only active systems will be processed
- rsd_isnew: only newly detected systems will be processed

The bot generates one message per processed system, and provide a JSON object within the "output" field. This can be processed by subsequent bots.

## Collector: McAfee Data Streaming Bus

This bot is used to consume routed messages via McAfee Data Streaming Bus; the underlying technology is kafka.
The bot requires four parameters:

- dsb_ip: IP Address of the McAfee DSB appliance
- dsb_client_cert: the certificate used to authenticate Message Forwarding clients
- dsb_ca: the McAfee DSB CA
- dsb_topic: the name of the topic to subscribe; placeholders such as '*' may be used as well

In order to support full operations, the local /etc/hosts file needs to map the DSB GUID to the actual IP address. 

## Parser: McAfee ESM Export file parser

This bot is used to parse an export file as retrieved from the McAfee Event Receiver, which is collected by the intelMQ file collector. Please see the following link on how to create and use that file for bulk data source import.

https://docs.mcafee.com/bundle/enterprise-security-manager-data-sources-configuration-reference-guide/page/GUID-2764DC15-6045-4271-B454-F00905C022F9.html

This parser prepares the content for consumption by the McAfee ESM Add Datasource BOT

## Output: McAfee ESM Add Datasource

This bot is being used to board new data sources into ESM. The data is expected as JSON object 
within the "output" field. An upfront parser has to be in place generating the epected outcome

```
{
    'name': '(data source 1)',
    'ipAddress': '(IP Address)',
    'typeId': 65, # DS Type ID == Linux
    'zoneId': 0,
    'enabled': True,
    'url': 'http://IP_of_DS_webUI',
    'elm_logging': False,
    'els_logging': False
}
```

The JSON Element has to cover the following mandatory fields:

- name
- ipAddress
- typeId (alternative: vendor, model)
- zoneId
- enabled
- url

Additional fields (e.g. hostname, elm_logging) are optional. For details on available fields per McAfee Event Receiver please review the data source export file. The header (second line of the export file) contains a list of all available fields for your environment.

## Output: McAfee ePO DXL Commands

This bot is being used to issue McAfee ePO DXL Commands. The bot requires two parameters:

- dxl_config_file: the DXL config file
- dxl_epo_command: the actual command to issue

As parameters this bot expects JSON formatted content within the intelMQ 'output' field.
For details on available commands please review your local ePO installation:

```
-> Menu -> Server Settings -> DXL Commands
```


