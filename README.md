# intelMQ development

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
