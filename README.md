# intelMQ development

## Output: McAfee ESM Add Datasource

This bot is being used to board new data sources into ESM. The data is expected as JSON object 
within the "output" field. An upfront parser has to be in place formatting the epected outcome

```
{
    '(ERC ID)':
    [{
        'name': '(data source 1)',
        'ipAddress': '(IP Address)',
        'typeId': 65, # DS Type ID == Linux
        'zoneId': 0,
        'enabled': True,
        'url': 'http://IP_of_DS_webUI',
        'parameters': [
            {'key': 'elm_logging', 'value': False},
            {'key': 'els_logging', 'value': False}
        ]
    }]
}
```

The JSON Element may cover different ERC, each ERC can cover multiple data sources
