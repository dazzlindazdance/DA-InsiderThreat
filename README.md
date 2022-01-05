# DA-InsiderThreat
Splunk Addon to Extend Splunk Enterprise Security for Insider Threat Use Cases

## Remit
This addon extends Enterprise Security and allows a separate Insider team to utilise Enterprise Security, it follows the Risk based approaches of Enterprise Security but keeps the risk modifiers separate as Insider teams often want to restrict what is being alerted on even from the security team as one or more of that team might be the subject of investigations.

## Logical Diagram
![Logical Diagram](/appserver/static/logical_diagram.png)

## Requirements
### Index
There is a new index required for Insider Risk Events called `it_risk`

### Additional Apps and Addons required
- [Splunk Enterprise Security Suite](https://splunkbase.splunk.com/app/263/)
- [URL Toolbox](https://splunkbase.splunk.com/app/2734/)
- [Horseshoe Meter - Custom Visualization](https://splunkbase.splunk.com/app/3166/)
- [Splunk Timeline - Custom Visualization](https://splunkbase.splunk.com/app/3120/)

### Content Required
Insider Threat is all about your users, as a result we need to know certain information about them.  The ES Asset and Identity Framework is a perfect place to store this information, it should be regularly updated.
This information is also useful when performing investigations as will give access to key information without having to pivot to another system.
Information on the Enterprise Security Asset and Identity Framework can be found here: [Asset and Identity framework in Splunk ES](https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/assetandidentityframework/)
#### Identity Fields
The useful fields for Insider Threat.
##### identity
This is a pipe delimited field containing the usernames associated with an individual.  It is useful when trying to tie the actions of the different personas of a user back to the individual.  
##### first

##### last

##### category

##### watchlist

##### startDate

##### endDate

### Installation
TBD

## Configuration
TBD
#### Access restriction
You may want to restrict users outside the Insider Threat team from accessing the `it_risk` index so that they can't see if they themselves are being investigated.
### Lookups to Manage
