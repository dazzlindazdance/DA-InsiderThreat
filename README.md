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

## Installation Instructions
TBD
