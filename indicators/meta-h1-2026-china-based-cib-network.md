# Indicators of Compromise: China-Based Influence Operation Network Targeting Taiwan

Meta disrupted a China-based Coordinated Inauthentic Behavior (CIB) network targeting Taiwan. This file contains Indicators of Compromise (IOCs) from Meta’s Adversarial Threat Report H1 2026.

## Meta’s Adversarial Threat Report Network Summary

We disrupted a network originating in China that targeted audiences in Taiwan. We actioned 154 Facebook accounts, 23 Pages, and 1 Instagram account for violating our policy against Coordinated Inauthentic Behavior. About 93,000 accounts followed one or more of these Pages. This network promoted pro-Beijing narratives and criticized Taiwan’s ruling party. The network engaged in around $15,000 in spending for ads on Facebook and Instagram, paid for mostly in Hong Kong Dollars, Chinese Yuan, Taiwan New Dollars, likely to appear more legitimate.

The network operated several pages, such as Taiwan Gossip Net and New Generation Rebellion, that claimed to be run by Taiwanese volunteers and nationals. These pages and their associated websites encouraged users to submit anonymous grievances about Taiwanese public affairs to foster domestic discord. The individuals behind this campaign used Taiwan-based proxy IPs and traditional Chinese script to make their operations appear to be of Taiwanese origin. Despite this obfuscation, our investigation uncovered that the network originated from China. The network maintained a presence on other platforms and a dedicated Android app to support its fake personas.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Domain | `newgenerationrebellion[.]com` |
| Domain | `ngrebellion[.]com` |
| Domain | `newgenreb[.]com` |
| Domain | `twgossiping[.]com` |
| Social Media Account | `youtube[.]com/@NewGenerationRebellion` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H1 2026](https://transparency.meta.com/sr/first-half-2026-Adversarial-threat-report/)
- **AlienVault OTX Pulse:** [meta-h1-2026-china-based-cib-network on OTX](https://otx.alienvault.com/pulse/meta-h1-2026-china-based-cib-network)
- **IOC File (GitHub):** [meta-h1-2026-china-based-cib-network on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/meta-h1-2026-china-based-cib-network.md)
