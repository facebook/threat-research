# Iran-Based Influence Operation Targeting Azerbaijan

Meta disrupted a Iran-based Coordinated Inauthentic Behavior (CIB) network targeting Azerbaijan. This file contains indicators of compromise and a network summary from Meta’s Adversarial Threat Report H2 2026.

## Meta’s Adversarial Threat Report Network Summary

We disrupted a Coordinated Inauthentic Behavior network originating in Iran and primarily targeting audiences in Azerbaijan, alongside minor targeting of neighboring Georgia and Armenia. The operation maintained a cross-platform presence, including on TikTok and Telegram. We removed 15 Facebook accounts, 7 Pages, and 96 Instagram accounts for violating our policy against Coordinated Inauthentic Behavior. About 23,600 accounts followed one or more of these Pages, and about 77,200 accounts followed one or more of these Instagram accounts. Although the people behind it attempted to conceal their identity, our investigation found links to Azerbaijani individuals in Iran.

The network engaged in sophisticated brand development, using inauthentic accounts to manage media entities that masqueraded as authentic local Azerbaijani news outlets. To tailor their messaging, operators employed a highly segregated content strategy, building distinct brands focused exclusively on single geopolitical topics—such as criticizing the EU, domestic policy, or promoting religious content—without using overt pro-Iran framing. The operation also demonstrated a notable investment in original content production, leveraging AI-generated media imagery and videos featuring AI-generated characters to criticize Azerbaijan’s domestic policies. To amplify these narratives, the network utilized clusters of inauthentic accounts to artificially boost engagement on their own media accounts, while also commenting directly on the posts of authentic Azerbaijani media entities. The operation demonstrated moderate operational security through strict operator and device segregation between brands, proxy IP usage to obfuscate their origins, and the creation of reserve accounts in an attempt to increase the longevity of their brands against enforcement actions. We observed that network operators promoted pro-Iran and pro-Shia narratives, criticized Azerbaijani internal affairs, and attempted to undermine confidence in the Azerbaijani government.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Social Media Account | `http://t[.]me/xeybar_az` |
| Social Media Account | `http://tiktok[.]com/@sozundibi6` |
| Social Media Account | `http://tiktok[.]com/@kolgetv` |
| Social Media Account | `http://tiktok[.]com/aydin_baxish` |
| Social Media Account | `http://tiktok[.]com/@azadhaqq` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H2 2026](TBD)
- **AlienVault OTX Pulse:** [h2-2026-iran-cib-based-network-2 on OTX](https://otx.alienvault.com/pulse/h2-2026-iran-cib-based-network-2)
- **IOC File (GitHub):** [h2-2026-iran-cib-based-network-2 on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/h2-2026-iran-cib-based-network-2.md)
