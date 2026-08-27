# Russia-Based Influence Operation Targeting Hungary

Meta disrupted a Russia-based Coordinated Inauthentic Behavior (CIB) network targeting Hungary. This file contains indicators of compromise and a network summary from Meta’s Adversarial Threat Report H2 2026.

## Meta’s Adversarial Threat Report Network Summary

We disrupted a Coordinated Inauthentic Behavior network originating in Russia and targeting audiences in Hungary.  We removed 6 Facebook accounts and 4 Pages for violating our policy against Coordinated Inauthentic Behavior. About 15,200 accounts followed one or more of these Pages, and we determined through these enforcement actions that network operators engaged in around $1,400 in spending, paid for mostly in US Dollars, for ads on Facebook. We found this network as a result of Meta’s investigation and took action ahead of the election in Hungary. Our investigation found links to individuals in Russia.

The operation employed sophisticated operational security and impersonation tactics, running Pages that posed as local Hungarian and Ukrainian media. These assets, managed by inauthentic accounts obscuring their origin through proxy servers, amplified links to a set of external domains, which included both fabricated news sites and fictitious investigative journalism outlets. Operators activated dormant Pages—some created months in advance to post legitimate news to appear authentic—and renamed them simultaneously just prior to launching their campaigns. They then utilized undeclared political advertisements to launder their fabricated, AI-generated content from the deceptive websites onto our platforms to target domestic audiences in Hungary. We observed the network systematically disseminate messaging focused on the Hungarian elections, utilizing narratives designed to discredit Fidesz's political opposition—most notably the Tisza party and its candidates.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Domain | `oknyomozoriport[.]hu` |
| Domain | `ecij[.]org` |
| Domain | `timesofukraine[.]net` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H2 2026](TBD)
- **AlienVault OTX Pulse:** [h2-2026-russia-cib-based-network-3 on OTX](https://otx.alienvault.com/pulse/h2-2026-russia-cib-based-network-3)
- **IOC File (GitHub):** [h2-2026-russia-cib-based-network-3 on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/h2-2026-russia-cib-based-network-3.md)
