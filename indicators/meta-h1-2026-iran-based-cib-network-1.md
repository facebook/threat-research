# Indicators of Compromise: Deep Dive: Dissecting the Kill Chain of an Early-Stage Iranian Influence Operation

## Meta’s Adversarial Threat Report Network Summary

Iranian threat actors continue to target the US and other English-speaking audiences via CIB operations. These networks, which use inauthentic accounts to create and distribute their content, share several key narratives, including criticism of US policies in the Middle East, as well as support for Gaza in the Israel-Gaza conflict. Today we are sharing an insight into one such operation that we detected and disrupted. 
We actioned 8 Facebook accounts, 2 Pages, and 294 Instagram accounts for violating our policy against Coordinated Inauthentic Behavior. About 15 accounts followed one or more of these Pages, and about 41,000 accounts followed one or more of these Instagram accounts. There was no ad spend associated with this network. The network originated in Iran and primarily targeted English-speaking audiences in the United States, with a smaller, earlier component targeting Arabic-speaking audiences in Iraq. Our systems detected the deceptive activity early, allowing us to disrupt the operation before it managed to build an authentic audience on our services.

While Iranian threat actors are persistent, this specific investigation offers the opportunity to analyze the lifecycle of a CIB network caught in its infancy. Our automated systems detected this operation early in its development, allowing us to observe how the network moved through its "kill chain,” from establishing infrastructure and building personas to attempting distribution, before it could successfully build an authentic audience.
As we have previously reported, Meta uses the Online Operations Kill Chain framework to analyze many sorts of malicious online operations, identify the earliest opportunities to disrupt them, and share information across investigative teams. The kill chain describes the sequence of steps threat actors go through to establish a presence across internet services, disguise their operations, engage with potential audiences, and respond to takedowns. 

Acquiring Assets
We found this activity as a result of an internal investigation into suspected CIB in the region. The activity targeting the US on our platforms represented an expansion of a well-established influence operation that we assess began in 2024 on X, where dozens of interconnected fictitious personas portraying themselves as US residents shared each other’s content. 

Technically sophisticated adversaries, such as Iranian CIB actors, employ advanced operational tradecraft to evade detection by our automated systems. For example, these actors can invest in clean devices and cloud or proxy IP usage to attempt to obfuscate the origin and identity of authentic operators behind these networks. Despite these efforts, our deep-dive investigation identified signals that linked the activity to individuals in Iran.
However, CIB operations are structured to advance specific strategic objectives, developing content narratives and establishing inauthentic accounts tailored to target particular audiences. By analyzing both infrastructural indicators and behavioral patterns shared among these accounts, we were able to identify coordinated activity across a network, despite the barriers posed by actors' operational security.

Disguising Assets
Once the infrastructure was established, the network moved to a "prepare" phase, investing resources into creating credible personas. The network employed a two-tiered structure consisting of “creators” and “amplifiers”.
The core of the network consisted of a subset of high-complexity accounts (the “creators”) designed to produce original content. These personas had well-developed backstories, interests, and jobs, and included an American political scientist with a PhD, a women’s rights activist, and an Albanian satirical cartoonist. To increase credibility, these accounts utilized multiple, high quality AI-generated images for profile pictures. In addition to sophisticated human personas, the network also developed convincing brand identities to make their operation appear like a local, grassroots movement. The network adhered to a brand identity by interspersing strategic content with general news or non-civic content.
Surrounding the core creators was a larger ring of lower-complexity “amplifier” personas designed to boost engagement. The amplifiers engaged with creators’ content via comments, reactions, and shares, in an attempt to make their content appear more popular. 

Targeted Engagement
After establishing personas, the network attempted to distribute narratives critical of Israel and US foreign policy, and supportive of Palestinians. Their distribution strategy relied heavily on co-opting authentic content.
Rather than solely relying on their own fabricated content, the "creator" accounts frequently reshared posts from authentic, high-profile pro-Palestinian voices, adding original captions and tagging the original authors. This tactic was likely an attempt to legitimize their presence and solicit reposts or engagement from real influencers.
The "amplifier" accounts were then tasked with boosting this content via likes and comments, creating a "manufactured consensus" around the posts. The network utilized the full suite of Instagram features to maximize visibility, including Stories, Highlights, and Channels, and even expanded some personas onto Threads. Despite this multi-surface approach and sophisticated persona building, the operation failed to gain traction, achieving negligible engagement from authentic communities before our disruption.

Attempt to Enable Longevity 
After we removed the network, the actors behind this activity quickly sought to reestablish their presence on Instagram. Recidivism is expected of CIB networks, which are often operated by well-resourced, persistent actors that will attempt to return to our services after enforcement. We monitor for recidivism via manual and automated measures, which in this case offered us insights on how these actors adapt to enforcement. 

We observed a marked shift in the tactics behind this operation after we removed the network. Rather than investing in the elaborate persona development that characterized their initial operation, the actors pivoted to a strategy focused on speed and volume. The operators sought to create new accounts which fell into two distinct categories: one group turned its attention domestically, attempting to hijack conversations about local protests and government crackdowns within Iran, while the other consisted of dormant, US-centric personas that remained largely inactive, likely reserved for future activation.

Content quality was notably compromised in this phase. The new accounts engaged almost exclusively in commenting activity, abandoning original posting and substantial persona building. Our automated systems removed a portion of these returning accounts, and manual enforcement efforts eliminated the remainder of linked assets.

## Indicators of Compromise

*Note: URLs have been defanged for safety. Replace `[.]` with `.` to resolve.*

| Indicator Type | Indicator Value |
| :--- | :--- |
| Social Media Account | `https://x[.]com/SophiaGnzlz` |
| Social Media Account | `https://x[.]com/Therapist_Ben` |
| Social Media Account | `https://x[.]com/ImAliceJohnson` |
| Social Media Account | `https://x[.]com/LevyMillar` |

## Cross-Links

- **Full ATR Report:** [Meta Adversarial Threat Report H1 2026](https://transparency.meta.com/sr/h1-2026-adversarial-threat-report/)
- **AlienVault OTX Pulse:** [meta-h1-2026-iran-based-cib-network-1 on OTX](https://otx.alienvault.com/pulse/meta-h1-2026-iran-based-cib-network-1)
- **IOC File (GitHub):** [meta-h1-2026-iran-based-cib-network-1 on GitHub](https://github.com/facebook/threat-research/blob/main/indicators/meta-h1-2026-iran-based-cib-network-1.md)
